#!/usr/bin/env python3
"""Verified, retrying GitHub Actions artifact transport for workflow steps.

``actions/download-artifact`` makes a single request per API call, so a transient
connection reset while listing or streaming an artifact fails the whole job. Workflow
steps therefore download through this module instead: every request is retried with
bounded exponential backoff, the archive is checked against the artifact digest, and
the expanded tree is validated before it reaches the workspace.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import random
import stat
import sys
import tempfile
import time
from urllib.parse import quote
import zipfile

import requests

API_ROOT = "https://api.github.com"
CONNECT_TIMEOUT = 30.0
READ_TIMEOUT = 300.0
ATTEMPTS = 5
BACKOFF_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 30.0
RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_ARCHIVE_BYTES = 8 * 1024**3
MAX_EXPANDED_BYTES = 16 * 1024**3


class ArtifactError(RuntimeError):
    """Artifact transport failure; the message is the only diagnostic."""


class _RetryableError(RuntimeError):
    """Request failure that a later attempt can plausibly recover from."""


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or not str(value).strip():
        raise ArtifactError(f"{name} is required")
    return str(value).strip()


def _digest_name(name: str) -> bool:
    return name.startswith("sha256:") and len(name) == 71


def _backoff(attempt: int) -> float:
    return min(MAX_BACKOFF_SECONDS, BACKOFF_SECONDS * 2 ** (attempt - 1)) * (1 + random.random() / 4)


def _retry(action, *, description: str):
    """Run ``action`` until it succeeds or the attempt budget is exhausted."""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            return action()
        except _RetryableError as exc:
            if attempt == ATTEMPTS:
                raise ArtifactError(f"{description} failed after {ATTEMPTS} attempts: {exc}") from exc
            delay = _backoff(attempt)
            print(
                f"{description} attempt {attempt}/{ATTEMPTS} failed ({exc}); retrying in {delay:.1f}s",
                file=sys.stderr,
            )
            time.sleep(delay)
    raise AssertionError("retry budget is never empty")


def session(token: str) -> requests.Session:
    client = requests.Session()
    client.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    return client


def _reject_status(response: requests.Response, url: str) -> None:
    if response.status_code in RETRY_STATUS:
        raise _RetryableError(f"HTTP {response.status_code}")
    if response.status_code != 200:
        detail = response.text[:512].replace("\n", " ")
        raise ArtifactError(f"GET {url} returned HTTP {response.status_code}: {detail}")


def _get_json(client: requests.Session, url: str) -> dict:
    def attempt():
        try:
            response = client.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        except requests.RequestException as exc:
            raise _RetryableError(f"{type(exc).__name__}: {exc}") from exc
        _reject_status(response, url)
        try:
            return response.json()
        except ValueError as exc:
            raise _RetryableError(f"invalid JSON: {exc}") from exc

    return _retry(attempt, description=f"list {url}")


def _download(client: requests.Session, url: str, destination: Path) -> int:
    def attempt():
        try:
            with client.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), stream=True) as response:
                _reject_status(response, url)
                written = 0
                with destination.open("wb") as sink:
                    for chunk in response.iter_content(1024 * 1024):
                        written += len(chunk)
                        if written > MAX_ARCHIVE_BYTES:
                            raise ArtifactError(f"artifact archive exceeds {MAX_ARCHIVE_BYTES} bytes")
                        sink.write(chunk)
                return written
        except requests.RequestException as exc:
            raise _RetryableError(f"{type(exc).__name__}: {exc}") from exc

    return _retry(attempt, description=f"download {url}")


def resolve_artifact(client: requests.Session, repository: str, run_id: str, name: str) -> dict:
    """Find the single non-expired run artifact with this exact name."""
    if not run_id.isdigit():
        raise ArtifactError(f"workflow run id must be numeric, got {run_id!r}")
    url = f"{API_ROOT}/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100&name={quote(name)}"
    payload = _get_json(client, url)
    artifacts = [item for item in payload.get("artifacts") or [] if item.get("name") == name]
    if not artifacts:
        raise ArtifactError(f"artifact {name!r} is missing from workflow run {run_id}")
    if len(artifacts) > 1:
        raise ArtifactError(f"artifact name {name!r} is ambiguous in workflow run {run_id}")
    return artifacts[0]


def fetch_artifact(client: requests.Session, repository: str, artifact_id: str) -> dict:
    if not artifact_id.isdigit():
        raise ArtifactError(f"artifact id must be numeric, got {artifact_id!r}")
    return _get_json(client, f"{API_ROOT}/repos/{repository}/actions/artifacts/{artifact_id}")


def _validate(artifact: dict) -> int:
    identity = artifact.get("name") or artifact.get("id")
    if artifact.get("expired"):
        raise ArtifactError(f"artifact {identity!r} is expired")
    size = artifact.get("size_in_bytes")
    if not isinstance(size, int) or size <= 0:
        raise ArtifactError(f"artifact {identity!r} has no usable size")
    if size > MAX_ARCHIVE_BYTES:
        raise ArtifactError(f"artifact {identity!r} exceeds {MAX_ARCHIVE_BYTES} bytes")
    return size


def _verify(artifact: dict, archive: Path, expected_size: int) -> None:
    written = archive.stat().st_size
    if written != expected_size:
        raise ArtifactError(f"artifact archive is {written} bytes, GitHub reports {expected_size}")
    digest = str(artifact.get("digest") or "").lower()
    if not digest:
        return
    if not _digest_name(digest):
        raise ArtifactError(f"artifact digest {digest!r} is not a sha256 digest")
    hasher = hashlib.sha256()
    with archive.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    actual = f"sha256:{hasher.hexdigest()}"
    if actual != digest:
        raise ArtifactError(f"artifact archive digest {actual} does not match {digest}")


def archive_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Reject archives that could escape the destination or smuggle non-regular files."""
    expanded = 0
    for item in archive.infolist():
        name = item.filename
        if not name or "\\" in name or ":" in name.split("/")[0]:
            raise ArtifactError(f"artifact archive member is not a portable path: {name!r}")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise ArtifactError(f"artifact archive member escapes the destination: {name!r}")
        expected_type = stat.S_IFDIR if item.is_dir() else stat.S_IFREG
        if stat.S_IFMT(item.external_attr >> 16) not in (0, expected_type):
            raise ArtifactError(f"artifact archive member has an unexpected type: {name!r}")
        if item.is_dir():
            continue
        expanded += item.file_size
        if expanded > MAX_EXPANDED_BYTES:
            raise ArtifactError(f"artifact archive expands beyond {MAX_EXPANDED_BYTES} bytes")
    return archive.infolist()


def extract(archive: Path, destination: Path) -> None:
    """Expand the archive exactly as ``actions/download-artifact`` would for one name."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for item in archive_members(bundle):
            parts = PurePosixPath(item.filename).parts
            if item.is_dir():
                destination.joinpath(*parts).mkdir(parents=True, exist_ok=True)
                continue
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as source, target.open("wb") as sink:
                while block := source.read(1024 * 1024):
                    sink.write(block)


def download() -> None:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token or not token.strip():
        raise ArtifactError("GH_TOKEN or GITHUB_TOKEN is required")
    repository = _env("CI_ARTIFACT_REPOSITORY", os.environ.get("GITHUB_REPOSITORY"))
    name = os.environ.get("CI_ARTIFACT_NAME", "").strip()
    artifact_id = os.environ.get("CI_ARTIFACT_ID", "").strip()
    run_id = os.environ.get("CI_ARTIFACT_RUN_ID", "").strip()
    destination = Path(_env("CI_ARTIFACT_PATH"))
    if bool(name) == bool(artifact_id):
        raise ArtifactError("exactly one of CI_ARTIFACT_NAME or CI_ARTIFACT_ID is required")

    with session(token) as client:
        artifact = (
            resolve_artifact(client, repository, run_id or _env("GITHUB_RUN_ID"), name)
            if name
            else fetch_artifact(client, repository, artifact_id)
        )
        expected_size = _validate(artifact)
        with tempfile.TemporaryDirectory() as staging:
            archive = Path(staging) / "artifact.zip"
            _download(client, f"{API_ROOT}/repos/{repository}/actions/artifacts/{int(artifact['id'])}/zip", archive)
            _verify(artifact, archive, expected_size)
            extract(archive, destination)

    label = artifact.get("name") or artifact.get("id")
    print(f"downloaded artifact {label} into {destination}", file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["download"])
    parser.parse_args(argv)
    try:
        download()
    except (ArtifactError, OSError, zipfile.BadZipFile) as exc:
        print(f"CI artifact download failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
