"""Exercise the retrying artifact transport against a simulated GitHub API."""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

import ci_artifacts


def archive_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, payload in members.items():
            bundle.writestr(name, payload)
    return buffer.getvalue()


class FakeResponse:
    def __init__(self, payload=None, content: bytes = b"", status: int = 200):
        self.payload = payload
        self.content = content
        self.status_code = status
        self.text = json.dumps(payload) if payload is not None else content.decode("utf-8", "replace")

    def json(self):
        if self.payload is None:
            raise ValueError("no JSON payload")
        return self.payload

    def iter_content(self, size: int):
        for start in range(0, len(self.content), size):
            yield self.content[start : start + size]

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        return False


class FakeClient:
    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.urls: list[str] = []

    def get(self, url: str, timeout=None, stream: bool = False):
        self.urls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                return response() if callable(response) else response
        raise AssertionError(f"unexpected URL: {url}")

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        return False


class RetryTests(unittest.TestCase):
    def test_retries_transient_failures_then_succeeds(self):
        attempts = []

        def action():
            attempts.append(1)
            if len(attempts) < 3:
                raise ci_artifacts._RetryableError("connection reset")
            return "ok"

        with mock.patch.object(ci_artifacts.time, "sleep") as sleep:
            self.assertEqual("ok", ci_artifacts._retry(action, description="download"))
        self.assertEqual(2, sleep.call_count)

    def test_reports_failure_after_the_attempt_budget(self):
        def action():
            raise ci_artifacts._RetryableError("connection reset")

        with (
            mock.patch.object(ci_artifacts.time, "sleep"),
            self.assertRaisesRegex(ci_artifacts.ArtifactError, f"after {ci_artifacts.ATTEMPTS} attempts"),
        ):
            ci_artifacts._retry(action, description="download")

    def test_terminal_failures_are_not_retried(self):
        def action():
            raise ci_artifacts.ArtifactError("expired")

        with mock.patch.object(ci_artifacts.time, "sleep") as sleep, self.assertRaises(ci_artifacts.ArtifactError):
            ci_artifacts._retry(action, description="download")
        sleep.assert_not_called()

    def test_backoff_grows_but_stays_bounded(self):
        self.assertLess(ci_artifacts._backoff(1), ci_artifacts._backoff(4))
        self.assertLessEqual(ci_artifacts._backoff(12), ci_artifacts.MAX_BACKOFF_SECONDS * 1.25)


class ResolveTests(unittest.TestCase):
    def payload(self, *names):
        return {
            "total_count": len(names),
            "artifacts": [{"id": index + 1, "name": name} for index, name in enumerate(names)],
        }

    def test_matches_the_exact_name(self):
        client = FakeClient({"actions/runs/7/artifacts": FakeResponse(self.payload("plan", "plan-extra"))})
        artifact = ci_artifacts.resolve_artifact(client, "owner/repo", "7", "plan")
        self.assertEqual({"id": 1, "name": "plan"}, artifact)
        self.assertIn("name=plan", client.urls[0])

    def test_rejects_a_missing_artifact(self):
        client = FakeClient({"actions/runs/7/artifacts": FakeResponse(self.payload("other"))})
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "missing from workflow run 7"):
            ci_artifacts.resolve_artifact(client, "owner/repo", "7", "plan")

    def test_rejects_an_ambiguous_name(self):
        client = FakeClient({"actions/runs/7/artifacts": FakeResponse(self.payload("plan", "plan"))})
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "ambiguous"):
            ci_artifacts.resolve_artifact(client, "owner/repo", "7", "plan")

    def test_rejects_a_non_numeric_run_id(self):
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "run id must be numeric"):
            ci_artifacts.resolve_artifact(FakeClient({}), "owner/repo", "../../runs/7", "plan")

    def test_retries_a_reset_while_listing(self):
        responses = [FakeResponse(status=502), FakeResponse(self.payload("plan"))]
        client = FakeClient({"actions/runs/7/artifacts": lambda: responses.pop(0)})
        with mock.patch.object(ci_artifacts.time, "sleep"):
            artifact = ci_artifacts.resolve_artifact(client, "owner/repo", "7", "plan")
        self.assertEqual("plan", artifact["name"])


class ValidationTests(unittest.TestCase):
    def artifact(self, **overrides):
        artifact = {"id": 3, "name": "plan", "expired": False, "size_in_bytes": 12, "digest": None}
        artifact.update(overrides)
        return artifact

    def test_accepts_a_live_sized_artifact(self):
        self.assertEqual(12, ci_artifacts._validate(self.artifact()))

    def test_rejects_an_expired_artifact(self):
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "expired"):
            ci_artifacts._validate(self.artifact(expired=True))

    def test_rejects_a_missing_size(self):
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "no usable size"):
            ci_artifacts._validate(self.artifact(size_in_bytes=0))

    def test_verifies_the_declared_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "artifact.zip"
            archive.write_bytes(b"payload")
            digest = "sha256:" + hashlib.sha256(b"payload").hexdigest()
            ci_artifacts._verify(self.artifact(size_in_bytes=7, digest=digest), archive, 7)
            with self.assertRaisesRegex(ci_artifacts.ArtifactError, "does not match"):
                ci_artifacts._verify(self.artifact(size_in_bytes=7, digest="sha256:" + "0" * 64), archive, 7)

    def test_rejects_a_truncated_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "artifact.zip"
            archive.write_bytes(b"payload")
            with self.assertRaisesRegex(ci_artifacts.ArtifactError, "GitHub reports 9"):
                ci_artifacts._verify(self.artifact(size_in_bytes=9), archive, 9)


class ExtractTests(unittest.TestCase):
    def extract(self, content: bytes) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive = root / "artifact.zip"
        archive.write_bytes(content)
        destination = root / "artifact"
        ci_artifacts.extract(archive, destination)
        return destination

    def test_writes_nested_members_under_the_destination(self):
        destination = self.extract(archive_bytes({"plan.json": b"{}", "nested/evidence.json": b"[]"}))
        self.assertEqual(b"{}", (destination / "plan.json").read_bytes())
        self.assertEqual(b"[]", (destination / "nested" / "evidence.json").read_bytes())

    def test_creates_the_destination_for_an_empty_archive(self):
        self.assertTrue(self.extract(archive_bytes({})).is_dir())

    def test_rejects_traversal_members(self):
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "escapes the destination"):
            self.extract(archive_bytes({"../escape.json": b"{}"}))

    def test_rejects_absolute_members(self):
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "escapes the destination"):
            self.extract(archive_bytes({"/etc/passwd": b"root"}))

    def test_rejects_windows_separators(self):
        # zipfile rewrites member separators while reading on Windows, so check the guard directly.
        info = zipfile.ZipInfo("placeholder")
        info.filename = "nested\\evidence.json"

        class Archive:
            def infolist(self):
                return [info]

        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "not a portable path"):
            ci_artifacts.archive_members(Archive())

    def test_rejects_symbolic_links(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            link = zipfile.ZipInfo("link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(link, "/etc/passwd")
        with self.assertRaisesRegex(ci_artifacts.ArtifactError, "unexpected type"):
            self.extract(buffer.getvalue())


class DownloadTests(unittest.TestCase):
    def test_downloads_and_extracts_a_bound_artifact(self):
        content = archive_bytes({"trusted-source-artifact-plan.json": b"{}"})
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        artifact = {"id": 42, "name": "plan", "expired": False, "size_in_bytes": len(content), "digest": digest}
        client = FakeClient(
            {
                "actions/runs/77/artifacts": FakeResponse({"total_count": 1, "artifacts": [artifact]}),
                "actions/artifacts/42/zip": FakeResponse(content=content),
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "plan"
            environment = {
                "GH_TOKEN": "token",
                "CI_ARTIFACT_NAME": "plan",
                "CI_ARTIFACT_ID": "",
                "CI_ARTIFACT_RUN_ID": "77",
                "CI_ARTIFACT_REPOSITORY": "owner/repo",
                "CI_ARTIFACT_PATH": str(destination),
            }
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(ci_artifacts, "session", lambda token: client),
            ):
                ci_artifacts.download()
            self.assertEqual(b"{}", (destination / "trusted-source-artifact-plan.json").read_bytes())

    def test_requires_exactly_one_artifact_selector(self):
        environment = {
            "GH_TOKEN": "token",
            "CI_ARTIFACT_NAME": "plan",
            "CI_ARTIFACT_ID": "42",
            "CI_ARTIFACT_RUN_ID": "77",
            "CI_ARTIFACT_REPOSITORY": "owner/repo",
            "CI_ARTIFACT_PATH": "unused",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=False),
            self.assertRaisesRegex(ci_artifacts.ArtifactError, "exactly one of"),
        ):
            ci_artifacts.download()

    def test_requires_a_token(self):
        environment = {
            "GH_TOKEN": "",
            "GITHUB_TOKEN": "",
            "CI_ARTIFACT_NAME": "plan",
            "CI_ARTIFACT_ID": "",
            "CI_ARTIFACT_RUN_ID": "77",
            "CI_ARTIFACT_REPOSITORY": "owner/repo",
            "CI_ARTIFACT_PATH": "unused",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=False),
            self.assertRaisesRegex(ci_artifacts.ArtifactError, "GH_TOKEN or GITHUB_TOKEN"),
        ):
            ci_artifacts.download()


if __name__ == "__main__":
    unittest.main()
