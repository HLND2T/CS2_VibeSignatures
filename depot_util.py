#!/usr/bin/env python3
"""Shared helpers for invoking DepotDownloader with retries and password redaction."""

import os
import subprocess
import time


DEFAULT_DEPOTDOWNLOADER_ATTEMPTS = 3
DEFAULT_DEPOTDOWNLOADER_RETRY_DELAY_SECONDS = 30.0


def versioned_depot_dir(depot_root: str, gamever: str) -> str:
    """Return the per-GAMEVER depot directory under one depot root.

    Keeping each GAMEVER in its own tree keeps DepotDownloader's incremental
    state (its `.DepotDownloader` manifest/config store) version-scoped, so a
    stale file from an older build can never be reused for a newer one.
    """
    return os.path.join(depot_root, gamever)


def append_auth_args(
    command: list[str],
    username: str | None,
    password: str | None,
    remember_password: bool,
) -> None:
    """Append Steam auth arguments to a DepotDownloader command in place."""
    if username:
        command.extend(["-username", username])
    if password:
        command.extend(["-password", password])
    if remember_password:
        command.append("-remember-password")


def redact_command(command: list[str]) -> list[str]:
    """Return a copy of `command` with the value following `-password` redacted."""
    redacted: list[str] = []
    skip_next = False
    for part in command:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        redacted.append(part)
        if part == "-password":
            skip_next = True
    return redacted


def run_command(
    command: list[str],
    *,
    max_attempts: int = DEFAULT_DEPOTDOWNLOADER_ATTEMPTS,
    retry_delay_seconds: float = DEFAULT_DEPOTDOWNLOADER_RETRY_DELAY_SECONDS,
) -> None:
    """Run a subprocess command with bounded retries; callers normalize errors."""
    redacted = redact_command(command)
    attempt_count = max(1, max_attempts)

    for attempt in range(1, attempt_count + 1):
        if attempt == 1:
            print(f"Running: {' '.join(redacted)}")
        else:
            print(f"Retrying ({attempt}/{attempt_count}): {' '.join(redacted)}")

        try:
            subprocess.run(command, check=True)
            return
        except subprocess.CalledProcessError:
            if attempt == attempt_count:
                raise
            print(f"Command failed; retrying in {retry_delay_seconds:g}s ({attempt}/{attempt_count})")
            time.sleep(retry_delay_seconds)
