"""Format tracked Python and YAML files in this repository."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

MAX_WINDOWS_COMMAND_CHARS = 30000
GENERATED_REFERENCE_YAML_PREFIX = "ida_preprocessor_scripts/references/"
GAMESYMBOL_SNAPSHOT_PREFIX = "gamesymbols/"
AGENT_DIR_YAML_PREFIXES = (".claude/", ".codex/")
ALWAYS_CHECK_PY_GLOB = "ida_preprocessor_scripts/*.py"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Format git-tracked *.py and *.yaml files with Ruff and yamlfix.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check formatting without writing changes.",
    )
    return parser.parse_args(argv)


def list_tracked_format_files() -> list[str]:
    command = ["git", "ls-files", "--cached", "--", "*.py", "*.yaml"]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or "git ls-files failed"
        raise RuntimeError(message)

    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def list_unchecked_preprocessor_scripts(tracked_files: Sequence[str]) -> list[str]:
    tracked_set = {Path(path).resolve().as_posix() for path in tracked_files}
    extra: list[str] = []
    for path in Path("").glob(ALWAYS_CHECK_PY_GLOB):
        if path.is_file() and path.resolve().as_posix() not in tracked_set:
            extra.append(path.as_posix())
    return extra


def chunk_paths(
    command_prefix: Sequence[str],
    paths: Sequence[str],
    *,
    max_command_chars: int = MAX_WINDOWS_COMMAND_CHARS,
) -> Iterable[list[str]]:
    current: list[str] = []
    for path in paths:
        candidate = current + [path]
        if current and _command_line_length([*command_prefix, *candidate]) > max_command_chars:
            yield current
            current = [path]
        else:
            current = candidate

    if current:
        yield current


def run_command_chunks(command_prefix: Sequence[str], paths: Sequence[str]) -> int:
    if not paths:
        return 0

    failed = False
    for chunk in chunk_paths(command_prefix, paths):
        result = subprocess.run([*command_prefix, *chunk], check=False)
        failed = failed or result.returncode != 0

    return 1 if failed else 0


def should_format_yaml(path: str) -> bool:
    normalized_path = path.replace("\\", "/")
    return not normalized_path.startswith(
        (GENERATED_REFERENCE_YAML_PREFIX, GAMESYMBOL_SNAPSHOT_PREFIX, *AGENT_DIR_YAML_PREFIXES)
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        tracked_files = list_tracked_format_files()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    existing_files = [path for path in tracked_files if Path(path).is_file()]
    python_files = [path for path in existing_files if path.endswith(".py")]
    python_files.extend(list_unchecked_preprocessor_scripts(tracked_files))
    yaml_files = [path for path in existing_files if path.endswith(".yaml") and should_format_yaml(path)]

    ruff_command = ["ruff", "format"]
    yamlfix_command = ["yamlfix"]
    if args.check:
        ruff_command.append("--check")
        yamlfix_command.append("--check")

    results = [
        run_command_chunks(ruff_command, python_files),
        run_command_chunks(yamlfix_command, yaml_files),
    ]
    return 1 if any(result != 0 for result in results) else 0


def _command_line_length(args: Sequence[str]) -> int:
    return len(subprocess.list2cmdline([str(arg) for arg in args]))


if __name__ == "__main__":
    raise SystemExit(main())
