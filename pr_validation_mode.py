#!/usr/bin/env python3
"""Classify a PR into full or lightweight validation from its changed paths."""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from gamesymbol_snapshot_lib.model import ChangedPath
from trusted_yaml import load_yaml, load_yaml_file

CONFIG_REPO_PATH = "pr_validation_mode.yaml"
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
_RULE_KEYS = frozenset({"paths", "regexes", "reason"})
TRUSTED_CONFIG_MISSING_REASON = "Trusted validation config missing; fail-closed to full validation"


class PrValidationModeError(RuntimeError):
    pass


class TrustedConfigMissingError(PrValidationModeError):
    pass


@dataclass(frozen=True)
class ImpactRule:
    glob_patterns: tuple[str, ...]
    regex_patterns: tuple[re.Pattern[str], ...]
    reason: str


@dataclass(frozen=True)
class Classification:
    mode: str
    matched_rules: tuple[str, ...]
    force_light: bool


@dataclass(frozen=True)
class ValidationResult:
    mode: str
    latest_gamever: str
    matched_rules: tuple[str, ...]
    changed_paths: tuple[str, ...]


def _git_lines(repo_root: Path, arguments: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise PrValidationModeError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _read_tracked_file(repo_root: Path, ref: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{ref}:{path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        commit_check = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-e", f"{ref}^{{commit}}"],
            capture_output=True,
            check=False,
        )
        if commit_check.returncode == 0:
            raise TrustedConfigMissingError(f"trusted config {path!r} is missing from base commit {ref}")
        raise PrValidationModeError(
            result.stderr.decode("utf-8", errors="replace").strip() or f"git show {ref}:{path} failed"
        )
    return result.stdout


def _decode_git_field(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PrValidationModeError(f"git returned a non-UTF-8 path: {exc}") from exc


def parse_changed_paths(raw: bytes) -> list[ChangedPath]:
    fields = raw.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes = []
    index = 0
    while index < len(fields):
        status_token = _decode_git_field(fields[index])
        index += 1
        status = status_token[:1]
        if status not in {"A", "M", "D", "R", "C"}:
            raise PrValidationModeError(f"unsupported git change status: {status_token}")
        required_paths = 2 if status in {"R", "C"} else 1
        if index + required_paths > len(fields):
            raise PrValidationModeError(f"malformed git diff --name-status record for {status_token}")
        paths = [_decode_git_field(value) for value in fields[index : index + required_paths]]
        index += required_paths
        if status == "A":
            changes.append(ChangedPath(status, None, paths[0]))
        elif status == "D":
            changes.append(ChangedPath(status, paths[0], None))
        elif status == "M":
            changes.append(ChangedPath(status, paths[0], paths[0]))
        else:
            changes.append(ChangedPath(status, paths[0], paths[1]))
    return changes


def changed_paths(repo_root: Path, base_ref: str, head_ref: str) -> list[ChangedPath]:
    result = subprocess.run(
        ["git", "diff", "--name-status", "-M", "-z", base_ref, head_ref, "--"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise PrValidationModeError(stderr or "git diff --name-status failed")
    return parse_changed_paths(result.stdout)


def normalize_path(path: str) -> str:
    normalized = str(path).strip().replace("\\", "/")
    normalized = normalized.removeprefix("./")
    if not normalized:
        raise PrValidationModeError(f"changed path must not be empty: {path!r}")
    return normalized


def _string_list(value, context: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise PrValidationModeError(f"{context} must be a list of non-empty strings")
    return [item.strip() for item in value]


def _validate_glob_pattern(pattern: str) -> None:
    if "\\" in pattern:
        raise PrValidationModeError(f"rule glob pattern must use forward slashes: {pattern!r}")
    if pattern.startswith("/"):
        raise PrValidationModeError(f"rule glob pattern must be repo-relative: {pattern!r}")
    if any(char in pattern for char in "[ ] { }"):
        raise PrValidationModeError(f"rule glob pattern must not use bracket or brace metacharacters: {pattern!r}")
    if any(component in {"", ".", ".."} for component in pattern.split("/")):
        raise PrValidationModeError(f"rule glob pattern must not contain empty or dot components: {pattern!r}")


def _parse_rule(rule, index: int) -> ImpactRule:
    context = f"rules[{index}]"
    if not isinstance(rule, dict):
        raise PrValidationModeError(f"{context} must be a mapping")
    unknown = set(rule) - _RULE_KEYS
    if unknown:
        raise PrValidationModeError(f"{context} has unknown keys: {', '.join(sorted(unknown))}")
    globs = _string_list(rule.get("paths"), f"{context}.paths")
    regexes = _string_list(rule.get("regexes"), f"{context}.regexes")
    if not globs and not regexes:
        raise PrValidationModeError(f"{context} must declare at least one of paths or regexes")
    for pattern in globs:
        _validate_glob_pattern(pattern)
    compiled = []
    for pattern in regexes:
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            raise PrValidationModeError(f"{context}.regexes contains an invalid pattern {pattern!r}: {exc}")
    reason = rule.get("reason")
    if reason is not None and (not isinstance(reason, str) or not reason.strip()):
        raise PrValidationModeError(f"{context}.reason must be a non-empty string")
    return ImpactRule(tuple(globs), tuple(compiled), reason or "")


def parse_rules(document) -> tuple[ImpactRule, ...]:
    if not isinstance(document, dict):
        raise PrValidationModeError("pr_validation_mode.yaml must be a mapping")
    unknown = set(document) - {"schema_version", "rules"}
    if unknown:
        raise PrValidationModeError(f"unknown pr_validation_mode.yaml top-level keys: {', '.join(sorted(unknown))}")
    if document.get("schema_version") != 1:
        raise PrValidationModeError("pr_validation_mode.yaml schema_version must be 1")
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PrValidationModeError("pr_validation_mode.yaml rules must be a non-empty list")
    return tuple(_parse_rule(rule, index) for index, rule in enumerate(rules))


def load_rules_from_ref(repo_root: Path, base_ref: str) -> tuple[ImpactRule, ...]:
    payload = _read_tracked_file(repo_root, base_ref, CONFIG_REPO_PATH)
    return parse_rules(load_yaml(payload.decode("utf-8")))


def load_rules_from_file(path) -> tuple[ImpactRule, ...]:
    return parse_rules(load_yaml_file(Path(path)))


def rule_matches(rule: ImpactRule, path: str) -> bool:
    for pattern in rule.glob_patterns:
        if fnmatch.fnmatchcase(path, pattern):
            return True
    for regex in rule.regex_patterns:
        if regex.search(path):
            return True
    return False


def classify_paths(
    changed_paths: list[str], rules: tuple[ImpactRule, ...], *, force_light: bool = False
) -> Classification:
    normalized = {normalize_path(path) for path in changed_paths}
    matched = tuple(rule.reason for rule in rules if any(rule_matches(rule, path) for path in normalized))
    mode = "light" if force_light else ("full" if matched else "light")
    return Classification(mode, matched, force_light)


def latest_gamever(repo_root: Path) -> str:
    document = load_yaml_file(repo_root / "download.yaml")
    downloads = document.get("downloads") if isinstance(document, dict) else None
    if not isinstance(downloads, list) or not downloads or not isinstance(downloads[-1], dict):
        raise PrValidationModeError("download.yaml has no latest download entry")
    tag = str(downloads[-1].get("tag", "")).strip()
    if not tag:
        raise PrValidationModeError("download.yaml latest download has no tag")
    return tag


def resolve_validation_mode(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
    *,
    config_path: str | None = None,
    force_light: bool = False,
) -> ValidationResult:
    repo_root = Path(repo_root).resolve()
    base_ref = str(base_ref).strip()
    if not SHA_PATTERN.fullmatch(base_ref):
        raise PrValidationModeError(f"base ref must be a full commit SHA: {base_ref}")
    trusted_config_missing = False
    if config_path:
        rules = load_rules_from_file(config_path)
    else:
        try:
            rules = load_rules_from_ref(repo_root, base_ref)
        except TrustedConfigMissingError:
            rules = ()
            trusted_config_missing = True
    changed = changed_paths(repo_root, base_ref, head_ref)
    paths = tuple(sorted({path for change in changed for path in (change.old_path, change.new_path) if path}))
    if trusted_config_missing:
        classification = Classification("full", (TRUSTED_CONFIG_MISSING_REASON,), False)
    else:
        classification = classify_paths(list(paths), rules, force_light=force_light)
    return ValidationResult(
        mode=classification.mode,
        latest_gamever=latest_gamever(repo_root),
        matched_rules=classification.matched_rules,
        changed_paths=paths,
    )


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", default="HEAD")
    parser.add_argument(
        "--config",
        default=None,
        help=f"override the trusted config file (default: read {CONFIG_REPO_PATH} from --base-ref)",
    )
    parser.add_argument(
        "--force-light", action="store_true", help="force lightweight validation regardless of changed paths"
    )
    parser.add_argument("--github-output")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        result = resolve_validation_mode(
            Path(args.repo_root),
            args.base_ref,
            args.head_ref,
            config_path=args.config,
            force_light=args.force_light,
        )
    except (OSError, PrValidationModeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as handle:
            handle.write(f"validation-mode={result.mode}\n")
            handle.write(f"latest-gamever={result.latest_gamever}\n")
    print(f"validation-mode={result.mode}")
    print(f"latest-gamever={result.latest_gamever}")
    for reason in result.matched_rules:
        print(f"  matched rule: {reason}")
    for path in result.changed_paths:
        print(f"  changed: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
