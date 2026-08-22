#!/usr/bin/env python3
"""
Run C++ tests declared in the selected analysis config and compare clang layouts with YAML references.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Sequence

try:
    import yaml
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required dependencies with: uv sync")
    sys.exit(1)

from cpp_tests_util import (
    compare_compiler_record_layout_with_yaml,
    compare_compiler_vtable_with_yaml,
    format_compiler_record_members,
    format_compiler_vtable_entries,
    format_record_compare_differences,
    format_record_compare_report,
    format_reference_record_members,
    format_reference_vtable_entries,
    format_vtable_compare_differences,
    format_vtable_compare_report,
    map_target_triple_to_platform,
    pointer_size_from_target_triple,
)
from analysis_config import AnalysisConfigError, resolve_analysis_config
from gamesymbol_store import SymbolStore, SymbolStoreError, open_snapshot_store


DEFAULT_CLANG = "clang++"
DEFAULT_CPP_STD = "c++20"


def parse_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Run configured C++ tests with clang++ and compare vtable metadata")
    parser.add_argument(
        "-configyaml",
        default=None,
        help="Analysis config path; defaults to configs/<GAMEVER>.yaml",
    )
    parser.add_argument("-snapshot", required=True, help="Canonical candidate or published game-symbol snapshot")
    parser.add_argument(
        "-gamever",
        required=True,
        help="Game version recorded by the snapshot (required)",
    )
    parser.add_argument(
        "-clang",
        default=DEFAULT_CLANG,
        help=f"clang++ executable path (default: {DEFAULT_CLANG})",
    )
    parser.add_argument(
        "-std",
        default=DEFAULT_CPP_STD,
        help=f"C++ standard for compilation (default: {DEFAULT_CPP_STD})",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        help="Maximum number of tests/probes to run in parallel (default: auto)",
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Enable debug output",
    )
    return parser.parse_args()


def _to_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    return [str(value).strip()]


def _resolve_source_path(value: str, source_root: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    root = source_root.resolve()
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"relative source path escapes repository root: {value}") from exc
    return resolved


def _to_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        raise ValueError(f"Invalid boolean value: {value!r}")
    if isinstance(value, str):
        normalized = value.strip().lower()
        if not normalized:
            return default
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
        raise ValueError(f"Invalid boolean value: {value!r}")
    raise ValueError(f"Invalid boolean value: {value!r}")


def _normalize_option(option_text: str) -> str:
    option_text = option_text.strip()
    if not option_text:
        return ""
    if option_text.startswith("-"):
        return option_text
    return f"-{option_text}"


def _contains_fdump_vtable_layouts(options: Sequence[str]) -> bool:
    for option in options:
        normalized = _normalize_option(option)
        if normalized and normalized.lstrip("-") == "fdump-vtable-layouts":
            return True
    return False


def _contains_fdump_record_layouts(options: Sequence[str]) -> bool:
    for option in options:
        normalized = _normalize_option(option)
        if normalized and normalized.lstrip("-") == "fdump-record-layouts":
            return True
    return False


def _format_command(command: Sequence[str]) -> str:
    return subprocess.list2cmdline(list(command))


def _collect_process_output(result: subprocess.CompletedProcess) -> str:
    stdout_text = result.stdout.strip() if result.stdout else ""
    stderr_text = result.stderr.strip() if result.stderr else ""

    if stdout_text and stderr_text:
        return f"{stdout_text}\n{stderr_text}"
    if stdout_text:
        return stdout_text
    return stderr_text


def resolve_worker_count(jobs: int | None) -> int:
    """Resolve the concurrency level for parallel clang++ invocations."""
    if jobs is not None:
        if jobs < 1:
            raise ValueError(f"Invalid --jobs value: {jobs!r} (must be >= 1)")
        return jobs
    cpu = os.cpu_count() or 1
    return max(1, min(32, cpu + 4))


def parse_config(config_path: Path) -> List[Dict[str, Any]]:
    """Load and validate cpp_tests from the selected analysis config."""
    try:
        with config_path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    except Exception as exc:
        print(f"Error: Failed to parse config file {config_path}: {exc}")
        sys.exit(1)

    cpp_tests = config.get("cpp_tests", [])
    if not isinstance(cpp_tests, list):
        print("Error: 'cpp_tests' in the analysis config must be a list")
        sys.exit(1)

    return cpp_tests


def get_default_target_triple(clang: str) -> str:
    """Run clang++ -print-target-triple and return the result."""
    command = [clang, "-print-target-triple"]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        output = _collect_process_output(result)
        print(f"Error: Failed to run `{_format_command(command)}`")
        if output:
            print(output)
        sys.exit(1)

    triple = (result.stdout or "").strip()
    if not triple:
        triple = (result.stderr or "").strip()
    if not triple:
        print("Error: clang++ -print-target-triple returned empty output")
        sys.exit(1)
    return triple


def probe_target_support(clang: str, target: str, cpp_std: str) -> Dict[str, Any]:
    """Probe whether clang can compile a minimal source with the given target triple."""
    with tempfile.TemporaryDirectory(prefix="cpp_target_probe_") as temp_dir:
        temp_dir_path = Path(temp_dir)
        source_file = temp_dir_path / "probe.cpp"
        object_file = temp_dir_path / "probe.o"
        source_file.write_text("int main() { return 0; }\n", encoding="utf-8")

        command = [
            clang,
            f"--target={target}",
            f"-std={cpp_std}",
            "-c",
            str(source_file),
            "-o",
            str(object_file),
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

    return {
        "target": target,
        "supported": result.returncode == 0,
        "command": command,
        "output": _collect_process_output(result),
    }


def build_compile_command(
    *,
    clang: str,
    cpp_std: str,
    target: str,
    cpp_file: Path,
    object_file: Path,
    include_directories: Sequence[Path],
    defines: Sequence[str],
    additional_options: Sequence[str],
) -> List[str]:
    """Construct clang++ compile command for one cpp test item."""
    command = [
        clang,
        f"--target={target}",
        f"-std={cpp_std}",
        "-c",
        str(cpp_file),
        "-o",
        str(object_file),
    ]

    for include_dir in include_directories:
        command.extend(["-I", str(include_dir)])

    for define in defines:
        command.append(f"-D{define}")

    for option in additional_options:
        normalized_option = _normalize_option(option)
        if normalized_option:
            command.append(normalized_option)

    return command


def compile_and_compare(
    *,
    test_item: Dict[str, Any],
    args: argparse.Namespace,
    config_dir: Path,
    symbol_store: SymbolStore,
) -> Dict[str, Any]:
    """Compile a C++ test file and compare vtable layout against YAML references.

    Returns a dict with keys: status, command, output, compare_reports, and
    optionally message (when status is 'invalid').
    """
    test_name = str(test_item.get("name", "unnamed_test"))
    symbol = str(test_item.get("symbol", "")).strip()
    cpp_rel_path = str(test_item.get("cpp", "")).strip()
    target = str(test_item.get("target", "")).strip()

    if not symbol or not cpp_rel_path or not target:
        return {
            "status": "invalid",
            "message": "Missing required fields: symbol/cpp/target",
        }

    try:
        cpp_file = _resolve_source_path(cpp_rel_path, config_dir)
        for header in _to_list(test_item.get("headers")):
            _resolve_source_path(header, config_dir)
    except ValueError as exc:
        return {"status": "invalid", "message": str(exc)}

    if not cpp_file.is_file():
        return {
            "status": "invalid",
            "message": f"CPP file not found: {cpp_file}",
        }

    include_directories: List[Path] = []
    try:
        for include_rel in _to_list(test_item.get("include_directories")):
            include_directories.append(_resolve_source_path(include_rel, config_dir))
    except ValueError as exc:
        return {"status": "invalid", "message": str(exc)}

    defines = _to_list(test_item.get("defines"))

    additional_options = _to_list(test_item.get("additional_compiler_options"))
    if not additional_options:
        # Keep compatibility with alternate field naming.
        additional_options = _to_list(test_item.get("additional_compile_options"))

    should_parse_vtable = _contains_fdump_vtable_layouts(additional_options)
    should_parse_record = _contains_fdump_record_layouts(additional_options)

    with tempfile.TemporaryDirectory(prefix=f"cpp_test_{test_name}_") as temp_dir:
        temp_dir_path = Path(temp_dir)
        object_file = temp_dir_path / f"{test_name}.o"
        command = build_compile_command(
            clang=args.clang,
            cpp_std=args.std,
            target=target,
            cpp_file=cpp_file,
            object_file=object_file,
            include_directories=include_directories,
            defines=defines,
            additional_options=additional_options,
        )
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

    compile_output = _collect_process_output(result)
    if result.returncode != 0:
        return {
            "status": "compile_failed",
            "command": command,
            "output": compile_output,
        }

    compare_reports = []
    if should_parse_vtable or should_parse_record:
        platform = map_target_triple_to_platform(target)
        if platform is None:
            compare_reports = [
                {
                    "class_name": symbol,
                    "platform": "unknown",
                    "requested_modules": _to_list(test_item.get("reference_modules")),
                    "compiler_found": False,
                    "reference_found": False,
                    "differences": [],
                    "notes": [f"Cannot map target triple '{target}' to yaml platform; layout compare skipped."],
                }
            ]
        else:
            reference_modules = _to_list(test_item.get("reference_modules"))
            if should_parse_vtable:
                alias_symbols = _to_list(test_item.get("alias_symbols"))
                reference_vtable_owners = _to_list(test_item.get("reference_vtable_owners"))
                exclude_reference_vtables = _to_list(test_item.get("exclude_reference_vtables"))
                try:
                    merge_reference_modules = _to_bool(test_item.get("merge_reference_modules"), default=True)
                except ValueError as exc:
                    return {
                        "status": "invalid",
                        "message": (
                            "Invalid 'merge_reference_modules' value: "
                            f"{test_item.get('merge_reference_modules')!r}. {exc}"
                        ),
                    }
                if not reference_modules or merge_reference_modules:
                    compare_reports.append(
                        compare_compiler_vtable_with_yaml(
                            class_name=symbol,
                            compiler_output=compile_output,
                            symbol_store=symbol_store,
                            platform=platform,
                            reference_modules=reference_modules,
                            merge_reference_modules=merge_reference_modules,
                            pointer_size=pointer_size_from_target_triple(target),
                            alias_class_names=alias_symbols,
                            reference_vtable_owners=reference_vtable_owners,
                            exclude_reference_vtables=exclude_reference_vtables,
                        )
                    )
                else:
                    for module_name in reference_modules:
                        compare_reports.append(
                            compare_compiler_vtable_with_yaml(
                                class_name=symbol,
                                compiler_output=compile_output,
                                symbol_store=symbol_store,
                                platform=platform,
                                reference_modules=[module_name],
                                merge_reference_modules=False,
                                pointer_size=pointer_size_from_target_triple(target),
                                alias_class_names=alias_symbols,
                                reference_vtable_owners=reference_vtable_owners,
                                exclude_reference_vtables=exclude_reference_vtables,
                            )
                        )
            if should_parse_record:
                compare_reports.append(
                    compare_compiler_record_layout_with_yaml(
                        struct_name=symbol,
                        compiler_output=compile_output,
                        symbol_store=symbol_store,
                        platform=platform,
                        reference_modules=reference_modules,
                    )
                )
    else:
        compare_reports = None

    return {
        "status": "ok",
        "command": command,
        "output": compile_output,
        "compare_reports": compare_reports,
    }


def run_one_test(
    *,
    test_item: Dict[str, Any],
    args: argparse.Namespace,
    config_dir: Path,
    symbol_store: SymbolStore,
) -> Dict[str, Any]:
    """Compile and (optionally) compare one cpp test item."""
    test_name = str(test_item.get("name", "unnamed_test"))
    result = compile_and_compare(
        test_item=test_item,
        args=args,
        config_dir=config_dir,
        symbol_store=symbol_store,
    )
    result["name"] = test_name
    return result


def main():
    args = parse_args()
    try:
        worker_count = resolve_worker_count(args.jobs)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2
    try:
        config_path = resolve_analysis_config(args.gamever, args.configyaml)
    except AnalysisConfigError as exc:
        print(f"Error: {exc}")
        return 2
    source_root = Path(__file__).resolve().parent
    try:
        symbol_store = open_snapshot_store(
            snapshot_path=args.snapshot,
            config_path=config_path,
            expected_game_version=args.gamever,
        )
    except SymbolStoreError as exc:
        print(f"Error: {exc}")
        return 2

    print("Symbol source: snapshot")
    print(f"Candidate SHA-256: {symbol_store.candidate_sha256}")
    print(f"Game version: {symbol_store.game_version}")
    print(f"File count: {symbol_store.file_count}")
    print(f"Config digest: {symbol_store.config_sha256}")

    cpp_tests = parse_config(config_path)
    if not cpp_tests:
        print(f"No cpp_tests defined in {config_path}")
        return 0

    print("=== clang++ target triple detection ===")
    default_target_triple = get_default_target_triple(args.clang)
    print(f"clang++ -print-target-triple => {default_target_triple}")

    configured_targets = sorted(
        {str(item.get("target", "")).strip() for item in cpp_tests if str(item.get("target", "")).strip()}
    )

    if not configured_targets:
        print("No target triples found in cpp_tests config")
        return 1

    print("=== target support probe (from configured targets) ===")
    target_support: Dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        probe_futures = [
            executor.submit(probe_target_support, args.clang, target, args.std)
            for target in configured_targets
        ]
        probes = [future.result() for future in probe_futures]
    for target, probe in zip(configured_targets, probes):
        target_support[target] = bool(probe["supported"])
        status_text = "SUPPORTED" if probe["supported"] else "UNSUPPORTED"
        print(f"[{status_text}] {target}")
        if args.debug and probe["output"]:
            print(probe["output"])

    runnable_tests = []
    skipped_tests = []
    for test_item in cpp_tests:
        target = str(test_item.get("target", "")).strip()
        if target and target_support.get(target):
            runnable_tests.append(test_item)
        else:
            skipped_tests.append(test_item)

    print("=== test selection summary ===")
    print(f"Total tests in config: {len(cpp_tests)}")
    print(f"Runnable tests: {len(runnable_tests)}")
    print(f"Skipped tests (unsupported target): {len(skipped_tests)}")
    for skipped in skipped_tests:
        print(f"- skip: {skipped.get('name', 'unnamed_test')} (target={skipped.get('target', '')})")

    if not runnable_tests:
        print("Error: No runnable tests for current clang++ environment.")
        return 1

    print("=== running cpp_tests ===")
    print(f"Parallel jobs: {worker_count}")
    compile_failed_count = 0
    invalid_count = 0
    compare_diff_count = 0
    compare_run_count = 0
    vtable_compare_run_count = 0
    vtable_compare_diff_count = 0
    record_compare_run_count = 0
    record_compare_diff_count = 0

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(
                run_one_test,
                test_item=test_item,
                args=args,
                config_dir=source_root,
                symbol_store=symbol_store,
            )
            for test_item in runnable_tests
        ]
        ordered_results = [future.result() for future in futures]

    for test_item, result in zip(runnable_tests, ordered_results):
        test_name = str(test_item.get("name", "unnamed_test"))
        print(f"[RUN ] {test_name}")

        if result["status"] == "invalid":
            invalid_count += 1
            print(f"[FAIL] {test_name}: {result['message']}")
            continue

        if result["status"] == "compile_failed":
            compile_failed_count += 1
            print(f"[FAIL] {test_name}: compile failed")
            if args.debug:
                print(f"Command: {_format_command(result['command'])}")
            if result.get("output"):
                print(result["output"])
            continue

        print(f"[PASS] {test_name}: compile succeeded")
        if args.debug:
            print(f"Command: {_format_command(result['command'])}")

        compare_reports = result.get("compare_reports")
        if compare_reports:
            for compare_report in compare_reports:
                compare_run_count += 1
                is_record = compare_report.get("comparison_kind") == "record_layout"
                if is_record:
                    record_compare_run_count += 1
                    lines = format_record_compare_report(compare_report, include_differences=not args.debug)
                else:
                    vtable_compare_run_count += 1
                    lines = format_vtable_compare_report(compare_report, include_differences=not args.debug)
                for line in lines:
                    print(f"  {line}")
                if compare_report.get("differences"):
                    compare_diff_count += 1
                    if is_record:
                        record_compare_diff_count += 1
                    else:
                        vtable_compare_diff_count += 1
                if args.debug:
                    if is_record:
                        compiler_debug_lines = format_compiler_record_members(compare_report)
                        reference_debug_lines = format_reference_record_members(compare_report)
                        diff_lines = format_record_compare_differences(compare_report)
                        print("  [DEBUG] Compiler record members:")
                    else:
                        compiler_debug_lines = format_compiler_vtable_entries(compare_report)
                        reference_debug_lines = format_reference_vtable_entries(compare_report)
                        diff_lines = format_vtable_compare_differences(compare_report)
                        print("  [DEBUG] Compiler vtable entries:")
                    for debug_line in compiler_debug_lines:
                        print(f"    {debug_line}")
                    if is_record:
                        print("  [DEBUG] YAML reference struct members:")
                    else:
                        print("  [DEBUG] YAML reference vtable entries:")
                    for debug_line in reference_debug_lines:
                        print(f"    {debug_line}")
                    for diff_line in diff_lines:
                        print(f"  {diff_line}")

        elif args.debug and result.get("output"):
            print("  (Compiler output)")
            print(result["output"])

    print("=== done ===")
    print(f"Compile failures: {compile_failed_count}")
    print(f"Invalid test items: {invalid_count}")
    print(f"Layout compares run: {compare_run_count}")
    print(f"Layout compares with differences: {compare_diff_count}")
    print(f"VTable compares run: {vtable_compare_run_count}")
    print(f"VTable compares with differences: {vtable_compare_diff_count}")
    print(f"Record layout compares run: {record_compare_run_count}")
    print(f"Record layout compares with differences: {record_compare_diff_count}")
    if compare_diff_count > 0:
        print("[FAIL] Layout compare differences are treated as test failures.")

    if compile_failed_count > 0 or invalid_count > 0 or compare_diff_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
