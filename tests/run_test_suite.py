#!/usr/bin/env python3
"""Run explicit unittest suites and audit that every discovered test is assigned once."""

from __future__ import annotations

import argparse
import sys
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
PRIMARY_SUITES = ("unit", "repository-contract", "redis-integration", "release-integration")
SUITE_NAMES = (*PRIMARY_SUITES, "all")

REPOSITORY_CONTRACT_MODULES = frozenset(
    {
        "test_abandon_staged_release",
        "test_build_self_runner_workflow",
        "test_config_scheduling_dependencies",
        "test_fix_cppheaders_skill",
        "test_pack_snapshot_skill",
        "test_pr_self_runner_workflow",
        "test_restore_from_snapshot_skill",
        "test_smoke_ida_mcp_2",
        "test_symbol_store_architecture",
        "test_trigger_release_build",
    }
)
REPOSITORY_CONTRACT_PREFIXES = (
    "test_agent_runner.TestOpenCodeSigFinderAgent",
    "test_agent_runner.TestSkillRunnerProjectPromptConfiguration",
    "test_analysis_config.RepositoryMigrationFixtureTests",
    "test_bump_download.TestBumpDownload.test_bump_workflow_prunes_local_only_tags_before_bump",
    "test_gamesymbol_snapshot_versioning.TestConfigDigestVersioning.test_checked_in_v1_regression_fixture_keeps_digest",
    "test_ida_mcp_session.TestMcpSessionBoundary.test_only_adapter_creates_raw_mcp_sessions",
    "test_llm_decompile_dependencies.TestRepositoryLlmDecompileDependencyPolicy",
    "test_test_suite_runner.TestSuiteAssignmentContract",
    "test_trusted_yaml.TestRepositoryYamlCompatibility",
)
REDIS_INTEGRATION_PREFIXES = (
    "test_process_reporter_redis.TestRedisProcessReporterIntegration",
    "test_process_scheduler_redis.TestRedisProcessSchedulerIntegration",
    "test_process_status_reader_redis.TestRedisProcessStatusReader",
)
RELEASE_INTEGRATION_MODULES = frozenset(
    {
        "test_completed_release_cleanup",
        "test_release_gamedata_smoke",
        "test_release_workflow",
        "test_release_workflow_guards",
    }
)
UNIT_MODULES = frozenset(
    {
        "test_agent_runner",
        "test_analysis_config",
        "test_binary_hashing",
        "test_bump_download",
        "test_copy_depot_bin",
        "test_cs2fow_gamedata",
        "test_define_inputfunc_preprocessor",
        "test_download_depot",
        "test_format_repo_files",
        "test_gamedata_candidate",
        "test_gamedata_utils",
        "test_gamesymbol_candidate",
        "test_gamesymbol_pr_cli",
        "test_gamesymbol_pr_reference_validation",
        "test_gamesymbol_pr_validation",
        "test_gamesymbol_snapshot_config",
        "test_gamesymbol_snapshot_ops",
        "test_gamesymbol_snapshot_versioning",
        "test_gamesymbol_store",
        "test_generate_reference_yaml",
        "test_ida_analyze_bin",
        "test_ida_analyze_util",
        "test_ida_llm_utils",
        "test_ida_mcp_session",
        "test_ida_preprocessor_contracts_commands",
        "test_ida_preprocessor_contracts_gamesystems",
        "test_ida_preprocessor_contracts_misc",
        "test_ida_preprocessor_contracts_network",
        "test_ida_remote_export",
        "test_ida_skill_preprocessor",
        "test_ida_vcall_finder",
        "test_igamesystem_dispatch_common",
        "test_igamesystem_slot_dispatch_preprocessor",
        "test_igamesystem_slot_dispatch_py_eval_behavior",
        "test_indirect_vcall_target_common",
        "test_init_gamebin",
        "test_llm_decompile_dependencies",
        "test_process_api",
        "test_process_reporter",
        "test_process_reporter_factory",
        "test_process_reporter_redis",
        "test_process_scheduler_redis",
        "test_process_status_reader_redis",
        "test_prune_pr_expected_output_bin",
        "test_ordinal_vtable_common",
        "test_register_api_callbacks_preprocessor",
        "test_register_event_listener_abstract_preprocessor",
        "test_registerconcommand_preprocessor",
        "test_run_cpp_tests",
        "test_script_desc_internal_preprocessor",
        "test_test_suite_runner",
        "test_trusted_yaml",
        "test_update_gamedata",
    }
)


def _normalized_test_id(test_id: str) -> str:
    return test_id.removeprefix("tests.")


def _test_module(test_id: str) -> str:
    return _normalized_test_id(test_id).split(".", 1)[0]


def _matches_prefix(test_id: str, prefixes: tuple[str, ...]) -> bool:
    normalized = _normalized_test_id(test_id)
    return any(normalized == prefix or normalized.startswith(f"{prefix}.") for prefix in prefixes)


def matching_primary_suites(test_id: str) -> tuple[str, ...]:
    """Return every primary suite selector matching a test ID."""
    module = _test_module(test_id)
    repository_contract = module in REPOSITORY_CONTRACT_MODULES or _matches_prefix(
        test_id, REPOSITORY_CONTRACT_PREFIXES
    )
    redis_integration = _matches_prefix(test_id, REDIS_INTEGRATION_PREFIXES)
    release_integration = module in RELEASE_INTEGRATION_MODULES
    special = repository_contract or redis_integration or release_integration
    unit = module in UNIT_MODULES and not special
    return tuple(
        suite_name
        for suite_name, matched in (
            ("unit", unit),
            ("repository-contract", repository_contract),
            ("redis-integration", redis_integration),
            ("release-integration", release_integration),
        )
        if matched
    )


def iter_test_cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_test_cases(item)
        else:
            yield item


def discover_test_cases() -> list[unittest.TestCase]:
    loader = unittest.defaultTestLoader
    discovered = loader.discover(str(TESTS_DIR), pattern="test_*.py")
    return list(iter_test_cases(discovered))


def build_assignments(test_cases) -> tuple[dict[str, list[unittest.TestCase]], list[str]]:
    assignments = {suite_name: [] for suite_name in PRIMARY_SUITES}
    issues = []
    seen_ids = set()
    for test in test_cases:
        test_id = test.id()
        if test_id in seen_ids:
            issues.append(f"duplicate discovery: {test_id}")
            continue
        seen_ids.add(test_id)
        matches = matching_primary_suites(test_id)
        if not matches:
            issues.append(f"unassigned: {test_id}")
        elif len(matches) > 1:
            issues.append(f"assigned to multiple suites {matches}: {test_id}")
        else:
            assignments[matches[0]].append(test)
    return assignments, issues


class TimedTextTestResult(unittest.TextTestResult):
    def __init__(self, *args, duration_count: int | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.duration_count = duration_count
        self.test_durations = []
        self._started_at = {}

    def startTest(self, test) -> None:
        self._started_at[test] = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test) -> None:
        started_at = self._started_at.pop(test, None)
        if started_at is not None:
            self.test_durations.append((time.perf_counter() - started_at, test.id()))
        super().stopTest(test)

    def print_durations(self) -> None:
        if self.duration_count is None:
            return
        durations = sorted(self.test_durations, reverse=True)
        if self.duration_count > 0:
            durations = durations[: self.duration_count]
        self.stream.writeln("\nSlowest test durations")
        self.stream.writeln("-" * 70)
        for duration, test_id in durations:
            self.stream.writeln(f"{duration:.3f}s     {test_id}")


class TimedTextTestRunner(unittest.TextTestRunner):
    def __init__(self, *args, duration_count: int | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.duration_count = duration_count

    def _makeResult(self):
        return TimedTextTestResult(
            self.stream,
            self.descriptions,
            self.verbosity,
            duration_count=self.duration_count,
        )

    def run(self, test):
        result = super().run(test)
        result.print_durations()
        return result


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=SUITE_NAMES)
    parser.add_argument("-b", "--buffer", action="store_true")
    parser.add_argument("-f", "--failfast", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--durations", type=int, metavar="N")
    args = parser.parse_args(argv)
    if args.durations is not None and args.durations < 0:
        parser.error("--durations must be zero or a positive integer")
    return args


def _passed_count(result) -> int:
    return result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)


def main(argv=None) -> int:
    args = _parse_args(argv)
    test_cases = discover_test_cases()
    assignments, issues = build_assignments(test_cases)
    counts = ", ".join(f"{name}={len(assignments[name])}" for name in PRIMARY_SUITES)
    print(f"Discovered {len(test_cases)} tests: {counts}")
    if issues:
        print("Suite assignment audit failed:", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 2

    selected = test_cases if args.suite == "all" else assignments[args.suite]
    print(f"Running suite {args.suite}: {len(selected)} tests")
    verbosity = 0 if args.quiet else 1 + args.verbose
    runner = TimedTextTestRunner(
        buffer=args.buffer,
        failfast=args.failfast,
        verbosity=verbosity,
        duration_count=args.durations,
    )
    result = runner.run(unittest.TestSuite(selected))
    print(
        f"Suite {args.suite}: total={result.testsRun} passed={_passed_count(result)} "
        f"failures={len(result.failures)} errors={len(result.errors)} skipped={len(result.skipped)}"
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
