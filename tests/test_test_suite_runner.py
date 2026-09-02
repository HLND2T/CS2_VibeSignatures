import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_test_suite


class TestSuiteClassifier(unittest.TestCase):
    def test_classifies_primary_suite_boundaries(self) -> None:
        cases = {
            "tests.test_ida_analyze_util.TestLlmDecompileSupport.test_example": ("unit",),
            "tests.test_symbol_store_architecture.TestSymbolStoreArchitecture.test_example": ("repository-contract",),
            "tests.test_process_reporter_redis.TestRedisProcessReporterIntegration.test_example": (
                "redis-integration",
            ),
            "tests.test_release_workflow.TestReleaseWorkflow.test_example": ("release-integration",),
            "tests.test_unknown.TestUnknown.test_example": (),
        }
        for test_id, expected in cases.items():
            with self.subTest(test_id=test_id):
                self.assertEqual(expected, run_test_suite.matching_primary_suites(test_id))


class TestSuiteAssignmentContract(unittest.TestCase):
    def test_every_discovered_test_is_assigned_once_and_all_is_the_union(self) -> None:
        test_cases = run_test_suite.discover_test_cases()
        assignments, issues = run_test_suite.build_assignments(test_cases)

        self.assertEqual([], issues)
        primary_ids = [test.id() for suite_name in run_test_suite.PRIMARY_SUITES for test in assignments[suite_name]]
        self.assertEqual(len(test_cases), len(primary_ids))
        self.assertEqual({test.id() for test in test_cases}, set(primary_ids))


if __name__ == "__main__":
    unittest.main()
