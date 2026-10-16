import importlib.machinery
import unittest
from unittest.mock import patch

from tests import optional_dependencies as dependencies


class OptionalDependencyTests(unittest.TestCase):
    def test_dependency_matrix_skips_only_the_selected_tests(self) -> None:
        for sevenzip, binsync in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(sevenzip=sevenzip, binsync=binsync):
                executed = []
                spec = importlib.machinery.ModuleSpec("binsync", loader=None) if binsync else None
                with (
                    patch.object(dependencies.shutil, "which", return_value="7z" if sevenzip else None),
                    patch.object(dependencies.importlib.util, "find_spec", return_value=spec),
                ):

                    class ArchiveTests(unittest.TestCase):
                        @dependencies.requires_7z
                        def test_archive(self):
                            executed.append("7z")

                        def test_parser(self):
                            executed.append("parser")

                    @dependencies.requires_binsync
                    class BinSyncTests(unittest.TestCase):
                        def test_candidate(self):
                            dependencies.require_binsync()
                            executed.append("binsync")

                    suite = unittest.TestSuite(
                        (
                            unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveTests),
                            unittest.defaultTestLoader.loadTestsFromTestCase(BinSyncTests),
                        )
                    )
                    result = unittest.TestResult()
                    suite.run(result)

                self.assertTrue(result.wasSuccessful(), result.errors or result.failures)
                self.assertEqual(3, result.testsRun)
                self.assertEqual(int(not sevenzip) + int(not binsync), len(result.skipped))
                self.assertEqual(
                    {"parser"} | ({"7z"} if sevenzip else set()) | ({"binsync"} if binsync else set()),
                    set(executed),
                )
                for _test, reason in result.skipped:
                    self.assertIn("required", reason)

    def test_shared_fixture_skips_before_creating_a_repository(self) -> None:
        from tests.test_binsync_candidate import BinSyncCandidateTests
        from tests.test_release_bundle import ReleaseBundleTests

        with patch.object(dependencies.importlib.util, "find_spec", return_value=None):
            candidate = BinSyncCandidateTests()
            with patch.object(candidate, "_git") as git:
                with self.assertRaisesRegex(unittest.SkipTest, "binsync Python package"):
                    candidate._repository(None)
                git.assert_not_called()

            with patch("tests.test_release_bundle.Path") as path:
                with self.assertRaisesRegex(unittest.SkipTest, "binsync Python package"):
                    ReleaseBundleTests()._fixture(None)
                path.assert_not_called()
