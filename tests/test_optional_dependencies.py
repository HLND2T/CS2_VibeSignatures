import unittest
from unittest.mock import patch

from tests import optional_dependencies as dependencies


class OptionalDependencyTests(unittest.TestCase):
    def test_archive_dependency_skips_only_archive_tests(self):
        for available in (False, True):
            with self.subTest(available=available):
                executed = []
                with patch.object(dependencies.shutil, "which", return_value="7z" if available else None):

                    class ArchiveTests(unittest.TestCase):
                        @dependencies.requires_7z
                        def test_archive(self):
                            executed.append("archive")

                        def test_parser(self):
                            executed.append("parser")

                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveTests).run(result)
                self.assertTrue(result.wasSuccessful(), result.errors or result.failures)
                self.assertEqual(2, result.testsRun)
                self.assertEqual(int(not available), len(result.skipped))
                self.assertEqual({"parser"} | ({"archive"} if available else set()), set(executed))
