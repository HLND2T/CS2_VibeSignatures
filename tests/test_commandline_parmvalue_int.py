import importlib
import unittest

from tests.test_script_desc_internal_preprocessor import _run_script_desc_py_eval


class TestCommandLineOverloadCallbacks(unittest.TestCase):
    def collect(self, script_name):
        return _run_script_desc_py_eval(
            source_func_va=0x1000,
            funcs={
                0x1000: (0x1000, 0x1100),
                0x5000: (0x5000, 0x5050),
                0x6000: (0x6000, 0x6060),
            },
            strings={},
            instructions={},
            names={"IntegerCallback": 0x5000, "FloatCallback": 0x6000},
            decompiled_lines=[
                '*(_QWORD *)(v1 + 8) = "CommandLineInt";',
                "*(_QWORD *)(v1 + 64) = IntegerCallback;",
                '*(_QWORD *)(v2 + 8) = "CommandLineFloat";',
                "*(_QWORD *)(v2 + 64) = FloatCallback;",
            ],
            script_names=[script_name],
        )["entries"]

    def test_registered_overloads_select_distinct_callbacks(self):
        for suffix, expected_address in [("Int", "0x5000"), ("Float", "0x6000")]:
            with self.subTest(overload=suffix):
                finder = importlib.import_module(f"ida_preprocessor_scripts.find-Script_CommandLine{suffix}")
                entries = self.collect(finder.TARGET_SCRIPT_FUNCTIONS[0]["script_name"])
                self.assertEqual(1, len(entries))
                self.assertEqual(expected_address, entries[0]["func_va"])

    def test_missing_callback_does_not_select_another_overload(self):
        self.assertEqual([], self.collect("CommandLineMissing"))
