from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import yaml

import ida_analyze_util
from tests.ida_preprocessor_test_support import FakeCallToolResult, load_module


TARGET = "CCSPlayer_WeaponServices_CanUse"


class TestWeaponServicesCanUsePreprocessor(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_callsite_signature_does_not_preempt_current_function_discovery(self):
        finder = load_module(
            Path("ida_preprocessor_scripts") / f"find-{TARGET}.py",
            "find_weapon_services_can_use",
        )
        for platform, image_base in (("windows", 0x180000000), ("linux", 0)):
            with self.subTest(platform=platform), TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root / f"{TARGET}.{platform}.yaml"
                old_output = root / f"old-{TARGET}.{platform}.yaml"
                old_output.write_text(
                    yaml.safe_dump(
                        {
                            "func_name": TARGET,
                            "vtable_name": "CCSPlayer_WeaponServices",
                            "vfunc_index": 1,
                            "vfunc_offset": "0x8",
                            "vfunc_sig": "FF 90 ?? ?? ?? ??",
                        }
                    ),
                    encoding="utf-8",
                )
                # A matching old callsite proves no function address or current slot.
                session = SimpleNamespace(
                    call_tool=AsyncMock(
                        return_value=FakeCallToolResult([{"matches": [hex(image_base + 0x8000)], "n": 1}])
                    )
                )
                current_function = {
                    "func_name": TARGET,
                    "func_va": hex(image_base + 0x4000),
                    "func_rva": "0x4000",
                    "func_size": "0x40",
                    "func_sig": "48 89 C8 C3",
                    "vtable_name": "CCSPlayer_WeaponServices",
                    "vfunc_index": 5,
                    "vfunc_offset": "0x28",
                }
                with patch.object(
                    ida_analyze_util,
                    "preprocess_func_xrefs_via_mcp",
                    AsyncMock(return_value=current_function),
                ) as find_current_function:
                    result = await finder.preprocess_skill(
                        session=session,
                        skill_name=f"find-{TARGET}",
                        expected_outputs=[str(output)],
                        old_yaml_map={str(output): str(old_output)},
                        new_binary_dir=str(root),
                        platform=platform,
                        image_base=image_base,
                    )

                self.assertTrue(result)
                self.assertEqual(current_function, yaml.safe_load(output.read_text(encoding="utf-8")))
                find_current_function.assert_awaited_once()
                self.assertEqual(
                    ["CCSPlayer_ItemServices_CanAcquire"],
                    find_current_function.call_args.kwargs["xref_funcs"],
                )
                self.assertEqual(
                    "CCSPlayer_WeaponServices",
                    find_current_function.call_args.kwargs["vtable_class"],
                )
