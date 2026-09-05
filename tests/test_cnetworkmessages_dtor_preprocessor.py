import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml


def _import_finder_module():
    path = Path("ida_preprocessor_scripts/find-CNetworkMessages_dtor.py")
    spec = importlib.util.spec_from_file_location("find_cnetworkmessages_dtor", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestCNetworkMessagesDtorPreprocessor(unittest.IsolatedAsyncioTestCase):
    async def test_resolves_abi_destructor_slot_and_generates_canonical_signature(self) -> None:
        cases = (
            ("windows", 37, 36, "0x1800d5680", 0x180000000),
            ("linux", 38, 36, "0x2a90c0", 0),
        )
        for platform, count, expected_index, func_va, image_base in cases:
            with self.subTest(platform=platform), TemporaryDirectory() as temp_dir:
                module = _import_finder_module()
                artifact_dir = Path(temp_dir) / "networksystem"
                artifact_dir.mkdir(parents=True)
                output = artifact_dir / f"CNetworkMessages_dtor.{platform}.yaml"
                entries = {index: hex(0x1000 + index * 0x10) for index in range(count)}
                entries[expected_index] = func_va
                (artifact_dir / f"CNetworkMessages_vtable.{platform}.yaml").write_text(
                    yaml.safe_dump(
                        {
                            "vtable_class": "CNetworkMessages",
                            "vtable_numvfunc": count,
                            "vtable_entries": entries,
                        },
                        sort_keys=False,
                    ),
                    encoding="utf-8",
                )
                generated = {
                    "func_va": func_va,
                    "func_rva": hex(int(func_va, 0) - image_base),
                    "func_size": "0x3a",
                    "func_sig": "48 83 EC ??",
                }

                with (
                    patch.object(
                        module,
                        "preprocess_gen_func_sig_via_mcp",
                        AsyncMock(return_value=generated),
                    ) as generate_signature,
                    patch.object(module, "write_func_yaml") as write_yaml,
                ):
                    result = await module.preprocess_skill(
                        session="session",
                        skill_name="find-CNetworkMessages_dtor",
                        expected_outputs=[str(output)],
                        old_yaml_map={},
                        new_binary_dir=str(artifact_dir),
                        platform=platform,
                        image_base=image_base,
                        debug=False,
                    )

                self.assertTrue(result)
                generate_signature.assert_awaited_once_with(
                    session="session",
                    func_va=int(func_va, 0),
                    image_base=image_base,
                    allow_across_function_boundary=False,
                    debug=False,
                )
                write_yaml.assert_called_once_with(
                    str(output),
                    {
                        "func_name": "CNetworkMessages_dtor",
                        **generated,
                        "vtable_name": "CNetworkMessages",
                        "vfunc_offset": "0x120",
                        "vfunc_index": 36,
                    },
                )

    async def test_fails_closed_for_noncontiguous_vtable(self) -> None:
        module = _import_finder_module()
        with TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir) / "networksystem"
            artifact_dir.mkdir(parents=True)
            output = artifact_dir / "CNetworkMessages_dtor.windows.yaml"
            (artifact_dir / "CNetworkMessages_vtable.windows.yaml").write_text(
                yaml.safe_dump(
                    {
                        "vtable_class": "CNetworkMessages",
                        "vtable_numvfunc": 37,
                        "vtable_entries": {36: "0x1800d5680"},
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )

            with patch.object(
                module,
                "preprocess_gen_func_sig_via_mcp",
                AsyncMock(),
            ) as generate_signature:
                result = await module.preprocess_skill(
                    session="session",
                    skill_name="find-CNetworkMessages_dtor",
                    expected_outputs=[str(output)],
                    old_yaml_map={},
                    new_binary_dir=str(artifact_dir),
                    platform="windows",
                    image_base=0x180000000,
                    debug=False,
                )

            self.assertFalse(result)
            generate_signature.assert_not_awaited()

    async def test_fails_closed_when_signature_generation_fails(self) -> None:
        module = _import_finder_module()
        with TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir) / "networksystem"
            artifact_dir.mkdir(parents=True)
            output = artifact_dir / "CNetworkMessages_dtor.windows.yaml"
            entries = {index: hex(0x180000000 + index * 0x10) for index in range(37)}
            (artifact_dir / "CNetworkMessages_vtable.windows.yaml").write_text(
                yaml.safe_dump(
                    {
                        "vtable_class": "CNetworkMessages",
                        "vtable_numvfunc": 37,
                        "vtable_entries": entries,
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )

            with (
                patch.object(
                    module,
                    "preprocess_gen_func_sig_via_mcp",
                    AsyncMock(return_value=None),
                ),
                patch.object(module, "write_func_yaml") as write_yaml,
            ):
                result = await module.preprocess_skill(
                    session="session",
                    skill_name="find-CNetworkMessages_dtor",
                    expected_outputs=[str(output)],
                    old_yaml_map={},
                    new_binary_dir=str(artifact_dir),
                    platform="windows",
                    image_base=0x180000000,
                    debug=False,
                )

            self.assertFalse(result)
            write_yaml.assert_not_called()


if __name__ == "__main__":
    unittest.main()
