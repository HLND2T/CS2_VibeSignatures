import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

import yaml

import ida_analyze_util


class _FakeTextContent:
    def __init__(self, text: str) -> None:
        self.text = text


class _FakeCallToolResult:
    def __init__(self, payload: dict[str, object]) -> None:
        self.content = [_FakeTextContent(json.dumps(payload))]


def _py_eval_payload(payload: object) -> _FakeCallToolResult:
    return _FakeCallToolResult(
        {
            "result": json.dumps(payload),
            "stdout": "",
            "stderr": "",
        }
    )


def _write_yaml(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


class TestPreprocessIndexBasedVfuncViaMcp(unittest.IsolatedAsyncioTestCase):
    async def test_reads_sibling_module_yaml_and_derives_index_from_offset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            gamever_dir = Path(temp_dir) / "bin" / "14141"
            current_module_dir = gamever_dir / "schemasystem"
            sibling_module_dir = gamever_dir / "server"
            target_output = current_module_dir / "CDerived_CreateFieldChangedEventQueue.windows.yaml"

            _write_yaml(
                sibling_module_dir / "CFlattenedSerializers_CreateFieldChangedEventQueue.windows.yaml",
                {
                    "vtable_name": "CFlattenedSerializers",
                    "vfunc_offset": "0x118",
                },
            )
            _write_yaml(
                current_module_dir / "CDerived_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        35: "0x180001180",
                    }
                },
            )

            session = AsyncMock()
            session.call_tool.return_value = _py_eval_payload(
                {
                    "func_va": "0x180001180",
                    "func_size": "0x40",
                }
            )

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_CreateFieldChangedEventQueue",
                target_output=str(target_output),
                old_yaml_map={},
                new_binary_dir=str(current_module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="../server/CFlattenedSerializers_CreateFieldChangedEventQueue",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(35, result["vfunc_index"])
            self.assertEqual("0x118", result["vfunc_offset"])
            self.assertEqual("CDerived_CreateFieldChangedEventQueue", result["func_name"])
            self.assertEqual("0x1180", result["func_rva"])
            session.call_tool.assert_awaited_once()

    async def test_returns_none_for_misaligned_vfunc_offset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"

            _write_yaml(
                module_dir / "CBaseEntity_Touch.windows.yaml",
                {
                    "vtable_name": "CBaseEntity",
                    "vfunc_offset": "0x11a",
                },
            )
            _write_yaml(
                module_dir / "CDerived_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        35: "0x180001180",
                    }
                },
            )

            session = AsyncMock()

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_Touch",
                target_output=str(module_dir / "CDerived_Touch.windows.yaml"),
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="CBaseEntity_Touch",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNone(result)
            session.call_tool.assert_not_awaited()

    async def test_returns_none_for_mismatched_vfunc_index_and_offset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"

            _write_yaml(
                module_dir / "CBaseEntity_Touch.windows.yaml",
                {
                    "vtable_name": "CBaseEntity",
                    "vfunc_index": 34,
                    "vfunc_offset": "0x118",
                },
            )
            _write_yaml(
                module_dir / "CDerived_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        35: "0x180001180",
                    }
                },
            )

            session = AsyncMock()

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_Touch",
                target_output=str(module_dir / "CDerived_Touch.windows.yaml"),
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="CBaseEntity_Touch",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNone(result)
            session.call_tool.assert_not_awaited()

    async def test_returns_none_for_base_vfunc_path_outside_gamever_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            session = AsyncMock()

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_Touch",
                target_output=str(module_dir / "CDerived_Touch.windows.yaml"),
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="../../outside/CBaseEntity_Touch",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNone(result)
            session.call_tool.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
