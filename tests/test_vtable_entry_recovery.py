import json
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml

import ida_analyze_util as util
from tests.ida_preprocessor_test_support import py_eval_payload


class EntrySession:
    def __init__(self, *, pointer=0x2000, code=True, executable=True, owner=None, succeeds=True):
        self.pointer = pointer
        self.code = code
        self.executable = executable
        self.owner = owner
        self.succeeds = succeeds
        self.defined = []

    async def call_tool(self, name, arguments):
        assert name == "py_eval"

        def add_func(addr):
            self.defined.append(addr)
            if self.succeeds:
                self.owner = types.SimpleNamespace(start_ea=addr, end_ea=addr + 7)
            return self.succeeds

        api = types.SimpleNamespace(
            get_func=lambda addr: self.owner,
            getseg=lambda addr: types.SimpleNamespace(perm=1 if self.executable else 0),
            SEGPERM_EXEC=1,
            add_func=add_func,
        )
        modules = {
            "idaapi": api,
            "ida_bytes": types.SimpleNamespace(
                get_qword=lambda addr: self.pointer,
                get_full_flags=lambda addr: 1,
                is_code=lambda flags: self.code,
            ),
            "ida_auto": types.SimpleNamespace(auto_wait=lambda: None),
        }
        namespace = {}
        with patch.dict("sys.modules", modules):
            exec(arguments["code"], {}, namespace)
        return py_eval_payload(json.loads(namespace["result"]))


class TestVtableEntryRecovery(unittest.IsolatedAsyncioTestCase):
    async def run_recovery(self, **kwargs):
        session = EntrySession(**kwargs)
        result = await util._recover_vtable_entries_via_mcp(
            session, {"vtable_va": "0x1000", "vtable_entries": {0: "0x2000"}}
        )
        return session, result

    async def test_restores_cached_vtable_entry_without_rebuilding_vtable_artifact(self):
        session, result = await self.run_recovery()
        self.assertEqual([0x2000], session.defined)
        self.assertTrue(result)

    async def test_rejects_stale_pointer_data_and_non_code(self):
        for kwargs in ({"pointer": 0x3000}, {"code": False}, {"executable": False}):
            with self.subTest(kwargs=kwargs):
                session, _ = await self.run_recovery(**kwargs)
                self.assertEqual([], session.defined)

    async def test_never_splits_an_existing_function(self):
        owner = types.SimpleNamespace(start_ea=0x1FF0, end_ea=0x2010)
        session, _ = await self.run_recovery(owner=owner)
        self.assertEqual([], session.defined)
        self.assertEqual(0x1FF0, session.owner.start_ea)

    async def test_reports_failed_definition(self):
        session, result = await self.run_recovery(succeeds=False)
        self.assertEqual([0x2000], session.defined)
        self.assertFalse(result)

    async def test_inherited_slot_retries_exact_metadata_after_recovery(self):
        with TemporaryDirectory() as root:
            directory = Path(root)
            for filename, payload in (
                ("IBase_Get.windows.yaml", {"vfunc_index": 0, "vtable_name": "IBase"}),
                ("Derived_vtable.windows.yaml", {"vtable_va": "0x1000", "vtable_entries": {0: "0x2000"}}),
            ):
                (directory / filename).write_text(yaml.safe_dump(payload), encoding="utf-8")
            session = EntrySession()
            result = await util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="Derived_Get",
                target_output=str(directory / "Derived_Get.windows.yaml"),
                old_yaml_map={},
                new_binary_dir=root,
                platform="windows",
                image_base=0,
                base_vfunc_name="IBase_Get",
                inherit_vtable_class="Derived",
                generate_func_sig=False,
            )
            self.assertEqual([0x2000], session.defined)
            self.assertEqual("0x2000", result["func_va"])
            self.assertEqual(0, result["vfunc_index"])
            self.assertNotIn("func_sig", result)

    async def test_xref_intersection_is_recomputed_after_entry_recovery(self):
        with TemporaryDirectory() as root:
            table = Path(root) / "Derived_vtable.windows.yaml"
            table.write_text(yaml.safe_dump({"vtable_va": "0x1000", "vtable_entries": {0: "0x2000"}}), encoding="utf-8")
            collect = AsyncMock(side_effect=[{0x3000}, {0x2000}])
            signature = AsyncMock(return_value={"func_va": "0x2000", "func_sig": "AA BB"})
            session = EntrySession()
            with (
                patch.object(util, "_collect_xref_func_starts_for_string", collect),
                patch.object(util, "preprocess_gen_func_sig_via_mcp", signature),
            ):
                result = await util.preprocess_func_xrefs_via_mcp(
                    session=session,
                    func_name="Derived_Get",
                    xref_strings=["anchor"],
                    xref_gvs=[],
                    xref_signatures=[],
                    xref_funcs=[],
                    exclude_funcs=[],
                    exclude_strings=[],
                    exclude_gvs=[],
                    exclude_signatures=[],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0,
                    vtable_class="Derived",
                )
            self.assertEqual([0x2000], session.defined)
            self.assertEqual(2, collect.await_count)
            self.assertEqual("0x2000", result["func_va"])
