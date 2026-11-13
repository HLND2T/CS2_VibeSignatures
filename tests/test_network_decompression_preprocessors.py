import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import load_module


SCRIPTS = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts"
PARSER = "CNetworkStringTableClient_ParseUpdate"
CONCRETE = "CNetworkSystem_BufferToBufferDecompress"
INTERFACE = "INetworkSystem_BufferToBufferDecompress"


def _seed(directory, index=12):
    engine, network = Path(directory, "engine"), Path(directory, "networksystem")
    engine.mkdir(exist_ok=True)
    network.mkdir(exist_ok=True)
    payloads = (
        (network, "CNetworkSystem_vtable", {"vtable_entries": {index: "0x2000"}}),
        (network, CONCRETE, dict(func_name=CONCRETE, func_va="0x2000", vtable_name="CNetworkSystem",
                                 vfunc_index=index, vfunc_offset=hex(index * 8))),
        (engine, PARSER, dict(func_name=PARSER, func_va="0x1000")),
    )
    for root, name, payload in payloads:
        (root / f"{name}.linux.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
    return engine, network


class TestParseUpdateFinder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, owners, *, fail_signature=False):
        finder = load_module(SCRIPTS / f"find-{PARSER}-14197.py", "parse_update_14197")
        with TemporaryDirectory() as directory:
            output = Path(directory, f"{PARSER}.linux.yaml")

            async def collect(**kwargs):
                return owners.pop(0)

            with (
                patch.object(finder, "_collect_xref_func_starts_for_string", AsyncMock(side_effect=collect)),
                patch.object(finder, "preprocess_gen_func_sig_via_mcp", AsyncMock(return_value=None if fail_signature else
                    dict(func_sig="55 48 89 E5", func_va="0x1000", func_rva="0x1000", func_size="0x100"))) as generate,
            ):
                result = await finder.preprocess_skill(AsyncMock(), "finder", [str(output)],
                                                       {str(output): "old.yaml"}, directory, "linux", 0)
            payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
            return result, payload, generate

    async def test_uses_unique_intersection_of_current_diagnostics(self):
        result, payload, generate = await self._run([{0x1000, 0x2000}, {0x1000, 0x3000}])
        self.assertTrue(result)
        self.assertEqual(PARSER, payload["func_name"])
        self.assertEqual(0x1000, generate.call_args.kwargs["func_va"])

    async def test_rejects_missing_conflicting_ambiguous_owners_and_failed_signature(self):
        for owners, failed in (([set(), {0x1000}], False), ([{0x1000}, {0x2000}], False),
                               ([{0x1000, 0x2000}, {0x1000, 0x2000}], False),
                               ([{0x1000}, {0x1000}], True)):
            with self.subTest(owners=owners, failed=failed):
                result, payload, _ = await self._run(owners, fail_signature=failed)
                self.assertFalse(result)
                self.assertIsNone(payload)


class TestDecompressionConcreteFinder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, *, direct=False, callers=None, fail_signature=False):
        finder = load_module(SCRIPTS / f"find-{CONCRETE}-14197.py", "decompression_concrete_14197")
        with TemporaryDirectory() as directory:
            _, network = _seed(directory)
            output = network / f"{CONCRETE}.linux.yaml"
            output.unlink()
            with (
                patch("ida_preprocessor_scripts._network_registry_vfunc_common._collect_xref_func_starts_for_string",
                      AsyncMock(return_value={0x2000 if direct else 0x5000})),
                patch("ida_preprocessor_scripts._network_registry_vfunc_common._collect_single_call_or_jump_xref_func_starts_for_ea",
                      AsyncMock(return_value={0x2000} if callers is None else callers)) as caller_probe,
                patch.object(finder, "_write_slot_func_yaml", AsyncMock(return_value=not fail_signature)) as write,
            ):
                result = await finder.preprocess_skill(AsyncMock(), "finder", [str(output)], {}, str(network), "linux", 0)
            return result, write, caller_probe

    async def test_accepts_the_unique_direct_or_wrapper_vtable_entry(self):
        for direct in (True, False):
            with self.subTest(direct=direct):
                result, write, callers = await self._run(direct=direct)
                self.assertTrue(result)
                self.assertEqual("CNetworkSystem", write.call_args.kwargs["vtable_class"])
                self.assertEqual(12, write.call_args.kwargs["slot"])
                if direct:
                    callers.assert_not_awaited()
                else:
                    callers.assert_awaited_once()

    async def test_rejects_unproven_entry_and_failed_signature(self):
        for kwargs in (dict(callers=set()), dict(fail_signature=True)):
            with self.subTest(kwargs=kwargs):
                result, _, _ = await self._run(**kwargs)
                self.assertFalse(result)


class TestDecompressionInterfaceFinder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, *, index=12, mutation=None, fail_signature=False):
        finder = load_module(SCRIPTS / f"find-{INTERFACE}-14197.py", "decompression_interface_14197")
        with TemporaryDirectory() as directory:
            engine, network = _seed(directory, index)
            if mutation in ("identity", "address", "offset"):
                path = network / f"{CONCRETE}.linux.yaml"
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                data[{"identity": "func_name", "address": "func_va", "offset": "vfunc_offset"}[mutation]] = "0x9000"
                path.write_text(yaml.safe_dump(data), encoding="utf-8")
            elif mutation == "parser":
                (engine / f"{PARSER}.linux.yaml").write_text("func_name: Other\nfunc_va: '0x1000'\n", encoding="utf-8")
            output = (network if mutation == "output" else engine) / f"{INTERFACE}.linux.yaml"
            probe = AsyncMock(return_value=None if mutation == "missing_call" else
                              {"receiver": 0x7000, "calls": [{"offset": index * 8, "inst_va": 0x3010}]})
            if mutation == "transport":
                probe.side_effect = RuntimeError("IDA unavailable")
            with (
                patch.object(finder, "probe_global_receiver_calls", probe),
                patch.object(finder, "preprocess_gen_vfunc_sig_via_mcp", AsyncMock(return_value=None if fail_signature else
                                  {"vfunc_sig": "FF 50 60 84 C0"})) as generate,
            ):
                result = await finder.preprocess_skill(AsyncMock(), "finder", [str(output)], {}, str(engine), "linux", 0)
            payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
            return result, payload, probe, generate

    async def test_validates_current_concrete_slot_and_signs_the_four_argument_call(self):
        result, payload, probe, generate = await self._run(index=19)
        self.assertTrue(result)
        self.assertEqual(19, payload["vfunc_index"])
        self.assertEqual((4,), probe.call_args.kwargs["arities"])
        self.assertEqual((19 * 8,), probe.call_args.kwargs["offsets"])
        self.assertEqual(0x3010, generate.call_args.kwargs["inst_va"])

    async def test_rejects_stale_metadata_missing_calls_transport_and_signature_failure(self):
        for kwargs in [dict(mutation=m) for m in ("identity", "address", "offset", "parser", "output", "missing_call", "transport")] + [dict(fail_signature=True)]:
            with self.subTest(kwargs=kwargs):
                result, payload, _, _ = await self._run(**kwargs)
                self.assertFalse(result)
                self.assertIsNone(payload)


if __name__ == "__main__":
    unittest.main()
