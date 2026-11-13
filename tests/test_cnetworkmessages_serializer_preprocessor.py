import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import load_module


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "ida_preprocessor_scripts"
    / "find-CNetworkMessages_RegisterNetworkFieldSerializer-AND-CNetworkMessages_RegisterNetworkArrayFieldSerializer-14197.py"
)
SIGNATURE_GENERATOR = "ida_preprocessor_scripts._vtable_slot_anchor_common.preprocess_gen_func_sig_via_mcp"
REGISTRY_HELPER = "ida_preprocessor_scripts._network_registry_vfunc_common"


class TestNetworkSerializerVfuncPreprocessor(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, platform="linux", owners=None, callers=None, entries=None, signature_ok=True, script=SCRIPT):
        finder = load_module(script, "network_serializer_vfuncs_14197")
        entries = entries if entries is not None else {2: 0x1200, 5: 0x1500}
        if entries:
            Path(directory, f"CNetworkMessages_vtable.{platform}.yaml").write_text(
                yaml.safe_dump({"vtable_entries": entries}), encoding="utf-8"
            )
        outputs = [Path(directory, f"{name}.{platform}.yaml") for name, _anchor in finder.TARGETS]
        owners = owners if owners is not None else [{0x1200}, {0x1500}]
        callers = callers if callers is not None else {}

        async def generate_signature(**kwargs):
            if not signature_ok:
                return None
            address = int(str(kwargs["func_va"]), 0)
            return {"func_rva": hex(address), "func_size": "0x20", "func_sig": "48 85 C0 74 ??"}

        with (
            patch(f"{REGISTRY_HELPER}._collect_xref_func_starts_for_string", AsyncMock(side_effect=owners)),
            patch(
                f"{REGISTRY_HELPER}._collect_single_call_or_jump_xref_func_starts_for_ea",
                AsyncMock(side_effect=lambda **kwargs: callers.get(kwargs["target_ea"])),
            ) as collect_callers,
            patch(SIGNATURE_GENERATOR, AsyncMock(side_effect=generate_signature)) as generate,
        ):
            result = await finder.preprocess_skill(
                session=AsyncMock(),
                skill_name=SCRIPT.stem,
                expected_outputs=[str(path) for path in outputs],
                old_yaml_map={str(path): "obsolete-signature.yaml" for path in outputs},
                new_binary_dir=directory,
                platform=platform,
                image_base=0,
            )
        payloads = [yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None for path in outputs]
        return result, payloads, collect_callers, generate

    async def test_resolves_inlined_implementations_without_probing_callers(self):
        with TemporaryDirectory() as directory:
            result, payloads, callers, _generate = await self._run(directory)
        self.assertTrue(result)
        self.assertEqual([2, 5], [payload["vfunc_index"] for payload in payloads])
        self.assertEqual(["0x1200", "0x1500"], [payload["func_va"] for payload in payloads])
        callers.assert_not_awaited()

    async def test_resolves_wrappers_and_ignores_nonvirtual_callers(self):
        with TemporaryDirectory() as directory:
            result, payloads, callers, _generate = await self._run(
                directory,
                owners=[{0x8000}, {0x9000}],
                callers={0x8000: {0x1200, 0x8100}, 0x9000: {0x1500, 0x9100}},
            )
        self.assertTrue(result)
        self.assertEqual([2, 5], [payload["vfunc_index"] for payload in payloads])
        self.assertEqual(["0x10", "0x28"], [payload["vfunc_offset"] for payload in payloads])
        self.assertEqual(2, callers.await_count)

    async def test_supports_mixed_inline_states_and_shifted_slots_on_both_platforms(self):
        for platform in ("windows", "linux"):
            for owners, callers in (
                ([{0x8000}, {0x1500}], {0x8000: {0x1200}}),
                ([{0x1200}, {0x9000}], {0x9000: {0x1500}}),
            ):
                with self.subTest(platform=platform, owners=owners), TemporaryDirectory() as directory:
                    result, payloads, _callers, _generate = await self._run(
                        directory,
                        platform=platform,
                        owners=owners,
                        callers=callers,
                        entries={11: 0x1200, 17: 0x1500},
                    )
                    self.assertTrue(result)
                    self.assertEqual([11, 17], [payload["vfunc_index"] for payload in payloads])
                    self.assertEqual(["0x58", "0x88"], [payload["vfunc_offset"] for payload in payloads])

    async def test_rejects_missing_or_ambiguous_anchors_before_emitting_outputs(self):
        for owners in ([set(), {0x1500}], [{0x1200, 0x8000}, {0x1500}], [{0x1200}, None]):
            with self.subTest(owners=owners), TemporaryDirectory() as directory:
                result, payloads, _callers, generate = await self._run(directory, owners=owners)
                self.assertFalse(result)
                self.assertEqual([None, None], payloads)
                generate.assert_not_awaited()

    async def test_rejects_missing_or_ambiguous_wrappers_before_emitting_outputs(self):
        for candidate_callers in (None, set(), {0x9100}, {0x1500, 0x1600}):
            with self.subTest(callers=candidate_callers), TemporaryDirectory() as directory:
                result, payloads, _callers, generate = await self._run(
                    directory,
                    owners=[{0x1200}, {0x9000}],
                    callers={0x9000: candidate_callers},
                    entries={2: 0x1200, 5: 0x1500, 8: 0x1600},
                )
                self.assertFalse(result)
                self.assertEqual([None, None], payloads)
                generate.assert_not_awaited()

    async def test_rejects_an_implementation_shared_by_multiple_vtable_slots(self):
        with TemporaryDirectory() as directory:
            result, payloads, _callers, generate = await self._run(
                directory, entries={2: 0x1200, 3: 0x1200, 5: 0x1500}
            )
        self.assertFalse(result)
        self.assertEqual([None, None], payloads)
        generate.assert_not_awaited()

    async def test_rejects_missing_vtable_or_signature_generation_failure(self):
        for kwargs in ({"entries": {}}, {"signature_ok": False}):
            with self.subTest(kwargs=kwargs), TemporaryDirectory() as directory:
                result, payloads, _callers, _generate = await self._run(directory, **kwargs)
                self.assertFalse(result)
                self.assertEqual([None, None], payloads)

    async def test_rejects_both_registration_roles_resolving_to_the_same_slot(self):
        with TemporaryDirectory() as directory:
            result, payloads, _callers, generate = await self._run(directory, owners=[{0x1200}, {0x1200}])
        self.assertFalse(result)
        self.assertEqual([None, None], payloads)
        generate.assert_not_awaited()

    async def test_resolves_all_three_callback_registry_roles_with_the_shared_helper(self):
        script = SCRIPT.parent / "find-CNetworkMessages_RegistryCallbacks-14197.py"
        for platform in ("windows", "linux"):
            with self.subTest(platform=platform), TemporaryDirectory() as directory:
                result, payloads, _callers, _generate = await self._run(
                    directory,
                    script=script,
                    platform=platform,
                    entries={3: 0x1300, 8: 0x1800, 14: 0x1E00},
                    owners=[{0x9000}, {0x1800}, {0xB000}],
                    callers={0x9000: {0x1300}, 0xB000: {0x1E00}},
                )
                self.assertTrue(result)
                self.assertEqual([3, 8, 14], [payload["vfunc_index"] for payload in payloads])


if __name__ == "__main__":
    unittest.main()
