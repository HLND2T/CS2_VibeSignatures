import importlib
import json
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, call, patch

import yaml


def _import_common_module():
    return importlib.import_module("ida_preprocessor_scripts._script_desc_internal_common")


def _write_source_yaml(tmpdir: str, platform: str) -> Path:
    new_binary_dir = Path(tmpdir)
    source_yaml = new_binary_dir / f"CBaseModelEntity_GetScriptDescInternal.{platform}.yaml"
    source_yaml.write_text(
        yaml.safe_dump(
            {
                "func_name": "CBaseModelEntity_GetScriptDescInternal",
                "func_va": "0x1805d75f0",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return new_binary_dir


def _op(kind: int, *, addr: int = 0, reg: int | None = None) -> dict[str, object]:
    return {"type": kind, "addr": addr, "reg": reg}


class _FakeFunc:
    def __init__(self, start_ea: int, end_ea: int) -> None:
        self.start_ea = start_ea
        self.end_ea = end_ea


class _FakeInsn:
    def __init__(self) -> None:
        self.ops = [types.SimpleNamespace(type=0, addr=0, reg=None) for _ in range(3)]


class _FakePseudocodeLine:
    def __init__(self, line: str) -> None:
        self.line = line


class _FakeCfunc:
    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    def get_pseudocode(self):
        return [_FakePseudocodeLine(line) for line in self._lines]


def _run_script_desc_py_eval(
    *,
    source_func_va: int,
    funcs: dict[int, tuple[int, int]],
    strings: dict[int, str],
    instructions: dict[int, dict[str, object]],
    names: dict[str, int] | None = None,
    decompiled_lines: list[str] | None = None,
) -> dict[str, object]:
    module = _import_common_module()
    code = module._build_script_desc_internal_py_eval(
        hex(source_func_va),
        [
            "GetModelScale",
            "ScriptLookupAttachment",
            "ScriptSetMaterialGroup",
        ],
    )
    heads = sorted(instructions)

    def fake_decode_insn(insn: _FakeInsn, ea: int) -> bool:
        spec = instructions.get(ea)
        if spec is None:
            return False
        insn.ops = [types.SimpleNamespace(**op) for op in spec.get("ops", [])]
        return True

    def fake_strlit(ea: int):
        text = strings.get(ea)
        return text.encode("utf-8") if text is not None else None

    fake_idaapi = types.SimpleNamespace(
        o_reg=1,
        o_displ=2,
        o_phrase=3,
        o_imm=4,
        o_mem=5,
        o_near=6,
        o_far=7,
        BADADDR=-1,
        get_func=lambda ea: _FakeFunc(*funcs[ea]) if ea in funcs else None,
        add_func=lambda _ea: None,
        insn_t=_FakeInsn,
        decode_insn=fake_decode_insn,
    )
    fake_idautils = types.SimpleNamespace(
        Heads=lambda start, end: [ea for ea in heads if start <= ea < end],
    )
    fake_ida_hexrays = types.SimpleNamespace(
        decompile=lambda _ea: _FakeCfunc(decompiled_lines) if decompiled_lines else None,
    )
    fake_ida_lines = types.SimpleNamespace(tag_remove=lambda line: line)
    fake_idc = types.SimpleNamespace(
        print_insn_mnem=lambda ea: instructions.get(ea, {}).get("mnem", ""),
        print_operand=lambda ea, index: instructions.get(ea, {}).get(
            "operands",
            ("", "", ""),
        )[index],
        get_operand_value=lambda ea, index: instructions.get(ea, {}).get(
            "operand_values",
            (0, 0, 0),
        )[index],
        get_strlit_contents=fake_strlit,
        get_name_ea_simple=lambda name: (names or {}).get(name, fake_idaapi.BADADDR),
    )
    exec_globals: dict[str, object] = {}
    exec_locals: dict[str, object] = {}
    with patch.dict(
        "sys.modules",
        {
            "idaapi": fake_idaapi,
            "ida_hexrays": fake_ida_hexrays,
            "ida_lines": fake_ida_lines,
            "idautils": fake_idautils,
            "idc": fake_idc,
        },
    ):
        exec(code, exec_globals, exec_locals)
    return json.loads(exec_locals["result"])


class TestScriptDescInternalPyEvalBehavior(unittest.TestCase):
    def test_py_eval_extracts_script_functions_from_decompiled_assignments(self) -> None:
        payload = _run_script_desc_py_eval(
            source_func_va=0x1000,
            funcs={
                0x1000: (0x1000, 0x1100),
                0x5000: (0x5000, 0x5050),
                0x6000: (0x6000, 0x6060),
                0x7000: (0x7000, 0x7070),
            },
            strings={},
            instructions={},
            names={
                "CBaseModelEntity_GetModelScale": 0x5000,
                "CBaseModelEntity_ScriptLookupAttachment": 0x6000,
                "sub_MaterialGroup": 0x7000,
            },
            decompiled_lines=[
                "*v3 = _mm_unpacklo_epi64(",
                '  (__m128i)(unsigned __int64)"GetModelScale",',
                '  (__m128i)(unsigned __int64)"GetModelScale");',
                "v3[4].m128i_i64[0] = CBaseModelEntity_GetModelScale;",
                "v33 = _mm_insert_epi64(",
                '  v32, (signed __int64)"ScriptLookupAttachment", 1);',
                "*(__m128i *)v44 = v33;",
                "*(_QWORD *)(v44 + 64) = CBaseModelEntity_ScriptLookupAttachment;",
                "*(__m128i *)v62 = _mm_insert_epi64(",
                '  v61, (signed __int64)"ScriptSetMaterialGroup", 1);',
                "v62[4].m128i_i64[0] = (__int64)&sub_MaterialGroup;",
            ],
        )

        entries_by_script = {
            entry["script_name"]: {key: value for key, value in entry.items() if key != "order"}
            for entry in payload["entries"]
        }
        self.assertEqual(
            {
                "GetModelScale": {
                    "script_name": "GetModelScale",
                    "func_va": "0x5000",
                    "func_expr": "CBaseModelEntity_GetModelScale",
                    "desc_expr": "v3",
                },
                "ScriptLookupAttachment": {
                    "script_name": "ScriptLookupAttachment",
                    "func_va": "0x6000",
                    "func_expr": "CBaseModelEntity_ScriptLookupAttachment",
                    "desc_expr": "v44",
                },
                "ScriptSetMaterialGroup": {
                    "script_name": "ScriptSetMaterialGroup",
                    "func_va": "0x7000",
                    "func_expr": "(__int64)&sub_MaterialGroup",
                    "desc_expr": "v62",
                },
            },
            entries_by_script,
        )

    def test_py_eval_extracts_script_functions_without_hexrays(self) -> None:
        payload = _run_script_desc_py_eval(
            source_func_va=0x1000,
            funcs={
                0x1000: (0x1000, 0x1100),
                0x5000: (0x5000, 0x5050),
                0x6000: (0x6000, 0x6060),
                0x7000: (0x7000, 0x7070),
            },
            strings={
                0x3000: "GetModelScale",
                0x3010: "ScriptLookupAttachment",
                0x3020: "ScriptSetMaterialGroup",
            },
            instructions={
                0x1000: {
                    "mnem": "lea",
                    "operands": ("r13", "aGetmodelscale", ""),
                    "operand_values": (0, 0x3000, 0),
                    "ops": [_op(1, reg=13), _op(5, addr=0x3000)],
                },
                0x1004: {
                    "mnem": "movq",
                    "operands": ("xmm0", "r13", ""),
                    "ops": [_op(1, reg=100), _op(1, reg=13)],
                },
                0x1008: {
                    "mnem": "punpcklqdq",
                    "operands": ("xmm0", "xmm0", ""),
                    "ops": [_op(1, reg=100), _op(1, reg=100)],
                },
                0x100C: {
                    "mnem": "movups",
                    "operands": ("[rax]", "xmm0", ""),
                    "ops": [_op(3, addr=0, reg=1), _op(1, reg=100)],
                },
                0x1010: {
                    "mnem": "lea",
                    "operands": ("rdx", "CBaseModelEntity_GetModelScale", ""),
                    "operand_values": (0, 0x5000, 0),
                    "ops": [_op(1, reg=2), _op(5, addr=0x5000)],
                },
                0x1014: {
                    "mnem": "mov",
                    "operands": ("[rax+40h]", "rdx", ""),
                    "ops": [_op(2, addr=0x40, reg=1), _op(1, reg=2)],
                },
                0x1020: {
                    "mnem": "lea",
                    "operands": ("rax", "aScriptlookupat", ""),
                    "operand_values": (0, 0x3010, 0),
                    "ops": [_op(1, reg=1), _op(5, addr=0x3010)],
                },
                0x1024: {
                    "mnem": "mov",
                    "operands": ("[rdx+8]", "rax", ""),
                    "ops": [_op(2, addr=8, reg=2), _op(1, reg=1)],
                },
                0x1028: {
                    "mnem": "lea",
                    "operands": ("rcx", "CBaseModelEntity_ScriptLookupAttachment", ""),
                    "operand_values": (0, 0x6000, 0),
                    "ops": [_op(1, reg=3), _op(5, addr=0x6000)],
                },
                0x102C: {
                    "mnem": "mov",
                    "operands": ("[rdx+40h]", "rcx", ""),
                    "ops": [_op(2, addr=0x40, reg=2), _op(1, reg=3)],
                },
                0x1030: {
                    "mnem": "movq",
                    "operands": ("xmm0", "cs:off_display", ""),
                    "ops": [_op(1, reg=100), _op(5, addr=0x3000)],
                },
                0x1034: {
                    "mnem": "lea",
                    "operands": ("rax", "aScriptsetmater", ""),
                    "operand_values": (0, 0x3020, 0),
                    "ops": [_op(1, reg=1), _op(5, addr=0x3020)],
                },
                0x1038: {
                    "mnem": "pinsrq",
                    "operands": ("xmm0", "rax", "1"),
                    "operand_values": (0, 0, 1),
                    "ops": [_op(1, reg=100), _op(1, reg=1), _op(4)],
                },
                0x103C: {
                    "mnem": "movups",
                    "operands": ("[r8]", "xmm0", ""),
                    "ops": [_op(3, addr=0, reg=8), _op(1, reg=100)],
                },
                0x1040: {
                    "mnem": "lea",
                    "operands": ("rax", "sub_MaterialGroup", ""),
                    "operand_values": (0, 0x7000, 0),
                    "ops": [_op(1, reg=1), _op(5, addr=0x7000)],
                },
                0x1044: {
                    "mnem": "mov",
                    "operands": ("[r8+40h]", "rax", ""),
                    "ops": [_op(2, addr=0x40, reg=8), _op(1, reg=1)],
                },
            },
        )

        self.assertEqual(
            [
                {
                    "script_name": "GetModelScale",
                    "func_va": "0x5000",
                    "func_expr": "0x5000",
                    "source_ea": "0x1014",
                    "order": 0,
                },
                {
                    "script_name": "ScriptLookupAttachment",
                    "func_va": "0x6000",
                    "func_expr": "0x6000",
                    "source_ea": "0x102c",
                    "order": 1,
                },
                {
                    "script_name": "ScriptSetMaterialGroup",
                    "func_va": "0x7000",
                    "func_expr": "0x7000",
                    "source_ea": "0x1044",
                    "order": 2,
                },
            ],
            payload["entries"],
        )


class TestPreprocessScriptDescInternalSkill(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_matches_functions_by_script_name(self) -> None:
        module = _import_common_module()
        session = AsyncMock()
        entries = [
            {
                "script_name": "ScriptSetMaterialGroup",
                "func_va": "0x180AAA000",
                "func_expr": "CBaseModelEntity_ScriptSetMaterialGroup",
                "order": 0,
            },
            {
                "script_name": "ScriptLookupAttachment",
                "func_va": "0x180123450",
                "func_expr": "CBaseModelEntity_ScriptLookupAttachment",
                "order": 1,
            },
            {
                "script_name": "ScriptSetMeshGroupMask",
                "func_va": "0x180456780",
                "func_expr": "CBaseModelEntity_ScriptSetMeshGroupMask",
                "order": 2,
            },
        ]
        target_specs = [
            {
                "script_name": "ScriptLookupAttachment",
                "target_name": "CBaseModelEntity_ScriptLookupAttachment",
            },
            {
                "script_name": "ScriptSetMeshGroupMask",
                "target_name": "CBaseModelEntity_ScriptSetMeshGroupMask",
            },
        ]
        desired_fields = [
            (
                "CBaseModelEntity_ScriptLookupAttachment",
                [
                    "func_name",
                    "func_sig",
                    "func_sig_allow_across_function_boundary:true",
                    "func_va",
                    "func_rva",
                    "func_size",
                ],
            ),
            (
                "CBaseModelEntity_ScriptSetMeshGroupMask",
                ["func_name", "func_va", "func_rva", "func_size"],
            ),
        ]

        async def fake_query_func_info(_session, func_va, debug=False):
            return {"func_va": str(func_va), "func_size": "0x90"}

        async def fake_gen_func_sig_via_mcp(
            session,
            func_va,
            image_base,
            allow_across_function_boundary=False,
            debug=False,
            **_kwargs,
        ):
            self.assertEqual("0x180123450", func_va)
            self.assertTrue(allow_across_function_boundary)
            return {
                "func_va": "0x180123450",
                "func_rva": "0x123450",
                "func_size": "0x90",
                "func_sig": "48 89 5C 24 ??",
            }

        with TemporaryDirectory() as tmpdir:
            new_binary_dir = _write_source_yaml(tmpdir, "windows")
            with (
                patch.object(
                    module,
                    "_collect_script_func_entries",
                    AsyncMock(return_value=entries),
                ),
                patch.object(
                    module,
                    "_query_func_info",
                    fake_query_func_info,
                ),
                patch.object(
                    module,
                    "preprocess_gen_func_sig_via_mcp",
                    fake_gen_func_sig_via_mcp,
                ),
                patch.object(module, "write_func_yaml") as mock_write,
            ):
                result = await module.preprocess_script_desc_internal_skill(
                    session=session,
                    expected_outputs=[
                        "/tmp/CBaseModelEntity_ScriptLookupAttachment.windows.yaml",
                        "/tmp/CBaseModelEntity_ScriptSetMeshGroupMask.windows.yaml",
                    ],
                    new_binary_dir=str(new_binary_dir),
                    platform="windows",
                    image_base=0x180000000,
                    source_yaml_stem="CBaseModelEntity_GetScriptDescInternal",
                    target_specs=target_specs,
                    generate_yaml_desired_fields=desired_fields,
                    expected_script_func_count=3,
                    debug=True,
                )

        self.assertTrue(result)
        mock_write.assert_has_calls(
            [
                call(
                    "/tmp/CBaseModelEntity_ScriptLookupAttachment.windows.yaml",
                    {
                        "func_name": "CBaseModelEntity_ScriptLookupAttachment",
                        "func_sig": "48 89 5C 24 ??",
                        "func_sig_allow_across_function_boundary": True,
                        "func_va": "0x180123450",
                        "func_rva": "0x123450",
                        "func_size": "0x90",
                    },
                ),
                call(
                    "/tmp/CBaseModelEntity_ScriptSetMeshGroupMask.windows.yaml",
                    {
                        "func_name": "CBaseModelEntity_ScriptSetMeshGroupMask",
                        "func_va": "0x180456780",
                        "func_rva": "0x456780",
                        "func_size": "0x90",
                    },
                ),
            ]
        )

    async def test_preprocess_skill_rejects_duplicate_script_names(self) -> None:
        module = _import_common_module()
        session = AsyncMock()

        with TemporaryDirectory() as tmpdir:
            new_binary_dir = _write_source_yaml(tmpdir, "windows")
            with (
                patch.object(
                    module,
                    "_collect_script_func_entries",
                    AsyncMock(
                        return_value=[
                            {"script_name": "Dup", "func_va": "0x180100000"},
                            {"script_name": "Dup", "func_va": "0x180200000"},
                        ]
                    ),
                ),
                patch.object(module, "write_func_yaml") as mock_write,
            ):
                result = await module.preprocess_script_desc_internal_skill(
                    session=session,
                    expected_outputs=["/tmp/Target.windows.yaml"],
                    new_binary_dir=str(new_binary_dir),
                    platform="windows",
                    image_base=0x180000000,
                    source_yaml_stem="CBaseModelEntity_GetScriptDescInternal",
                    target_specs=[
                        {"script_name": "Dup", "target_name": "Target"},
                    ],
                    generate_yaml_desired_fields=[
                        ("Target", ["func_name", "func_va", "func_size"]),
                    ],
                    debug=True,
                )

        self.assertFalse(result)
        mock_write.assert_not_called()


class TestCBaseModelEntityRegisteredScriptFuncs(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_delegates_to_script_desc_helper(self) -> None:
        module = importlib.import_module("ida_preprocessor_scripts.find-CBaseModelEntity_RegisteredScriptFuncs")
        session = AsyncMock()

        with patch.object(
            module,
            "preprocess_script_desc_internal_skill",
            AsyncMock(return_value=True),
        ) as mock_helper:
            result = await module.preprocess_skill(
                session=session,
                skill_name="find-CBaseModelEntity_RegisteredScriptFuncs",
                expected_outputs=["/tmp/CBaseModelEntity_GetModelScale.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp/bin/server",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        self.assertFalse(hasattr(module, "LLM_DECOMPILE"))
        target_specs = mock_helper.await_args.kwargs["target_specs"]
        self.assertEqual(22, len(target_specs))
        self.assertIn(
            {
                "script_name": "ScriptLookupAttachment",
                "target_name": "CBaseModelEntity_ScriptLookupAttachment",
            },
            target_specs,
        )
        self.assertIn(
            {
                "script_name": "ScriptSetMaterialGroup",
                "target_name": "CBaseModelEntity_ScriptSetMaterialGroup",
            },
            target_specs,
        )
        self.assertIn(
            {
                "script_name": "ScriptSetSingleMeshGroup",
                "target_name": "CBaseModelEntity_ScriptSetSingleMeshGroup",
            },
            target_specs,
        )
        mock_helper.assert_awaited_once()
        self.assertEqual(
            "CBaseModelEntity_GetScriptDescInternal",
            mock_helper.await_args.kwargs["source_yaml_stem"],
        )
        self.assertEqual(22, mock_helper.await_args.kwargs["expected_script_func_count"])


class TestCBaseEntityRegisteredScriptFuncs(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_keeps_script_gravity_symbol_distinct(self) -> None:
        module = importlib.import_module("ida_preprocessor_scripts.find-CBaseEntity_RegisteredScriptFuncs")
        session = AsyncMock()

        with patch.object(
            module,
            "preprocess_script_desc_internal_skill",
            AsyncMock(return_value=True),
        ) as mock_helper:
            result = await module.preprocess_skill(
                session=session,
                skill_name="find-CBaseEntity_RegisteredScriptFuncs",
                expected_outputs=["/tmp/CBaseEntity_ScriptSetGravityScale.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp/bin/server",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        target_specs = mock_helper.await_args.kwargs["target_specs"]
        self.assertEqual(65, len(target_specs))
        self.assertIn(
            {
                "script_name": "SetGravityScale",
                "target_name": "CBaseEntity_ScriptSetGravityScale",
            },
            target_specs,
        )
        self.assertNotIn(
            {
                "script_name": "SetGravityScale",
                "target_name": "CBaseEntity_SetGravityScale",
            },
            target_specs,
        )
        self.assertEqual(65, mock_helper.await_args.kwargs["expected_script_func_count"])
