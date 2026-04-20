import importlib
import json
import types
import unittest
from unittest.mock import patch


def _import_slot_dispatch_module():
    return importlib.import_module(
        "ida_preprocessor_scripts._igamesystem_slot_dispatch_common"
    )


def _slot_op(kind: int, *, addr: int = -1, reg: int | None = None) -> dict[str, object]:
    return {"type": kind, "addr": addr, "reg": reg}


class _FakeFunc:
    def __init__(self, start_ea: int, end_ea: int) -> None:
        self.start_ea = start_ea
        self.end_ea = end_ea


class _FakeInsn:
    def __init__(self) -> None:
        self.ops = [types.SimpleNamespace(type=0, addr=-1, reg=None) for _ in range(2)]


def _run_slot_dispatch_py_eval(
    *,
    source_func_va: int,
    platform: str,
    funcs: dict[int, tuple[int, int]],
    instructions: dict[int, dict[str, object]],
) -> dict[str, object]:
    module = _import_slot_dispatch_module()
    code = module._build_slot_dispatch_py_eval(
        source_func_va=hex(source_func_va),
        platform=platform,
    )
    heads = sorted(instructions)

    def fake_decode_insn(insn: _FakeInsn, ea: int) -> bool:
        spec = instructions.get(ea)
        if spec is None:
            return False
        insn.ops = [types.SimpleNamespace(**op) for op in spec.get("ops", [])]
        return True

    fake_idaapi = types.SimpleNamespace(
        o_reg=1,
        o_displ=2,
        o_phrase=3,
        BADADDR=-1,
        get_func=lambda ea: _FakeFunc(*funcs[ea]) if ea in funcs else None,
        add_func=lambda _ea: None,
        insn_t=_FakeInsn,
        decode_insn=fake_decode_insn,
    )
    fake_idautils = types.SimpleNamespace(
        Heads=lambda start, end: [ea for ea in heads if start <= ea < end]
    )
    fake_idc = types.SimpleNamespace(
        print_insn_mnem=lambda ea: instructions.get(ea, {}).get("mnem", ""),
        get_operand_value=lambda ea, index: instructions.get(ea, {}).get(
            "operand_values", (0, 0)
        )[index],
        prev_head=lambda ea, minimum: next(
            (head for head in reversed(heads) if minimum <= head < ea),
            -1,
        ),
    )
    namespace: dict[str, object] = {}
    with patch.dict(
        "sys.modules",
        {"idaapi": fake_idaapi, "idautils": fake_idautils, "idc": fake_idc},
    ):
        exec(code, namespace)
    return json.loads(namespace["result"])


class TestBuildIgameSystemSlotDispatchPyEvalBehavior(unittest.TestCase):
    def test_windows_skips_wrapper_over_max_instructions(self) -> None:
        payload = _run_slot_dispatch_py_eval(
            source_func_va=0x1805000C0,
            platform="windows",
            funcs={
                0x1805000C0: (0x1805000C0, 0x1805000D0),
                0x180500200: (0x180500200, 0x180500209),
            },
            instructions={
                0x1805000C4: {
                    "mnem": "call",
                    "operand_values": (0x180500200, 0),
                    "ops": [_slot_op(0), _slot_op(0)],
                },
                **{
                    0x180500200 + i: {
                        "mnem": "call" if i == 0 else "mov",
                        "operand_values": (0, 0),
                        "ops": [_slot_op(2, addr=0x28, reg=1), _slot_op(0)],
                    }
                    for i in range(9)
                },
            },
        )

        self.assertEqual({"entries": []}, payload)

    def test_linux_skips_call_when_prev_mov_reg_mismatches(self) -> None:
        payload = _run_slot_dispatch_py_eval(
            source_func_va=0xDD4720,
            platform="linux",
            funcs={0xDD4720: (0xDD4720, 0xDD4730)},
            instructions={
                0xDD4720: {
                    "mnem": "mov",
                    "operand_values": (0, 0),
                    "ops": [_slot_op(1, reg=2), _slot_op(3, reg=3)],
                },
                0xDD4724: {
                    "mnem": "call",
                    "operand_values": (0, 0),
                    "ops": [_slot_op(2, addr=0x28, reg=1), _slot_op(0)],
                },
            },
        )

        self.assertEqual({"entries": []}, payload)
