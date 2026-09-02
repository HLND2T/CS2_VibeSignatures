#!/usr/bin/env python3
"""Read-only canonical schema for prospective source-owned symbol artifacts."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

import yaml


FUNC_YAML_ORDER = (
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "func_sig_allow_across_function_boundary",
    "func_sig_resolve_jmp_thunk",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
    "vfunc_slot_size",
    "vfunc_sig",
    "vfunc_sig_disp",
    "vfunc_sig_max_match",
    "vfunc_sig_allow_across_function_boundary",
)
GV_YAML_ORDER = (
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary",
)
VTABLE_YAML_ORDER = (
    "vtable_class",
    "vtable_symbol",
    "vtable_va",
    "vtable_rva",
    "vtable_size",
    "vtable_numvfunc",
    "pointer_size",
    "vtable_entries",
)
PATCH_YAML_ORDER = (
    "patch_name",
    "patch_va",
    "patch_rva",
    "patch_sig",
    "patch_sig_disp",
    "patch_bytes",
)
STRUCT_MEMBER_YAML_ORDER = (
    "struct_name",
    "member_name",
    "offset",
    "size",
    "offset_sig",
    "offset_sig_disp",
    "offset_sig_max_match",
    "offset_sig_allow_across_function_boundary",
)
SYMBOL_ARTIFACT_CATEGORIES = frozenset({"func", "gv", "vfunc", "vtable", "patch", "structmember"})
SYMBOL_ARTIFACT_CATEGORY_ALIASES = {"struct": "structmember", "struct_member": "structmember"}
SYMBOL_ARTIFACT_IDENTITY_FIELDS = {
    "func": ("func_name",),
    "vfunc": ("func_name", "vtable_name"),
    "gv": ("gv_name",),
    "patch": ("patch_name",),
    "vtable": ("vtable_class",),
    "structmember": ("struct_name", "member_name"),
}
SYMBOL_ARTIFACT_FIELD_ORDER = {
    "func": FUNC_YAML_ORDER[:7],
    "vfunc": FUNC_YAML_ORDER,
    "gv": GV_YAML_ORDER,
    "vtable": VTABLE_YAML_ORDER,
    "patch": PATCH_YAML_ORDER,
    "structmember": STRUCT_MEMBER_YAML_ORDER,
}
SYMBOL_ARTIFACT_HEX_FIELDS = frozenset(
    {
        "func_va",
        "func_rva",
        "func_size",
        "gv_va",
        "gv_rva",
        "gv_sig_va",
        "vtable_va",
        "vtable_rva",
        "vtable_size",
        "patch_va",
        "patch_rva",
        "vfunc_offset",
        "offset",
    }
)
SYMBOL_ARTIFACT_INTEGER_FIELDS = frozenset(
    {
        "gv_inst_offset",
        "gv_inst_length",
        "gv_inst_disp",
        "vfunc_index",
        "vfunc_slot_size",
        "vfunc_sig_disp",
        "vfunc_sig_max_match",
        "vtable_numvfunc",
        "pointer_size",
        "patch_sig_disp",
        "size",
        "offset_sig_disp",
        "offset_sig_max_match",
    }
)
SYMBOL_ARTIFACT_BOOLEAN_FIELDS = frozenset(
    {
        "func_sig_allow_across_function_boundary",
        "func_sig_resolve_jmp_thunk",
        "vfunc_sig_allow_across_function_boundary",
        "gv_sig_allow_across_function_boundary",
        "offset_sig_allow_across_function_boundary",
    }
)
SYMBOL_SIGNATURE_RE = re.compile(r"^(?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?))*$")


class SymbolArtifactError(ValueError):
    """A source-owned symbol artifact violates the canonical schema."""


class _SymbolArtifactDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _artifact_int(value, field, *, nonnegative=False):
    if isinstance(value, bool):
        raise SymbolArtifactError(f"{field} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value.strip(), 0)
        except ValueError as exc:
            raise SymbolArtifactError(f"{field} must be an integer") from exc
    else:
        raise SymbolArtifactError(f"{field} must be an integer")
    if nonnegative and parsed < 0:
        raise SymbolArtifactError(f"{field} must be non-negative")
    return parsed


def _artifact_hex(value, field):
    return f"0x{_artifact_int(value, field, nonnegative=True):x}"


def normalize_symbol_signature(value):
    if isinstance(value, bytes):
        tokens = [f"{byte:02X}" for byte in value]
    elif isinstance(value, str):
        raw = value.strip().replace("\\x", " ").replace(",", " ").replace("*", "?")
        tokens = []
        for token in raw.split():
            token = token.upper()
            if token in {"?", "??"} or "?" in token:
                tokens.append("??")
            elif re.fullmatch(r"[0-9A-F]{2}", token):
                tokens.append(token)
            else:
                raise SymbolArtifactError(f"invalid signature token: {token!r}")
    elif isinstance(value, Iterable):
        tokens = []
        for byte in value:
            if byte is None:
                tokens.append("??")
            elif isinstance(byte, bool) or not isinstance(byte, int) or not 0 <= byte <= 0xFF:
                raise SymbolArtifactError(f"invalid signature byte: {byte!r}")
            else:
                tokens.append(f"{byte:02X}")
    else:
        raise SymbolArtifactError("signature must be text, bytes, or an iterable of bytes")
    signature = " ".join(tokens)
    if not signature or not SYMBOL_SIGNATURE_RE.fullmatch(signature):
        raise SymbolArtifactError(f"invalid signature: {value!r}")
    return signature


def _normalize_symbol_category(category):
    normalized = str(category or "").strip().lower()
    normalized = SYMBOL_ARTIFACT_CATEGORY_ALIASES.get(normalized, normalized)
    if normalized not in SYMBOL_ARTIFACT_CATEGORIES:
        raise SymbolArtifactError(f"unsupported symbol artifact category: {category!r}")
    return normalized


def infer_symbol_artifact_category(payload):
    if not isinstance(payload, Mapping):
        raise SymbolArtifactError("symbol artifact must be a mapping")
    candidates = set()
    if "func_name" in payload:
        candidates.add(
            "vfunc" if "vtable_name" in payload or any(key.startswith("vfunc_") for key in payload) else "func"
        )
    if "gv_name" in payload:
        candidates.add("gv")
    if "patch_name" in payload:
        candidates.add("patch")
    if "vtable_class" in payload:
        candidates.add("vtable")
    if "struct_name" in payload or "member_name" in payload:
        candidates.add("structmember")
    if len(candidates) != 1:
        raise SymbolArtifactError(f"unable to infer one symbol artifact category: {sorted(candidates)!r}")
    return candidates.pop()


def _normalize_vtable_entries(value):
    if not isinstance(value, Mapping):
        raise SymbolArtifactError("vtable_entries must be a mapping")
    entries = {}
    for raw_index, raw_address in value.items():
        index = _artifact_int(raw_index, "vtable entry index", nonnegative=True)
        if index in entries:
            raise SymbolArtifactError(f"duplicate vtable entry index: {index}")
        entries[index] = _artifact_hex(raw_address, f"vtable_entries[{index}]")
    return dict(sorted(entries.items()))


def normalize_symbol_artifact(payload, *, category=None):
    if not isinstance(payload, Mapping):
        raise SymbolArtifactError("symbol artifact must be a mapping")
    category = _normalize_symbol_category(category or infer_symbol_artifact_category(payload))
    allowed_fields = set(SYMBOL_ARTIFACT_FIELD_ORDER[category])
    unknown_fields = set(payload) - allowed_fields
    if unknown_fields:
        raise SymbolArtifactError(
            f"{category} artifact has unknown fields: {', '.join(sorted(map(str, unknown_fields)))}"
        )
    normalized = {}
    for field in SYMBOL_ARTIFACT_FIELD_ORDER[category]:
        if field not in payload:
            continue
        value = payload[field]
        if field in SYMBOL_ARTIFACT_IDENTITY_FIELDS[category] or field == "vtable_symbol":
            if not isinstance(value, str) or not value.strip():
                raise SymbolArtifactError(f"{category} artifact requires non-empty {field}")
            value = value.strip()
        elif field.endswith("_sig") or field == "patch_bytes":
            value = normalize_symbol_signature(value)
            if field == "patch_bytes" and "??" in value.split():
                raise SymbolArtifactError("patch_bytes must not contain wildcard bytes")
        elif field in SYMBOL_ARTIFACT_HEX_FIELDS:
            value = _artifact_hex(value, field)
        elif field in SYMBOL_ARTIFACT_INTEGER_FIELDS:
            value = _artifact_int(
                value,
                field,
                nonnegative=field not in {"gv_inst_disp", "patch_sig_disp", "offset_sig_disp", "vfunc_sig_disp"},
            )
        elif field in SYMBOL_ARTIFACT_BOOLEAN_FIELDS:
            if not isinstance(value, bool):
                raise SymbolArtifactError(f"{field} must be a boolean")
        elif field == "vtable_entries":
            value = _normalize_vtable_entries(value)
        normalized[field] = value

    for identity_field in SYMBOL_ARTIFACT_IDENTITY_FIELDS[category]:
        if identity_field not in normalized:
            raise SymbolArtifactError(f"{category} artifact requires non-empty {identity_field}")
    if category == "vfunc":
        slot_size = normalized.get("vfunc_slot_size", 8)
        if slot_size != 8:
            raise SymbolArtifactError("Source2 x64 vfunc slots are exactly 8 bytes")
        if "vfunc_offset" in normalized:
            offset = int(normalized["vfunc_offset"], 0)
            if offset % slot_size:
                raise SymbolArtifactError("Source2 x64 vfunc_offset must be 8-byte aligned")
            if "vfunc_index" in normalized and normalized["vfunc_index"] != offset // slot_size:
                raise SymbolArtifactError("vfunc_index does not match vfunc_offset / 8")
    if category == "vtable":
        pointer_size = normalized.get("pointer_size", 8)
        if pointer_size != 8:
            raise SymbolArtifactError("Source2 x64 vtable pointers are exactly 8 bytes")
        entries = normalized.get("vtable_entries")
        count = normalized.get("vtable_numvfunc")
        if entries is not None and count is not None:
            if tuple(entries) != tuple(range(count)):
                raise SymbolArtifactError("vtable_entries must contain every index from 0 to vtable_numvfunc - 1")
            if "vtable_size" in normalized and int(normalized["vtable_size"], 0) != count * pointer_size:
                raise SymbolArtifactError("vtable_size does not match vtable_numvfunc * 8")
    return normalized


def canonical_symbol_yaml_bytes(payload, *, category=None):
    normalized = normalize_symbol_artifact(payload, category=category)
    text = yaml.dump(
        normalized,
        Dumper=_SymbolArtifactDumper,
        allow_unicode=True,
        default_flow_style=False,
        explicit_end=False,
        explicit_start=False,
        indent=2,
        line_break="\n",
        sort_keys=False,
        width=120,
    )
    return text.rstrip("\r\n").encode("utf-8") + b"\n"
