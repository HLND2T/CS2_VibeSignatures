"""Accept anchor-only drift between a rebuilt artifact and the committed blob.

An `LLM_DECOMPILE` producer asks the model to pick one reference instruction and
then expands a deterministic signature from it, so the fields that describe *how*
a symbol was located legitimately vary between two equally rule-conformant runs.
The resolved facts stay authoritative: a payload may differ only inside its
anchor group, and only while the symbol identity, the resolved address/offset and
the anchor shape are unchanged.

`func`, `vtable` and `patch` carry no anchor group on purpose. Their signatures
are anchored at the resolved address itself (or, for a `patch` without
`patch_va`, *are* the only truth), so any difference there is a different symbol
rather than a different sampling of the same one. Search-policy switches
(`*_max_match`, `*_allow_across_function_boundary`) are excluded for the same
reason: tolerating them would accept a different search.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

import yaml

from ida_analyze_util import SymbolArtifactError, infer_symbol_artifact_category


@dataclass(frozen=True)
class AnchorSpec:
    """How one artifact category describes the symbol it locates.

    ``require_keys`` must all be present for the spec to apply, so a payload whose
    signature is its only truth never reaches the tolerant path. ``fixed_keys``
    are the resolved facts a rebuilt payload has to reproduce byte-exactly, and
    ``anchor_fields`` is the only set allowed to drift. ``hex_fields`` hold
    canonical ``'0x...'`` text while ``integer_fields`` hold plain integers; both
    must carry a valid non-negative offset when present, because normalization
    alone still permits an explicit null. ``coherent`` carries the cross-field
    invariants that symbol normalization does not already enforce.
    """

    require_keys: tuple[str, ...]
    fixed_keys: tuple[str, ...]
    anchor_fields: frozenset[str]
    hex_fields: tuple[str, ...] = ()
    integer_fields: tuple[str, ...] = ()
    coherent: Callable[[dict], bool] | None = None


def _payload(raw: bytes) -> dict | None:
    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        return None
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        return None
    return document


def _hex_offset(value) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _integer_offset(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def gv_anchor_is_coherent(payload: dict) -> bool:
    """Check that one payload still describes a well-formed anchored global.

    Relocation reads ``gv_inst_length`` bytes at ``gv_sig_va + gv_inst_offset``
    and decodes a 4-byte RIP-relative displacement at ``gv_inst_disp``, so the
    displacement field has to stay inside the anchored instruction.
    """
    offset = _integer_offset(payload.get("gv_inst_offset"))
    length = _integer_offset(payload.get("gv_inst_length"))
    if offset is None or not length:
        return False
    if _hex_offset(payload.get("gv_sig_va")) is None:
        return False
    signature = payload.get("gv_sig")
    if not isinstance(signature, str) or not signature.strip():
        return False
    disp_raw = payload.get("gv_inst_disp")
    if disp_raw is None:
        return True
    disp = _integer_offset(disp_raw)
    return disp is not None and disp + 4 <= length


# Every field a spec does not list keeps the byte-exact gate, which is how the
# policy switches and each category's resolved facts stay pinned.
ANCHOR_SPECS: dict[str, AnchorSpec] = {
    "gv": AnchorSpec(
        require_keys=("gv_name", "gv_va", "gv_rva"),
        fixed_keys=("gv_name", "gv_va", "gv_rva"),
        anchor_fields=frozenset(
            {
                "gv_sig",
                "gv_sig_va",
                "gv_inst_offset",
                "gv_inst_length",
                "gv_inst_disp",
            }
        ),
        hex_fields=("gv_sig_va",),
        integer_fields=("gv_inst_offset", "gv_inst_length", "gv_inst_disp"),
        coherent=gv_anchor_is_coherent,
    ),
    "vfunc": AnchorSpec(
        # A slot-only vfunc has no func_va, so the vtable slot is the resolved
        # fact that pins it.
        require_keys=("func_name", "vtable_name", "vfunc_offset", "vfunc_index"),
        fixed_keys=(
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
            "vfunc_slot_size",
        ),
        anchor_fields=frozenset({"vfunc_sig", "vfunc_sig_disp"}),
        integer_fields=("vfunc_sig_disp",),
    ),
    "structmember": AnchorSpec(
        require_keys=("struct_name", "member_name", "offset"),
        fixed_keys=("struct_name", "member_name", "offset", "size"),
        anchor_fields=frozenset({"offset_sig", "offset_sig_disp"}),
        integer_fields=("offset_sig_disp",),
    ),
}


def _spec_for(payload: dict) -> AnchorSpec | None:
    try:
        category = infer_symbol_artifact_category(payload)
    except SymbolArtifactError:
        return None
    spec = ANCHOR_SPECS.get(category)
    if spec is None or not all(key in payload for key in spec.require_keys):
        return None
    return spec


def anchor_only_drift(expected_raw: bytes, actual_raw: bytes) -> dict | None:
    """Return the changed anchor fields when two payloads differ only there."""
    expected = _payload(expected_raw)
    actual = _payload(actual_raw)
    if expected is None or actual is None or set(expected) != set(actual):
        return None
    # Both sides share one key set, and category inference plus require_keys read
    # only key presence, so one lookup decides the spec for both payloads.
    spec = _spec_for(expected)
    if spec is None:
        return None
    changed = {key for key in expected if expected[key] != actual[key]}
    if not changed or not changed <= spec.anchor_fields:
        return None
    if any(expected.get(key) != actual.get(key) for key in spec.fixed_keys):
        return None
    # An omitted optional field may use a default; an explicit null is not a
    # usable offset. Check unchanged fields and both sides of the comparison too.
    for payload in (expected, actual):
        for parse, fields in ((_hex_offset, spec.hex_fields), (_integer_offset, spec.integer_fields)):
            if any(key in payload and parse(payload[key]) is None for key in fields):
                return None
    if spec.coherent is not None and not spec.coherent(actual):
        return None
    return {key: (expected[key], actual[key]) for key in sorted(changed)}


def accepted_anchor_drift(
    expected: Mapping[str, tuple[int, str]],
    actual: Mapping[str, tuple[int, str]],
    *,
    read_expected: Callable[[str], bytes | None],
    read_actual: Callable[[str], bytes | None],
) -> dict[str, dict] | None:
    """Map every drifting artifact to its changed anchor fields, or fail closed.

    ``expected`` and ``actual`` map an artifact key to its ``(size, sha256)``
    fingerprint. Missing, extra and non-anchor payload changes keep the
    byte-exact gate: any of them makes the whole comparison return ``None``.
    """
    if expected.keys() != actual.keys():
        return None
    drift: dict[str, dict] = {}
    for key, expected_fingerprint in expected.items():
        if expected_fingerprint == actual[key]:
            continue
        expected_raw = read_expected(key)
        actual_raw = read_actual(key)
        if expected_raw is None or actual_raw is None:
            return None
        changed = anchor_only_drift(expected_raw, actual_raw)
        if changed is None:
            return None
        drift[key] = changed
    return drift or None


def format_anchor_drift(changes: Mapping[str, tuple[object, object]]) -> str:
    """Render one artifact's accepted anchor drift for a CI log line."""
    return ", ".join(f"{field} {before} -> {after}" for field, (before, after) in changes.items())
