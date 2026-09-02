"""Pure GAMEVER ordering and prior-baseline selection helpers."""

from __future__ import annotations

import re
from collections.abc import Iterable


GAMEVER_RE = re.compile(r"^(?P<number>[0-9]{4,10})(?P<suffix>[a-z]?)$")


def gamever_order_key(gamever: str) -> tuple[int, int] | None:
    """Return the repository GAMEVER order key, or None for an invalid spelling."""
    match = GAMEVER_RE.fullmatch(str(gamever))
    if match is None:
        return None
    suffix = match.group("suffix")
    return int(match.group("number")), 0 if not suffix else ord(suffix) - ord("a") + 1


def select_prior_gamever(gamever: str, candidates: Iterable[str]) -> str | None:
    """Select the greatest valid candidate strictly older than ``gamever``."""
    current_key = gamever_order_key(gamever)
    if current_key is None:
        return None
    eligible = []
    for candidate in candidates:
        candidate_key = gamever_order_key(candidate)
        if candidate_key is not None and candidate_key < current_key:
            eligible.append((candidate_key, candidate))
    return max(eligible)[1] if eligible else None
