"""ConVar-family binding of the shared bounded LLM helper-chain walk.

The walk itself lives in ``_llm_helper_chain_common``; this module only supplies
the ConVar export label so both target families share one implementation.
"""

from ida_preprocessor_scripts._llm_helper_chain_common import make_helper_loader
from ida_preprocessor_scripts._llm_helper_chain_common import preprocess_call_chain as _preprocess_call_chain

load_helper_details = make_helper_loader("ConVar_helper")


async def preprocess_call_chain(**kwargs):
    """Try the predecessor body before following direct calls and tail jumps."""
    return await _preprocess_call_chain(helper_loader=load_helper_details, **kwargs)


__all__ = ["load_helper_details", "preprocess_call_chain"]
