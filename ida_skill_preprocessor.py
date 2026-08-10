#!/usr/bin/env python3
"""
IDA Skill Preprocessor for CS2_VibeSignatures.

This module is a lightweight MCP entrypoint. It opens an MCP session,
resolves the skill-specific preprocessor script under ida_preprocessor_scripts,
and delegates preprocessing to the script's exported method.
"""

import importlib.util
import inspect
import re
import sys
import traceback
from pathlib import Path

from ida_analyze_util import parse_mcp_result
from ida_mcp_session import open_ida_mcp_session


_SCRIPT_DIR = Path(__file__).resolve().parent / "ida_preprocessor_scripts"
_PREPROCESS_EXPORT_NAME = "preprocess_skill"
_SCRIPT_ENTRY_CACHE = {}


class PreprocessStatus(str):
    def __new__(cls, value, truthy):
        obj = super().__new__(cls, value)
        obj._truthy = bool(truthy)
        return obj

    def __bool__(self):
        return self._truthy


PREPROCESS_STATUS_SUCCESS = PreprocessStatus("success", True)
PREPROCESS_STATUS_FAILED = PreprocessStatus("failed", False)
PREPROCESS_STATUS_ABSENT_OK = PreprocessStatus("absent_ok", True)
PREPROCESS_STATUS_NO_SCRIPT = PreprocessStatus("no_script", False)


def report_preprocess_exception(skill_name, phase, exc, debug=False):
    exception_type = type(exc).__name__
    exception_message = str(exc)
    exception_details = f"{exception_type}: {exception_message}" if exception_message else exception_type
    print(f"    Preprocess error [{phase}] for {skill_name}: {exception_details}")
    if debug:
        traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stdout)


def _normalize_preprocess_status(result):
    if result is True or result == PREPROCESS_STATUS_SUCCESS:
        return PREPROCESS_STATUS_SUCCESS
    if result == PREPROCESS_STATUS_ABSENT_OK:
        return PREPROCESS_STATUS_ABSENT_OK
    if result == PREPROCESS_STATUS_NO_SCRIPT:
        return PREPROCESS_STATUS_NO_SCRIPT
    return PREPROCESS_STATUS_FAILED


def _get_preprocess_entry(skill_name, debug=False):
    """Load and cache `preprocess_skill` from ida_preprocessor_scripts/{skill_name}.py."""
    if skill_name in _SCRIPT_ENTRY_CACHE:
        return _SCRIPT_ENTRY_CACHE[skill_name]

    script_path = _SCRIPT_DIR / f"{skill_name}.py"
    if not script_path.exists():
        if debug:
            print(f"    Preprocess: no script for skill {skill_name}: {script_path}")
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    module_name = "ida_preprocessor_script_" + re.sub(r"[^0-9a-zA-Z_]", "_", skill_name)
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        if debug:
            print(f"    Preprocess: failed to load module spec for {script_path}")
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        report_preprocess_exception(skill_name, "script import", e, debug=debug)
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    preprocess_func = getattr(module, _PREPROCESS_EXPORT_NAME, None)
    if not callable(preprocess_func):
        if debug:
            print(f"    Preprocess: script {script_path} does not export callable {_PREPROCESS_EXPORT_NAME}")
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    _SCRIPT_ENTRY_CACHE[skill_name] = preprocess_func
    return preprocess_func


async def preprocess_single_skill_via_mcp(
    host,
    port,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    expected_inputs=None,
    optional_inputs=None,
    expected_binary=None,
    explicit_database=None,
    llm_model=None,
    llm_apikey=None,
    llm_baseurl=None,
    llm_temperature=None,
    llm_effort=None,
    llm_fake_as=None,
    llm_max_retries=None,
    symbol_aliases=None,
    debug=False,
):
    """
    Attempt to pre-process a single skill via IDA MCP and skill script dispatch.

    Dispatch flow:
      ida_analyze_bin.py -> preprocess_single_skill_via_mcp ->
      ida_preprocessor_scripts/{skill_name}.py::preprocess_skill

    Args:
        host: MCP server host
        port: MCP server port
        skill_name: name of the skill to preprocess
        expected_outputs: list of expected output YAML paths
        expected_inputs: resolved expected input YAML paths declared by the skill
        optional_inputs: resolved optional input YAML paths declared by the skill
        old_yaml_map: dict mapping new_yaml_path -> old_yaml_path
        new_binary_dir: directory for new version YAML outputs
        platform: "windows" or "linux"
        llm_model: optional OpenAI-compatible model name for scripts that support LLM
        llm_apikey: optional OpenAI-compatible API key for scripts that support LLM
        llm_baseurl: optional OpenAI-compatible base URL for scripts that support LLM
        llm_temperature: optional OpenAI-compatible temperature for scripts that support LLM
        llm_effort: optional OpenAI-compatible reasoning effort for scripts that support LLM
        llm_fake_as: optional OpenAI-compatible fake_as for scripts that support LLM
        llm_max_retries: optional maximum total attempts for LLM decompile calls
        debug: enable debug output

    Returns:
        One of: "success", "absent_ok", "no_script", or "failed"
    """
    script_path = _SCRIPT_DIR / f"{skill_name}.py"
    if not script_path.exists():
        if debug:
            print(f"    Preprocess: no script for skill {skill_name}: {script_path}")
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return PREPROCESS_STATUS_NO_SCRIPT

    preprocess_func = _get_preprocess_entry(skill_name, debug=debug)
    if preprocess_func is None:
        return PREPROCESS_STATUS_FAILED

    try:
        session_kwargs = {}
        if expected_binary is not None:
            session_kwargs["expected_binary"] = expected_binary
        if explicit_database is not None:
            session_kwargs["explicit_database"] = explicit_database
        async with open_ida_mcp_session(host, port, **session_kwargs) as session:
            ib_result = await session.call_tool(name="py_eval", arguments={"code": "hex(idaapi.get_imagebase())"})
            ib_data = parse_mcp_result(ib_result)
            if isinstance(ib_data, dict):
                image_base = int(ib_data.get("result", "0x0"), 16)
            else:
                image_base = int(str(ib_data), 16) if ib_data else 0

            try:
                llm_config = {
                    "model": llm_model,
                    "api_key": llm_apikey,
                    "base_url": llm_baseurl,
                    "temperature": llm_temperature,
                    "effort": llm_effort,
                    "fake_as": llm_fake_as,
                }
                if symbol_aliases:
                    llm_config["symbol_aliases"] = symbol_aliases
                if llm_max_retries is not None:
                    llm_config["max_retries"] = llm_max_retries
                llm_config["_expected_inputs"] = list(expected_inputs or [])
                llm_config["_optional_inputs"] = list(optional_inputs or [])
                preprocess_kwargs = {
                    "session": session,
                    "skill_name": skill_name,
                    "expected_outputs": expected_outputs,
                    "old_yaml_map": old_yaml_map,
                    "new_binary_dir": new_binary_dir,
                    "platform": platform,
                    "image_base": image_base,
                    "debug": debug,
                }
                if "llm_config" in inspect.signature(preprocess_func).parameters:
                    preprocess_kwargs["llm_config"] = llm_config

                result = preprocess_func(**preprocess_kwargs)
                if inspect.isawaitable(result):
                    result = await result
                return _normalize_preprocess_status(result)
            except Exception as e:
                report_preprocess_exception(skill_name, "script execution", e, debug=debug)
                return PREPROCESS_STATUS_FAILED

    except Exception as e:
        report_preprocess_exception(skill_name, "MCP session", e, debug=debug)

    return PREPROCESS_STATUS_FAILED
