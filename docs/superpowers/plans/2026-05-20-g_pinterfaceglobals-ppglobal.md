# g_pInterfaceGlobals ppGlobal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `find-g_pInterfaceGlobals_ppGlobal` to derive all expected `g_pXXXX` global-variable pointer YAML files from the `g_pInterfaceGlobals` table.

**Architecture:** Add one focused custom preprocessor script that reads `g_pInterfaceGlobals.{platform}.yaml`, scans IDA entries as `(interface_name_ptr, pp_global_ptr)` pairs, strictly validates expected interface-name coverage against the shared expected list without depending on order, then writes minimal `gv_name/gv_va/gv_rva` YAML for each expected pointer. Register the skill after the existing `find-g_pInterfaceGlobals` step for `client`, `server`, and the post-client `engine` skill chain, and register the produced GV symbols in the modules that own symbols.

**Tech Stack:** Python 3, IDA MCP `py_eval`, PyYAML, `unittest`, `unittest.mock`, `config.yaml`

---

## File Map

- Create: `ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py`
  - Responsibility: strict table scan, expected-interface coverage validation, minimal GV YAML emission, optional best-effort IDB rename.
- Modify: `tests/test_ida_preprocessor_scripts.py`
  - Responsibility: cover the custom script without IDA by mocking MCP `py_eval` and YAML writer behavior.
- Modify: `config.yaml`
  - Responsibility: register the new skill and all generated GV symbols for `client`, `server`, and `engine`.
- Reference: `ida_preprocessor_scripts/find-g_pInterfaceGlobals.py`
  - Responsibility: existing prerequisite script that generates `g_pInterfaceGlobals.{platform}.yaml`.
- Reference: `ida_analyze_util.py`
  - Responsibility: reuse `parse_mcp_result` and `write_gv_yaml`.
- Reference: `docs/superpowers/specs/2026-05-20-g_pinterfaceglobals-ppglobal-design.md`
  - Responsibility: accepted design and strict behavior contract.

## Repository Constraints

- Do not depend on `pp_global_ptr` having an IDA name.
- Do not use per-module expected lists; `client`, `server`, and `engine` all use the same platform-specific expected sequence.
- Windows `.dll` includes `("NavSystem001", "g_pNavSystem")` and `("NavGameTest001", "g_pNavGameTest")`; current Linux `.so` ends at `("Vrad3_001", "g_pRAD3")` for required outputs.
- Do not run test or build commands unless explicitly requested by the user. Static import/YAML parse checks are allowed as targeted verification.
- Do not create commits unless the user explicitly confirms git history operations.
- The duplicate `engine` module near the end of `config.yaml` contains the existing `find-g_pInterfaceGlobals` skill and should receive the new follow-up skill. The primary `engine` module contains the `symbols` list and should receive the new GV symbols.

## Shared Expected Entries

Use this exact ordered list as the Windows list in the new script. Derive the Linux list with `EXPECTED_ENTRIES[:-1]`.

```python
EXPECTED_ENTRIES = [
    ("VApplication001", "g_pVApplication"),
    ("VEngineCvar007", "g_pVEngineCvar"),
    ("VStringTokenSystem001", "g_pVStringTokenSystem"),
    ("TestScriptMgr001", "g_pTestScriptMgr"),
    ("VProcessUtils002", "g_pProcessUtils"),
    ("VFileSystem017", "g_pFileSystem"),
    ("VAsyncFileSystem2_001", "g_pAsyncFileSystem"),
    ("ResourceSystem013", "g_pResourceSystem"),
    ("ResourceManifestRegistry001", "g_pResourceManifestRegistry"),
    ("ResourceHandleUtils001", "g_pResourceHandleUtils"),
    ("SchemaSystem_001", "g_pSchemaSystem"),
    ("ResourceCompilerSystem001", "g_pResourceCompilerSystem"),
    ("VMaterialSystem2_001", "g_pMaterialSystem2"),
    ("PostProcessingSystem_001", "g_pPostProcessingSystem"),
    ("InputSystemVersion001", "g_pInputSystem"),
    ("InputStackSystemVersion001", "g_pInputStackSystem"),
    ("RenderDeviceMgr001", "g_pRenderDeviceMgr"),
    ("RenderUtils_001", "g_pRenderUtils"),
    ("SoundSystem001", "g_pSoundSystem"),
    ("SoundOpSystemEdit001", "g_pSoundOpSystemEdit"),
    ("SoundOpSystem001", "g_pSoundOpSystem"),
    ("SteamAudio001", "g_pSteamAudio"),
    ("VP4003", "g_pVP4"),
    ("Localize_001", "g_pLocalize"),
    ("VMediaFoundation001", "g_pMediaFoundation"),
    ("VAvi001", "g_pAVI"),
    ("VWebm001", "g_pWEBM"),
    ("VBik001", "g_pBIK"),
    ("MeshSystem001", "g_pMeshSystem"),
    ("MeshUtils001", "g_pMeshUtils"),
    ("RenderDevice003", "g_pRenderDevice"),
    ("VRenderDeviceSetupV001", "g_pRenderDeviceSetup"),
    ("RenderHardwareConfig002", "g_pRenderHardwareConfig"),
    ("SceneSystem_002", "g_pSceneSystem"),
    ("IPulseSystem_001", "g_pIPulseSystem"),
    ("SceneUtils_001", "g_pSceneUtils"),
    ("WorldRendererMgr001", "g_pWorldRendererMgr"),
    ("AssetSystem001", "g_pAssetSystem"),
    ("AssetSystemTest001", "g_pAssetSystemTest"),
    ("ParticleSystemMgr003", "g_pParticleSystemMgr"),
    ("VScriptManager010", "g_pScriptManager"),
    ("PropertyEditorSystem_001", "g_pPropertyEditorSystem"),
    ("MATCHFRAMEWORK_001", "g_pMatchFramework"),
    ("Source2V8System001", "g_pSource2V8System"),
    ("PanoramaUIEngine001", "g_pPanoramaUIEngine"),
    ("PanoramaUIClient001", "g_pPanoramaUIClient"),
    ("PanoramaTextServices001", "g_pPanoramaTextServices"),
    ("ToolFramework2_002", "g_pToolFramework2"),
    ("PhysicsBuilderMgr001", "g_pPhysicsBuilderMgr"),
    ("VisBuilder_001", "g_pVisBuilder"),
    ("BakedLODBuilderMgr001", "g_pBakedLODBuilderMgr"),
    ("HelpSystem_001", "g_pHelpSystem"),
    ("ToolSceneNodeFactory_001", "g_pToolSceneNodeFactory"),
    ("EconItemToolModel_001", "g_pEconItemToolModel"),
    ("SchemaTestExternal_Two_001", "g_pSchemaTestExternalTwo"),
    ("SchemaTestExternal_One_001", "g_pSchemaTestExternalOne"),
    ("AnimationSystem_001", "g_pAnimationSystem"),
    ("AnimationSystemUtils_001", "g_pAnimationSystemUtils"),
    ("HammerMapLoader001", "g_pHammerMapLoader"),
    ("MaterialUtils_001", "g_pMaterialUtils"),
    ("FontManager_001", "g_pFontManager"),
    ("TextLayout_001", "g_pTextLayout"),
    ("AssetPreviewSystem_001", "g_pAssetPreviewSystem"),
    ("AssetBrowserSystem_001", "g_pAssetBrowserSystem"),
    ("AssetRenameSystem_001", "g_pAssetRenameSystem"),
    ("VConComm001", "g_pVConComm"),
    ("MODEL_PROCESSING_SERVICES_INTERFACE_001", "g_pModelProcessingServices"),
    ("NetworkSystemVersion001", "g_pNetworkSystem"),
    ("NetworkMessagesVersion001", "g_pNetworkMessages"),
    ("FlattenedSerializersVersion001", "g_pFlattenedSerializers"),
    ("SerializedEntitiesVersion001", "g_pSerializedEntities"),
    ("DemoUpconverterVersion001", "g_pDemoUpconverter"),
    ("Source2Client002", "g_pSource2Client"),
    ("Source2ClientUI001", "g_pSource2ClientUI"),
    ("Source2ClientPrediction001", "g_pSource2ClientPrediction"),
    ("Source2Server001", "g_pSource2Server"),
    ("Source2Host001", "g_pSource2Host"),
    ("Source2ModTools001", "g_pSource2ModTools"),
    ("Source2GameClients001", "g_pSource2GameClients"),
    ("Source2GameEntities001", "g_pSource2GameEntities"),
    ("EngineServiceMgr001", "g_pEngineServiceMgr"),
    ("HostStateMgr001", "g_pHostStateMgr"),
    ("NetworkService_001", "g_pNetworkService"),
    ("NetworkClientService_001", "g_pNetworkClientService"),
    ("NetworkP2PService_001", "g_pNetworkP2PService"),
    ("NetworkServerService_001", "g_pNetworkServerService"),
    ("ToolService_001", "g_pToolService"),
    ("RenderService_001", "g_pRenderService"),
    ("StatsService_001", "g_pStatsService"),
    ("VProfService_001", "g_pVProfService"),
    ("InputService_001", "g_pInputService"),
    ("MapListService_001", "g_pMapListService"),
    ("GameUIService_001", "g_pGameUIService"),
    ("SoundService_001", "g_pSoundService"),
    ("BenchmarkService001", "g_pBenchmarkService"),
    ("KeyValueCache001", "g_pKeyValueCache"),
    ("ClientServerSharedHandleSystem001", "g_pClientServerSharedHandleSystem"),
    ("GameResourceServiceClientV001", "g_pGameResourceServiceClient"),
    ("GameResourceServiceServerV001", "g_pGameResourceServiceServer"),
    ("Source2EngineToClient001", "g_pSource2EngineToClient"),
    ("Source2EngineToServer001", "g_pSource2EngineToServer"),
    ("Source2EngineToServerStringTable001", "g_pSource2EngineToServerStringTable"),
    ("Source2EngineToClientStringTable001", "g_pSource2EngineToClientStringTable"),
    ("VPhysics2_Interface_001", "g_pVPhysics2"),
    ("ModelDocUtils001", "g_pModelDocUtils"),
    ("AnimGraphEditorUtils001", "g_pAnimGraphEditorUtils"),
    ("EXPORTSYSTEM_INTERFACE_VERSION_001", "g_pExportSystem"),
    ("ServerToolsInfo_001", "g_pServerToolsInfo"),
    ("ClientToolsInfo_001", "g_pClientToolsInfo"),
    ("Vrad3_001", "g_pRAD3"),
    ("NavSystem001", "g_pNavSystem"),
    ("NavGameTest001", "g_pNavGameTest"),
]
```

## Task 1: Add Custom Preprocessor Script

**Files:**
- Create: `ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py`

- [ ] **Step 1: Create constants and basic helpers**

Create the file with imports and constants:

```python
#!/usr/bin/env python3
"""Preprocess script for g_pInterfaceGlobals ppGlobal entries."""

import json
import os

import yaml

from ida_analyze_util import parse_mcp_result, write_gv_yaml

INTERFACE_GLOBALS_NAME = "g_pInterfaceGlobals"
ENTRY_SIZE = 0x10
MAX_SCAN_ENTRIES = 256
EXPECTED_ENTRIES = [
    # Paste the full ordered list from this plan.
]
WINDOWS_EXPECTED_ENTRIES = EXPECTED_ENTRIES
LINUX_EXPECTED_ENTRIES = EXPECTED_ENTRIES[:-2]
```

Add:

```python
def _debug(debug, message):
    if debug:
        print(f"    Preprocess: {message}")
```

- [ ] **Step 2: Add YAML input loader**

Add:

```python
def _parse_addr(value):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _load_interface_globals_va(new_binary_dir, platform, debug=False):
    yaml_path = os.path.join(new_binary_dir, f"{INTERFACE_GLOBALS_NAME}.{platform}.yaml")
    if not os.path.exists(yaml_path):
        _debug(debug, f"missing input YAML {yaml_path}")
        return None
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        _debug(debug, f"failed to read {yaml_path}: {exc}")
        return None
    if not isinstance(data, dict):
        _debug(debug, f"invalid YAML payload in {yaml_path}")
        return None
    gv_va = _parse_addr(data.get("gv_va"))
    if gv_va is None:
        _debug(debug, f"missing or invalid gv_va in {yaml_path}")
    return gv_va
```

- [ ] **Step 3: Add IDA py_eval scanner**

Add:

```python
def _build_scan_py_eval(table_va, expected_count):
    max_entries = max(expected_count, MAX_SCAN_ENTRIES)
    return f"""
import ida_bytes
import idc
import json

table_va = {table_va}
entry_size = {ENTRY_SIZE}
max_entries = {max_entries}
entries = []

def read_qword(ea):
    value = ida_bytes.get_qword(ea)
    if value in (None, idc.BADADDR):
        return None
    return int(value)

for index in range(max_entries):
    entry_va = table_va + index * entry_size
    interface_name_va = read_qword(entry_va)
    pp_global_va = read_qword(entry_va + 8)
    if not interface_name_va or not pp_global_va:
        break
    interface_name = idc.get_strlit_contents(interface_name_va, -1, idc.STRTYPE_C)
    if isinstance(interface_name, bytes):
        interface_name = interface_name.decode("utf-8", errors="replace")
    if not interface_name:
        break
    entries.append({{
        "index": index,
        "entry_va": hex(entry_va),
        "interface_name": str(interface_name),
        "interface_name_va": hex(interface_name_va),
        "pp_global_va": hex(pp_global_va),
    }})

result = json.dumps(entries)
"""
```

Add:

```python
async def _scan_entries_via_mcp(session, table_va, debug=False):
    code = _build_scan_py_eval(table_va, len(EXPECTED_ENTRIES))
    try:
        result = await session.call_tool(name="py_eval", arguments={"code": code})
    except Exception as exc:
        _debug(debug, f"py_eval scan failed: {exc}")
        return None
    payload = parse_mcp_result(result)
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            _debug(debug, f"scan returned non-json payload: {payload}")
            return None
    if not isinstance(payload, list):
        _debug(debug, f"scan returned invalid payload: {payload}")
        return None
    return payload
```

- [ ] **Step 4: Add expected-interface coverage validator**

Add:

```python
def _match_expected_entries(actual_entries, debug=False):
    expected_interfaces = {interface for interface, _ in EXPECTED_ENTRIES}
    actual_by_interface = {}
    for actual in actual_entries:
        actual_interface = str(actual.get("interface_name", ""))
        if actual_interface not in expected_interfaces:
            continue
        if actual_interface in actual_by_interface:
            _debug(debug, f"duplicate interface entry: {actual_interface}")
            return None
        actual_by_interface[actual_interface] = actual

    for expected_interface, expected_gv in EXPECTED_ENTRIES:
        actual = actual_by_interface.get(expected_interface)
        if actual is None:
            _debug(debug, f"missing expected interface: {expected_interface}")
            return None
        pp_global_va = _parse_addr(actual.get("pp_global_va"))
        if pp_global_va is None or pp_global_va == 0:
            _debug(debug, f"invalid pp_global_va for {expected_gv}: {actual}")
            return None

    return actual_by_interface
```

- [ ] **Step 5: Add expected output mapping and writer**

Add:

```python
def _build_output_map(expected_outputs, platform, debug=False):
    output_map = {}
    for path in expected_outputs or []:
        output_map[os.path.basename(path)] = path

    resolved = {}
    for gv_name in EXPECTED_GV_NAMES:
        filename = f"{gv_name}.{platform}.yaml"
        output_path = output_map.get(filename)
        if not output_path:
            _debug(debug, f"missing expected output path for {filename}")
            return None
        resolved[gv_name] = output_path
    return resolved


def _build_gv_payloads(actual_by_interface, image_base):
    payloads = {}
    for interface_name, gv_name in EXPECTED_ENTRIES:
        actual = actual_by_interface[interface_name]
        gv_va = _parse_addr(actual.get("pp_global_va"))
        payloads[gv_name] = {
            "gv_name": gv_name,
            "gv_va": hex(gv_va),
            "gv_rva": hex(gv_va - image_base),
        }
    return payloads
```

- [ ] **Step 6: Add best-effort rename helper**

Add:

```python
async def _rename_globals_best_effort(session, payloads, debug=False):
    batch = {
        "data": [
            {"old": payload["gv_va"], "new": gv_name}
            for gv_name, payload in payloads.items()
        ]
    }
    try:
        await session.call_tool(name="rename", arguments={"batch": batch})
    except Exception as exc:
        _debug(debug, f"best-effort gv rename failed: {exc}")
```

If the IDA MCP `rename` data mode requires old symbol names instead of addresses, replace this helper with a `py_eval` based `idc.set_name(int(gv_va, 16), gv_name, idc.SN_NOWARN)` implementation. The rename helper must remain non-fatal.

- [ ] **Step 7: Add `preprocess_skill`**

Add:

```python
async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    _ = skill_name, old_yaml_map, llm_config

    table_va = _load_interface_globals_va(new_binary_dir, platform, debug=debug)
    if table_va is None:
        return False

    output_map = _build_output_map(expected_outputs, platform, debug=debug)
    if output_map is None:
        return False

    actual_entries = await _scan_entries_via_mcp(session, table_va, debug=debug)
    if actual_entries is None:
        return False

    actual_by_interface = _match_expected_entries(actual_entries, debug=debug)
    if actual_by_interface is None:
        return False

    payloads = _build_gv_payloads(actual_by_interface, image_base)
    try:
        for gv_name, payload in payloads.items():
            write_gv_yaml(output_map[gv_name], payload)
    except Exception as exc:
        _debug(debug, f"failed to write gv YAML: {exc}")
        return False

    await _rename_globals_best_effort(session, payloads, debug=debug)
    return True
```

## Task 2: Add Unit Tests For Custom Script

**Files:**
- Modify: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: Add script path constant**

Near existing script path constants, add:

```python
INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH = (
    PREPROCESSOR_SCRIPTS_DIR / "find-g_pInterfaceGlobals_ppGlobal.py"
)
```

- [ ] **Step 2: Add fake MCP result helper if needed**

If the file does not already have a reusable result class, add near the tests:

```python
class _TextResult:
    def __init__(self, text):
        self.content = [type("TextContent", (), {"text": text})()]
```

- [ ] **Step 3: Add success test**

Add a new `unittest.IsolatedAsyncioTestCase` class:

```python
class TestFindGInterfaceGlobalsPpGlobal(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_writes_minimal_gv_yaml_from_interface_names(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal",
        )
        expected_entries = [
            {
                "index": index,
                "entry_va": hex(0x180400000 + index * 0x10),
                "interface_name": interface_name,
                "interface_name_va": hex(0x180500000 + index * 0x20),
                "pp_global_va": hex(0x180600000 + index * 0x8),
            }
            for index, (interface_name, _) in enumerate(module.EXPECTED_ENTRIES)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "g_pInterfaceGlobals.windows.yaml"
            input_path.write_text(
                "gv_name: g_pInterfaceGlobals\n"
                "gv_va: '0x1804cd5c0'\n"
                "gv_rva: '0x4cd5c0'\n",
                encoding="utf-8",
            )
            expected_outputs = [
                str(Path(temp_dir) / f"{gv_name}.windows.yaml")
                for _, gv_name in module.EXPECTED_ENTRIES
            ]
            session = AsyncMock()
            session.call_tool.side_effect = [
                _TextResult(json.dumps(expected_entries)),
                _TextResult("{}"),
            ]

            with patch.object(module, "write_gv_yaml") as mock_write:
                result = await module.preprocess_skill(
                    session=session,
                    skill_name="find-g_pInterfaceGlobals_ppGlobal",
                    expected_outputs=expected_outputs,
                    old_yaml_map={},
                    new_binary_dir=temp_dir,
                    platform="windows",
                    image_base=0x180000000,
                    debug=True,
                )

        self.assertTrue(result)
        self.assertEqual(len(module.EXPECTED_ENTRIES), mock_write.call_count)
        first_path, first_payload = mock_write.call_args_list[0].args
        self.assertTrue(first_path.endswith("g_pVApplication.windows.yaml"))
        self.assertEqual(
            {
                "gv_name": "g_pVApplication",
                "gv_va": "0x180600000",
                "gv_rva": "0x600000",
            },
            first_payload,
        )
```

- [ ] **Step 4: Add mismatch, trailing-extra, and out-of-order tests**

Add tests for missing entries, trailing extra entries, out-of-order entries, and name mismatch:

```python
    async def test_preprocess_skill_fails_on_missing_entry(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_missing",
        )
        actual_entries = [
            {
                "index": index,
                "entry_va": hex(0x180400000 + index * 0x10),
                "interface_name": interface_name,
                "interface_name_va": hex(0x180500000 + index * 0x20),
                "pp_global_va": hex(0x180600000 + index * 0x8),
            }
            for index, (interface_name, _) in enumerate(module.EXPECTED_ENTRIES[:-1])
        ]
        result, mock_write = await self._run_with_entries(module, actual_entries)
        self.assertFalse(result)
        mock_write.assert_not_called()

    async def test_preprocess_skill_fails_on_interface_name_mismatch(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_mismatch",
        )
        actual_entries = [
            {
                "index": index,
                "entry_va": hex(0x180400000 + index * 0x10),
                "interface_name": interface_name,
                "interface_name_va": hex(0x180500000 + index * 0x20),
                "pp_global_va": hex(0x180600000 + index * 0x8),
            }
            for index, (interface_name, _) in enumerate(module.EXPECTED_ENTRIES)
        ]
        actual_entries[1]["interface_name"] = "WrongInterface001"
        result, mock_write = await self._run_with_entries(module, actual_entries)
        self.assertFalse(result)
        mock_write.assert_not_called()
```

Factor common setup into `_run_with_entries(...)` inside the test class if that keeps the tests short.

- [ ] **Step 5: Add missing output test**

Add:

```python
    async def test_preprocess_skill_fails_when_expected_output_is_missing(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_missing_output",
        )
        actual_entries = [
            {
                "index": index,
                "entry_va": hex(0x180400000 + index * 0x10),
                "interface_name": interface_name,
                "interface_name_va": hex(0x180500000 + index * 0x20),
                "pp_global_va": hex(0x180600000 + index * 0x8),
            }
            for index, (interface_name, _) in enumerate(module.EXPECTED_ENTRIES)
        ]
        result, mock_write = await self._run_with_entries(
            module,
            actual_entries,
            drop_last_output=True,
        )
        self.assertFalse(result)
        mock_write.assert_not_called()
```

## Task 3: Register Skill And GV Symbols In config.yaml

**Files:**
- Modify: `config.yaml`

- [ ] **Step 1: Add skill to client**

After the existing client skill:

```yaml
- name: find-g_pInterfaceGlobals
  expected_output:
    - g_pInterfaceGlobals.{platform}.yaml
  expected_input:
    - ConnectInterfaces.{platform}.yaml
```

add:

```yaml
- name: find-g_pInterfaceGlobals_ppGlobal
  expected_output:
    - g_pVApplication.{platform}.yaml
    - g_pVEngineCvar.{platform}.yaml
    # Add every gv name from EXPECTED_ENTRIES in order.
  expected_output_windows:
    - g_pNavSystem.{platform}.yaml
    - g_pNavGameTest.{platform}.yaml
  expected_input:
    - g_pInterfaceGlobals.{platform}.yaml
```

- [ ] **Step 2: Add skill to server**

Repeat the same skill block after the server `find-g_pInterfaceGlobals` block.

- [ ] **Step 3: Add skill to engine post-client module**

Repeat the same skill block after the duplicate post-client `engine` module's `find-g_pInterfaceGlobals` block near the end of `config.yaml`.

- [ ] **Step 4: Add GV symbols to primary engine symbols**

In the primary `engine` module's `symbols` list, before or after `g_pInterfaceGlobals`, add each `gv_name` from `EXPECTED_ENTRIES`:

```yaml
- name: g_pVApplication
  category: gv
- name: g_pVEngineCvar
  category: gv
```

Do not duplicate names already present in that module.

- [ ] **Step 5: Add GV symbols to client symbols**

Repeat the same symbol additions in the `client` module's `symbols` list.

- [ ] **Step 6: Add GV symbols to server symbols**

Repeat the same symbol additions in the `server` module's `symbols` list.

## Task 4: Static Verification

**Files:**
- Read: `ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py`
- Read: `config.yaml`

- [ ] **Step 1: Import the new script without running tests**

Run only this static import command:

```powershell
uv run python -c "import importlib.util; p='ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py'; s=importlib.util.spec_from_file_location('ppg', p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(len(m.EXPECTED_ENTRIES)); print(m.EXPECTED_ENTRIES[0]); print(m.EXPECTED_ENTRIES[-1])"
```

Expected:

```text
112
('VApplication001', 'g_pVApplication')
('NavGameTest001', 'g_pNavGameTest')
```

Also verify the Linux list:

```powershell
uv run python -c "import importlib.util; p='ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py'; s=importlib.util.spec_from_file_location('ppg', p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(len(m.LINUX_EXPECTED_ENTRIES)); print(m.LINUX_EXPECTED_ENTRIES[-1])"
```

Expected:

```text
111
('NavSystem001', 'g_pNavSystem')
```

- [ ] **Step 2: Parse config.yaml**

Run:

```powershell
uv run python -c "import yaml; data=yaml.safe_load(open('config.yaml', encoding='utf-8')); print(len(data['modules']))"
```

Expected:

```text
prints a positive module count without exception
```

- [ ] **Step 3: Verify module registrations by script**

Run:

```powershell
@'
import yaml
from pathlib import Path

expected = [
    "g_pVApplication",
    "g_pVEngineCvar",
    "g_pNavGameTest",
]
data = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
modules = data["modules"]
for name in ("client", "server", "engine"):
    matching = [m for m in modules if m.get("name") == name]
    has_skill = any(
        any(s.get("name") == "find-g_pInterfaceGlobals_ppGlobal" for s in m.get("skills", []))
        for m in matching
    )
    has_symbols = {
        sym.get("name")
        for m in matching
        for sym in m.get("symbols", []) or []
        if sym.get("category") == "gv"
    }
    missing = [gv for gv in expected if gv not in has_symbols]
    print(name, "skill=", has_skill, "missing_sample_symbols=", missing)
'@ | uv run python -
```

Expected:

```text
client skill= True missing_sample_symbols= []
server skill= True missing_sample_symbols= []
engine skill= True missing_sample_symbols= []
```

- [ ] **Step 4: Optional focused unit tests only after user confirmation**

If the user explicitly permits tests, run:

```powershell
uv run python -m unittest tests.test_ida_preprocessor_scripts.TestFindGInterfaceGlobalsPpGlobal -v
```

Expected:

```text
all tests in TestFindGInterfaceGlobalsPpGlobal pass
```

## Task 5: Completion Notes

**Files:**
- Read: `git status --short`

- [ ] **Step 1: Inspect final git status**

Run:

```powershell
git status --short
```

Expected:

```text
shows only the intended spec, plan, preprocessor script, tests, and config.yaml changes
```

- [ ] **Step 2: Do not commit unless confirmed**

If the user explicitly requests a commit, use:

```powershell
git add docs/superpowers/specs/2026-05-20-g_pinterfaceglobals-ppglobal-design.md docs/superpowers/plans/2026-05-20-g_pinterfaceglobals-ppglobal.md ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py tests/test_ida_preprocessor_scripts.py config.yaml
git commit -m "feat: 添加接口全局指针预处理"
```

Expected:

```text
commit is created only after explicit user confirmation
```
