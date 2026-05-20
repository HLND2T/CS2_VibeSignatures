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
    ('VApplication001', 'g_pVApplication'), ('VEngineCvar007', 'g_pVEngineCvar'), ('VStringTokenSystem001', 'g_pVStringTokenSystem'),
    ('TestScriptMgr001', 'g_pTestScriptMgr'), ('VProcessUtils002', 'g_pProcessUtils'), ('VFileSystem017', 'g_pFileSystem'),
    ('VAsyncFileSystem2_001', 'g_pAsyncFileSystem'), ('ResourceSystem013', 'g_pResourceSystem'), ('ResourceManifestRegistry001', 'g_pResourceManifestRegistry'),
    ('ResourceHandleUtils001', 'g_pResourceHandleUtils'), ('SchemaSystem_001', 'g_pSchemaSystem'), ('ResourceCompilerSystem001', 'g_pResourceCompilerSystem'),
    ('VMaterialSystem2_001', 'g_pMaterialSystem2'), ('PostProcessingSystem_001', 'g_pPostProcessingSystem'), ('InputSystemVersion001', 'g_pInputSystem'),
    ('InputStackSystemVersion001', 'g_pInputStackSystem'), ('RenderDeviceMgr001', 'g_pRenderDeviceMgr'), ('RenderUtils_001', 'g_pRenderUtils'),
    ('SoundSystem001', 'g_pSoundSystem'), ('SoundOpSystemEdit001', 'g_pSoundOpSystemEdit'), ('SoundOpSystem001', 'g_pSoundOpSystem'),
    ('SteamAudio001', 'g_pSteamAudio'), ('VP4003', 'g_pVP4'), ('Localize_001', 'g_pLocalize'),
    ('VMediaFoundation001', 'g_pMediaFoundation'), ('VAvi001', 'g_pAVI'), ('VWebm001', 'g_pWEBM'),
    ('VBik001', 'g_pBIK'), ('MeshSystem001', 'g_pMeshSystem'), ('MeshUtils001', 'g_pMeshUtils'),
    ('RenderDevice003', 'g_pRenderDevice'), ('VRenderDeviceSetupV001', 'g_pRenderDeviceSetup'), ('RenderHardwareConfig002', 'g_pRenderHardwareConfig'),
    ('SceneSystem_002', 'g_pSceneSystem'), ('IPulseSystem_001', 'g_pIPulseSystem'), ('SceneUtils_001', 'g_pSceneUtils'),
    ('WorldRendererMgr001', 'g_pWorldRendererMgr'), ('AssetSystem001', 'g_pAssetSystem'), ('AssetSystemTest001', 'g_pAssetSystemTest'),
    ('ParticleSystemMgr003', 'g_pParticleSystemMgr'), ('VScriptManager010', 'g_pScriptManager'), ('PropertyEditorSystem_001', 'g_pPropertyEditorSystem'),
    ('MATCHFRAMEWORK_001', 'g_pMatchFramework'), ('Source2V8System001', 'g_pSource2V8System'), ('PanoramaUIEngine001', 'g_pPanoramaUIEngine'),
    ('PanoramaUIClient001', 'g_pPanoramaUIClient'), ('PanoramaTextServices001', 'g_pPanoramaTextServices'), ('ToolFramework2_002', 'g_pToolFramework2'),
    ('PhysicsBuilderMgr001', 'g_pPhysicsBuilderMgr'), ('VisBuilder_001', 'g_pVisBuilder'), ('BakedLODBuilderMgr001', 'g_pBakedLODBuilderMgr'),
    ('HelpSystem_001', 'g_pHelpSystem'), ('ToolSceneNodeFactory_001', 'g_pToolSceneNodeFactory'), ('EconItemToolModel_001', 'g_pEconItemToolModel'),
    ('SchemaTestExternal_Two_001', 'g_pSchemaTestExternalTwo'), ('SchemaTestExternal_One_001', 'g_pSchemaTestExternalOne'), ('AnimationSystem_001', 'g_pAnimationSystem'),
    ('AnimationSystemUtils_001', 'g_pAnimationSystemUtils'), ('HammerMapLoader001', 'g_pHammerMapLoader'), ('MaterialUtils_001', 'g_pMaterialUtils'),
    ('FontManager_001', 'g_pFontManager'), ('TextLayout_001', 'g_pTextLayout'), ('AssetPreviewSystem_001', 'g_pAssetPreviewSystem'),
    ('AssetBrowserSystem_001', 'g_pAssetBrowserSystem'), ('AssetRenameSystem_001', 'g_pAssetRenameSystem'), ('VConComm001', 'g_pVConComm'),
    ('MODEL_PROCESSING_SERVICES_INTERFACE_001', 'g_pModelProcessingServices'), ('NetworkSystemVersion001', 'g_pNetworkSystem'), ('NetworkMessagesVersion001', 'g_pNetworkMessages'),
    ('FlattenedSerializersVersion001', 'g_pFlattenedSerializers'), ('SerializedEntitiesVersion001', 'g_pSerializedEntities'), ('DemoUpconverterVersion001', 'g_pDemoUpconverter'),
    ('Source2Client002', 'g_pSource2Client'), ('Source2ClientUI001', 'g_pSource2ClientUI'), ('Source2ClientPrediction001', 'g_pSource2ClientPrediction'),
    ('Source2Server001', 'g_pSource2Server'), ('Source2Host001', 'g_pSource2Host'), ('Source2ModTools001', 'g_pSource2ModTools'),
    ('Source2GameClients001', 'g_pSource2GameClients'), ('Source2GameEntities001', 'g_pSource2GameEntities'), ('EngineServiceMgr001', 'g_pEngineServiceMgr'),
    ('HostStateMgr001', 'g_pHostStateMgr'), ('NetworkService_001', 'g_pNetworkService'), ('NetworkClientService_001', 'g_pNetworkClientService'),
    ('NetworkP2PService_001', 'g_pNetworkP2PService'), ('NetworkServerService_001', 'g_pNetworkServerService'), ('ToolService_001', 'g_pToolService'),
    ('RenderService_001', 'g_pRenderService'), ('StatsService_001', 'g_pStatsService'), ('VProfService_001', 'g_pVProfService'),
    ('InputService_001', 'g_pInputService'), ('MapListService_001', 'g_pMapListService'), ('GameUIService_001', 'g_pGameUIService'),
    ('SoundService_001', 'g_pSoundService'), ('BenchmarkService001', 'g_pBenchmarkService'), ('KeyValueCache001', 'g_pKeyValueCache'),
    ('ClientServerSharedHandleSystem001', 'g_pClientServerSharedHandleSystem'), ('GameResourceServiceClientV001', 'g_pGameResourceServiceClient'), ('GameResourceServiceServerV001', 'g_pGameResourceServiceServer'),
    ('Source2EngineToClient001', 'g_pSource2EngineToClient'), ('Source2EngineToServer001', 'g_pSource2EngineToServer'), ('Source2EngineToServerStringTable001', 'g_pSource2EngineToServerStringTable'),
    ('Source2EngineToClientStringTable001', 'g_pSource2EngineToClientStringTable'), ('VPhysics2_Interface_001', 'g_pVPhysics2'), ('ModelDocUtils001', 'g_pModelDocUtils'),
    ('AnimGraphEditorUtils001', 'g_pAnimGraphEditorUtils'), ('EXPORTSYSTEM_INTERFACE_VERSION_001', 'g_pExportSystem'), ('ServerToolsInfo_001', 'g_pServerToolsInfo'),
    ('ClientToolsInfo_001', 'g_pClientToolsInfo'), ('Vrad3_001', 'g_pRAD3'), ('NavSystem001', 'g_pNavSystem'),
    ('NavGameTest001', 'g_pNavGameTest'),
]

WINDOWS_EXPECTED_ENTRIES = EXPECTED_ENTRIES
LINUX_EXPECTED_ENTRIES = EXPECTED_ENTRIES[:-2]


def _expected_entries_for_platform(platform):
    if platform == "linux":
        return LINUX_EXPECTED_ENTRIES
    return WINDOWS_EXPECTED_ENTRIES


def _expected_gv_names_for_platform(platform):
    return [gv_name for _, gv_name in _expected_entries_for_platform(platform)]


def _debug(debug, message):
    if debug:
        print(f"    Preprocess: {message}")


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


def _parse_py_eval_entries(payload, debug=False):
    if isinstance(payload, dict) and "result" in payload:
        payload = payload.get("result")
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


async def _scan_entries_via_mcp(session, table_va, expected_entries, debug=False):
    code = _build_scan_py_eval(table_va, len(expected_entries))
    try:
        result = await session.call_tool(name="py_eval", arguments={"code": code})
    except Exception as exc:
        _debug(debug, f"py_eval scan failed: {exc}")
        return None
    return _parse_py_eval_entries(parse_mcp_result(result), debug=debug)


def _match_expected_entries(actual_entries, expected_entries, debug=False):
    expected_interfaces = {interface for interface, _ in expected_entries}
    actual_by_interface = {}
    for actual in actual_entries:
        actual_interface = str(actual.get("interface_name", ""))
        if actual_interface not in expected_interfaces:
            continue
        if actual_interface in actual_by_interface:
            _debug(debug, f"duplicate interface entry: {actual_interface}")
            return None
        actual_by_interface[actual_interface] = actual

    if len(actual_by_interface) < len(expected_entries):
        missing = [
            interface
            for interface, _ in expected_entries
            if interface not in actual_by_interface
        ]
        _debug(
            debug,
            "missing expected interface entries: "
            f"{', '.join(missing)}",
        )
        return None

    for expected_interface, expected_gv in expected_entries:
        actual = actual_by_interface[expected_interface]
        pp_global_va = _parse_addr(actual.get("pp_global_va"))
        if pp_global_va is None or pp_global_va == 0:
            _debug(
                debug,
                f"invalid pp_global_va for {expected_interface} -> "
                f"{expected_gv}: {actual}",
            )
            return None

    return actual_by_interface


def _build_output_map(expected_outputs, platform, expected_entries, debug=False):
    output_map = {
        os.path.basename(path): path
        for path in (expected_outputs or [])
    }
    resolved = {}
    for _, gv_name in expected_entries:
        filename = f"{gv_name}.{platform}.yaml"
        output_path = output_map.get(filename)
        if not output_path:
            _debug(debug, f"missing expected output path for {filename}")
            return None
        resolved[gv_name] = output_path
    return resolved


def _build_gv_payloads(actual_by_interface, image_base, expected_entries):
    payloads = {}
    for interface_name, gv_name in expected_entries:
        actual = actual_by_interface[interface_name]
        gv_va = _parse_addr(actual.get("pp_global_va"))
        payloads[gv_name] = {
            "gv_name": gv_name,
            "gv_va": hex(gv_va),
            "gv_rva": hex(gv_va - image_base),
        }
    return payloads


def _build_rename_py_eval(payloads):
    rename_items = [
        {"addr": payload["gv_va"], "name": gv_name}
        for gv_name, payload in payloads.items()
    ]
    rename_items_json = json.dumps(rename_items)
    return f"""
import idc
import json

rename_items = json.loads({rename_items_json!r})
renamed = []
for item in rename_items:
    addr = int(item["addr"], 16)
    name = item["name"]
    ok = idc.set_name(addr, name, idc.SN_NOWARN)
    renamed.append({{"addr": item["addr"], "name": name, "ok": bool(ok)}})

result = json.dumps({{"renamed": renamed}})
"""


async def _rename_globals_best_effort(session, payloads, debug=False):
    try:
        await session.call_tool(
            name="py_eval",
            arguments={"code": _build_rename_py_eval(payloads)},
        )
    except Exception as exc:
        _debug(debug, f"best-effort gv rename failed: {exc}")


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    _ = skill_name, old_yaml_map, llm_config
    expected_entries = _expected_entries_for_platform(platform)

    table_va = _load_interface_globals_va(new_binary_dir, platform, debug=debug)
    if table_va is None:
        return False

    output_map = _build_output_map(
        expected_outputs,
        platform,
        expected_entries,
        debug=debug,
    )
    if output_map is None:
        return False

    actual_entries = await _scan_entries_via_mcp(
        session,
        table_va,
        expected_entries,
        debug=debug,
    )
    if actual_entries is None:
        return False

    actual_by_interface = _match_expected_entries(
        actual_entries,
        expected_entries,
        debug=debug,
    )
    if actual_by_interface is None:
        return False

    payloads = _build_gv_payloads(
        actual_by_interface,
        image_base,
        expected_entries,
    )
    try:
        for gv_name, payload in payloads.items():
            write_gv_yaml(output_map[gv_name], payload)
    except Exception as exc:
        _debug(debug, f"failed to write gv YAML: {exc}")
        return False

    await _rename_globals_best_effort(session, payloads, debug=debug)
    return True
