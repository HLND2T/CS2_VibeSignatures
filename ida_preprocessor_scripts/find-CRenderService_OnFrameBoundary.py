from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CRenderService_OnFrameBoundary"]

LLM_DECOMPILE = [
    {
        "symbol_name": "CRenderService_OnFrameBoundary",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CRenderService_EventMapRegister.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CRenderService_EventMapRegister.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CRenderService_OnFrameBoundary",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
