# Optional Output Skill Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `optional_output` support so optional-only skill outputs may be absent without making the whole skill fail.

**Architecture:** Keep `expected_output` as the required-output contract and add `optional_output` as a separate optional artifact list. `process_binary()` resolves both lists, passes `required + optional` paths to preprocessors, but only uses required outputs for hard success and Agent SKILL validation. Optional-only skills that produce no optional YAML are counted as skipped and do not fall back to Agent SKILL.

**Tech Stack:** Python, PyYAML config parsing, `unittest`, `unittest.mock`, temporary filesystem fixtures.

---

## File Structure

- Modify: `ida_analyze_bin.py`
  - Parse `optional_output`
  - Add small output-resolution helpers near `expand_expected_paths()` / `all_expected_outputs_exist()`
  - Update `process_binary()` prefilter and execution loops
- Modify: `tests/test_ida_analyze_bin.py`
  - Add parser tests for `optional_output`
  - Add ordering test proving `optional_output` does not infer dependencies
  - Add process tests for optional-only skip/success and required-plus-optional behavior
- No change: `config.yaml`
  - The target entry already declares `optional_output` for `find-CEngineServiceMgr_DeactivateLoop`

---

### Task 1: Parse Optional Output And Lock Dependency Boundary

**Files:**
- Modify: `tests/test_ida_analyze_bin.py:235-321`
- Modify: `ida_analyze_bin.py:1159-1169`

- [ ] **Step 1: Add failing parser tests**

Insert these tests inside `TestParseConfig`, after `test_parse_config_defaults_skip_if_exists_to_empty_list`:

```python
    def test_parse_config_reads_optional_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    path_windows: game/bin/win64/engine2.dll
    path_linux: game/bin/linuxsteamrt64/libengine2.so
    skills:
      - name: find-CEngineServiceMgr_DeactivateLoop
        optional_output:
          - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual(
            ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
            modules[0]["skills"][0]["optional_output"],
        )

    def test_parse_config_defaults_optional_output_to_empty_list(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    path_windows: game/bin/win64/engine2.dll
    path_linux: game/bin/linuxsteamrt64/libengine2.so
    skills:
      - name: find-CEngineServiceMgr_DeactivateLoop
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual([], modules[0]["skills"][0]["optional_output"])
```

Add this test inside `TestSkillOrdering`, after `test_topological_sort_skills_keeps_ilooptype_after_deactivateloop`:

```python
    def test_topological_sort_skills_ignores_optional_output(self) -> None:
        skills = [
            {
                "name": "consumer",
                "expected_output": ["Consumer.{platform}.yaml"],
                "expected_input": ["OptionalOnly.{platform}.yaml"],
            },
            {
                "name": "optional_producer",
                "optional_output": ["OptionalOnly.{platform}.yaml"],
            },
        ]

        ordered = ida_analyze_bin.topological_sort_skills(skills)

        self.assertEqual(["consumer", "optional_producer"], ordered)
```

- [ ] **Step 2: Run parser and ordering tests to verify failure**

Run:

```bash
uv run python -m pytest tests/test_ida_analyze_bin.py::TestParseConfig tests/test_ida_analyze_bin.py::TestSkillOrdering -q
```

Expected: parser tests fail with `KeyError: 'optional_output'`. The ordering test should pass or continue to pass because `topological_sort_skills()` does not read `optional_output`.

- [ ] **Step 3: Implement config parsing**

In `ida_analyze_bin.py`, update the `skills.append({...})` mapping in `parse_config()` to include `optional_output`:

```python
                skills.append({
                    "name": skill_name,
                    "expected_output": skill.get("expected_output", []) or [],
                    "optional_output": skill.get("optional_output", []) or [],
                    "expected_input": skill.get("expected_input", []),
                    "expected_input_windows": skill.get("expected_input_windows", []) or [],
                    "expected_input_linux": skill.get("expected_input_linux", []) or [],
                    "skip_if_exists": skill.get("skip_if_exists", []) or [],
                    "prerequisite": skill.get("prerequisite", []) or [],
                    "max_retries": skill.get("max_retries"),  # None means use default
                    "platform": skill.get("platform"),  # None means all platforms
                })
```

- [ ] **Step 4: Run parser and ordering tests to verify pass**

Run:

```bash
uv run python -m pytest tests/test_ida_analyze_bin.py::TestParseConfig tests/test_ida_analyze_bin.py::TestSkillOrdering -q
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "feat: 解析 optional_output 配置"
```

---

### Task 2: Resolve Required And Optional Outputs In Prefilter

**Files:**
- Modify: `tests/test_ida_analyze_bin.py:820-925`
- Modify: `ida_analyze_bin.py:1349-1359`
- Modify: `ida_analyze_bin.py:2107-2144`

- [ ] **Step 1: Add failing prefilter tests**

Insert these tests inside `TestProcessBinary`, after `test_process_binary_skips_when_all_skip_if_exists_artifacts_exist_before_ida_start`:

```python
    def test_process_binary_skips_optional_only_skill_when_optional_output_exists_before_ida_start(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr_DeactivateLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr_DeactivateLoop\n",
                encoding="utf-8",
            )

            with patch.object(
                ida_analyze_bin,
                "start_idalib_mcp",
                return_value=None,
            ) as mock_start_ida:
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "optional_output": [
                                "CEngineServiceMgr_DeactivateLoop.{platform}.yaml"
                            ],
                            "expected_input": [
                                "CEngineServiceMgr__MainLoop.{platform}.yaml"
                            ],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_start_ida.assert_not_called()

    def test_process_binary_rejects_illegal_optional_output_before_ida_start(
        self,
    ) -> None:
        binary_path = str(Path("/tmp/bin/14141/engine/libengine2.so"))

        with patch.object(
            ida_analyze_bin,
            "start_idalib_mcp",
            return_value=None,
        ) as mock_start_ida:
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=[
                    {
                        "name": "find-CEngineServiceMgr_DeactivateLoop",
                        "optional_output": ["../../outside/secret.{platform}.yaml"],
                        "expected_input": [],
                    }
                ],
                agent="codex",
                host="127.0.0.1",
                port=13337,
                ida_args="",
                platform="windows",
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_start_ida.assert_not_called()
```

- [ ] **Step 2: Run the new prefilter tests to verify failure**

Run:

```bash
uv run python -m pytest tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_skips_optional_only_skill_when_optional_output_exists_before_ida_start tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_rejects_illegal_optional_output_before_ida_start -q
```

Expected: the first test fails because the optional-only skill is not skipped before IDA startup; the second test fails if illegal `optional_output` paths are not validated.

- [ ] **Step 3: Add output helper functions**

In `ida_analyze_bin.py`, immediately after `all_expected_outputs_exist()`, add:

```python
def expand_skill_output_paths(binary_dir, skill, platform):
    """Return required, optional, and preprocessor output paths for one skill."""
    required_outputs = expand_expected_paths(
        binary_dir,
        skill.get("expected_output", []) or [],
        platform,
    )
    optional_outputs = expand_expected_paths(
        binary_dir,
        skill.get("optional_output", []) or [],
        platform,
    )
    return required_outputs, optional_outputs, required_outputs + optional_outputs


def should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
    """Return True when configured output artifacts make processing unnecessary."""
    if required_outputs:
        return all_expected_outputs_exist(required_outputs)
    return all_expected_outputs_exist(optional_outputs)
```

- [ ] **Step 4: Update prefilter to use required and optional paths**

Replace the prefilter block in `process_binary()` from line 2107 through the `skills_to_process.append(...)` call with:

```python
    # Filter skills that need processing (skip if configured outputs already exist)
    skills_to_process = []
    for skill_name in sorted_skill_names:
        skill = skill_map[skill_name]
        # Skip skills restricted to a different platform
        skill_platform = skill.get("platform")
        if skill_platform and skill_platform != platform:
            print(f"  Skipping skill: {skill_name} (platform '{skill_platform}' != '{platform}')")
            skip_count += 1
            continue
        try:
            required_outputs, optional_outputs, preprocess_outputs = expand_skill_output_paths(
                binary_dir,
                skill,
                platform,
            )
        except ValueError as e:
            fail_count += 1
            print(f"  Failed: {skill_name} ({e})")
            continue
        # Check if configured output files already make the skill unnecessary.
        if should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
            print(f"  Skipping skill: {skill_name} (all outputs exist)")
            skip_count += 1
        else:
            try:
                skip_for_existing_artifacts, _skip_paths = should_skip_skill_for_existing_artifacts(
                    binary_dir,
                    skill,
                    platform,
                )
            except ValueError as e:
                fail_count += 1
                print(f"  Failed: {skill_name} ({e})")
                continue
            if skip_for_existing_artifacts:
                print(f"  Skipping skill: {skill_name} (all skip_if_exists artifacts exist)")
                skip_count += 1
            else:
                # Use skill-specific max_retries if provided, otherwise use default
                skill_max_retries = skill.get("max_retries") or max_retries
                skills_to_process.append(
                    (
                        skill_name,
                        required_outputs,
                        optional_outputs,
                        preprocess_outputs,
                        skill_max_retries,
                    )
                )
```

- [ ] **Step 5: Run prefilter tests to verify pass**

Run:

```bash
uv run python -m pytest tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_skips_optional_only_skill_when_optional_output_exists_before_ida_start tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_rejects_illegal_optional_output_before_ida_start -q
```

Expected: both selected tests pass.

- [ ] **Step 6: Commit**

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "feat: 支持 optional_output 预筛选"
```

---

### Task 3: Apply Optional Output Semantics During Execution

**Files:**
- Modify: `tests/test_ida_analyze_bin.py:735-1000`
- Modify: `ida_analyze_bin.py:2177-2328`

- [ ] **Step 1: Add failing execution tests**

Insert these tests inside `TestProcessBinary`, after `test_process_binary_rechecks_skip_if_exists_before_running_skill`:

```python
    def test_process_binary_skips_optional_only_skill_when_preprocess_fails_without_output(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr__MainLoop\n",
                encoding="utf-8",
            )
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="failed",
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "optional_output": [
                                "CEngineServiceMgr_DeactivateLoop.{platform}.yaml"
                            ],
                            "expected_input": [
                                "CEngineServiceMgr__MainLoop.{platform}.yaml"
                            ],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_preprocess.assert_called_once()
        self.assertEqual(
            [
                str(binary_dir / "CEngineServiceMgr_DeactivateLoop.windows.yaml"),
            ],
            mock_preprocess.call_args.kwargs["expected_outputs"],
        )
        mock_run_skill.assert_not_called()

    def test_process_binary_counts_optional_only_skill_success_when_preprocess_writes_output(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr__MainLoop\n",
                encoding="utf-8",
            )

            def _fake_preprocess(*, expected_outputs, **_kwargs):
                Path(expected_outputs[0]).write_text(
                    "func_name: CEngineServiceMgr_DeactivateLoop\n",
                    encoding="utf-8",
                )
                return "success"

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=object()),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    side_effect=lambda process, *_args, **_kwargs: (process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "optional_output": [
                                "CEngineServiceMgr_DeactivateLoop.{platform}.yaml"
                            ],
                            "expected_input": [
                                "CEngineServiceMgr__MainLoop.{platform}.yaml"
                            ],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        mock_run_skill.assert_not_called()

    def test_process_binary_passes_required_plus_optional_to_preprocess_but_only_requires_expected_output(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")

            def _fake_preprocess(*, expected_outputs, **_kwargs):
                self.assertEqual(
                    [
                        str(binary_dir / "Required.windows.yaml"),
                        str(binary_dir / "Optional.windows.yaml"),
                    ],
                    expected_outputs,
                )
                Path(expected_outputs[0]).write_text(
                    "func_name: Required\n",
                    encoding="utf-8",
                )
                return "success"

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=object()),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    side_effect=lambda process, *_args, **_kwargs: (process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-required-and-optional",
                            "expected_output": ["Required.{platform}.yaml"],
                            "optional_output": ["Optional.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        mock_run_skill.assert_not_called()

    def test_process_binary_agent_skill_validates_only_required_outputs(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="failed",
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=True) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-required-and-optional",
                            "expected_output": ["Required.{platform}.yaml"],
                            "optional_output": ["Optional.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        self.assertEqual(
            [str(binary_dir / "Required.windows.yaml")],
            mock_run_skill.call_args.kwargs["expected_yaml_paths"],
        )
```

- [ ] **Step 2: Run execution tests to verify failure**

Run:

```bash
uv run python -m pytest tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_skips_optional_only_skill_when_preprocess_fails_without_output tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_counts_optional_only_skill_success_when_preprocess_writes_output tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_passes_required_plus_optional_to_preprocess_but_only_requires_expected_output tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_agent_skill_validates_only_required_outputs -q
```

Expected: tests fail because the execution loop still expects 3-tuple `skills_to_process`, checks all outputs as required, and passes all expected paths to `run_skill()`.

- [ ] **Step 3: Update IDA startup failure accounting**

In `ida_analyze_bin.py`, line 2181 currently uses `len(skills_to_process)`. Keep that behavior unchanged after tuple shape changes:

```python
                fail_count + len(skills_to_process) + len(vcall_targets) + post_process_failure,
```

No code change is needed for the expression itself; this step is a guardrail to avoid replacing it with a count that excludes optional-only skills. If IDA cannot start, queued optional-only skills did require IDA, so they still count as failed startup work.

- [ ] **Step 4: Update execution loop tuple unpacking and second output check**

Replace:

```python
        for skill_index, (skill_name, expected_outputs, skill_max_retries) in enumerate(skills_to_process):
            if all_expected_outputs_exist(expected_outputs):
                print(f"  Skipping skill: {skill_name} (all outputs exist)")
                skip_count += 1
                continue
```

with:

```python
        for skill_index, (
            skill_name,
            required_outputs,
            optional_outputs,
            preprocess_outputs,
            skill_max_retries,
        ) in enumerate(skills_to_process):
            if should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
                print(f"  Skipping skill: {skill_name} (all outputs exist)")
                skip_count += 1
                continue
```

- [ ] **Step 5: Update old YAML map and preprocessor output list**

Replace the old YAML map and `_run_preprocess_single_skill_via_mcp(...)` argument so they use `preprocess_outputs`:

```python
            old_yaml_map = None
            if old_binary_dir:
                old_yaml_map = {}
                for new_path in preprocess_outputs:
                    filename = os.path.basename(new_path)
                    old_path = os.path.join(old_binary_dir, filename)
                    old_yaml_map[new_path] = old_path
```

and:

```python
                    expected_outputs=preprocess_outputs,
```

- [ ] **Step 6: Update preprocessor success handling**

Replace the `PREPROCESS_STATUS_SUCCESS` block with:

```python
            if preprocess_status == PREPROCESS_STATUS_SUCCESS:
                missing_required_outputs = [
                    p for p in required_outputs if not os.path.exists(p)
                ]
                optional_output_generated = any(
                    os.path.exists(p) for p in optional_outputs
                )
                if missing_required_outputs:
                    fail_count += 1
                    missing_names = [
                        os.path.basename(p) for p in missing_required_outputs
                    ]
                    print(
                        f"  Pre-processed but missing expected_output: {skill_name} "
                        f"({', '.join(missing_names)})"
                    )
                elif (
                    not required_outputs
                    and optional_outputs
                    and not optional_output_generated
                ):
                    skip_count += 1
                    print(
                        f"  Skipping skill: {skill_name} "
                        "(optional outputs not generated)"
                    )
                else:
                    success_count += 1
                    if old_binary_dir:
                        print(f"  Pre-processed: {skill_name} (signature reuse)")
                    else:
                        print(f"  Pre-processed: {skill_name}")
                continue
```

- [ ] **Step 7: Update failed preprocessor fallback gate**

Replace the output-exists check before `Processing skill` with:

```python
            if should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
                print(f"  Skipping skill: {skill_name} (all outputs exist)")
                skip_count += 1
                continue

            if not required_outputs and optional_outputs:
                skip_count += 1
                print(
                    f"  Skipping skill: {skill_name} "
                    "(optional outputs not generated)"
                )
                continue
```

- [ ] **Step 8: Update Agent SKILL required-output validation**

Replace:

```python
            if run_skill(skill_name, agent, debug, expected_yaml_paths=expected_outputs, max_retries=skill_max_retries):
```

with:

```python
            if run_skill(
                skill_name,
                agent,
                debug,
                expected_yaml_paths=required_outputs,
                max_retries=skill_max_retries,
            ):
```

- [ ] **Step 9: Run execution tests to verify pass**

Run:

```bash
uv run python -m pytest tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_skips_optional_only_skill_when_preprocess_fails_without_output tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_counts_optional_only_skill_success_when_preprocess_writes_output tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_passes_required_plus_optional_to_preprocess_but_only_requires_expected_output tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_agent_skill_validates_only_required_outputs -q
```

Expected: all selected tests pass.

- [ ] **Step 10: Commit**

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "feat: 支持 optional_output 执行语义"
```

---

### Task 4: Regression Check And Final Commit

**Files:**
- Modify if needed: `ida_analyze_bin.py`
- Modify if needed: `tests/test_ida_analyze_bin.py`

- [ ] **Step 1: Run focused regression tests**

Run:

```bash
uv run python -m pytest tests/test_ida_analyze_bin.py::TestParseConfig tests/test_ida_analyze_bin.py::TestSkillOrdering tests/test_ida_analyze_bin.py::TestProcessBinary -q
```

Expected: all selected tests pass.

- [ ] **Step 2: Inspect config target entry**

Run:

```bash
sed -n '753,763p' config.yaml
```

Expected output includes:

```yaml
      - name: find-CEngineServiceMgr_DeactivateLoop
        optional_output:
          - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
        skip_if_exists:
          - CLoopTypeBase_DeallocateLoopMode.{platform}.yaml
```

- [ ] **Step 3: Inspect diff for unintended config or unrelated edits**

Run:

```bash
git diff -- ida_analyze_bin.py tests/test_ida_analyze_bin.py config.yaml
```

Expected: only `ida_analyze_bin.py` and `tests/test_ida_analyze_bin.py` changed. `config.yaml` should have no diff.

- [ ] **Step 4: Commit any regression fix if Step 1 required changes**

If Step 1 failed and code was adjusted, commit the focused fix:

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "fix: 修正 optional_output 回归行为"
```

If Step 1 passed without changes, do not create an empty commit.

---

## Self-Review Notes

- Spec coverage: parsing, prefilter, execution skip, preprocessor output path, Agent validation, topology isolation, and existing config entry are covered by tasks.
- Placeholder scan: no task contains unresolved implementation placeholders.
- Type consistency: the plan consistently uses `required_outputs`, `optional_outputs`, and `preprocess_outputs` in tests and implementation snippets.
