# Skip If Exists Skill Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `skip_if_exists` support to `config.yaml` skills so a skill is skipped when all configured substitute artifacts already exist.

**Architecture:** Preserve the new field in `parse_config()`, keep `topological_sort_skills()` unchanged, and evaluate `skip_if_exists` inside `process_binary()` both before IDA startup and immediately before each skill executes. Cover parser behavior, AND semantics, runtime recheck, and the real engine config entry with focused unit tests in `tests/test_ida_analyze_bin.py`.

**Tech Stack:** Python 3, `unittest` executed with `pytest`, YAML configuration.

---

## File Map

- `ida_analyze_bin.py:1036`
  - Extend `parse_config()` to preserve `skip_if_exists`
  - Reuse artifact path expansion and add skip checks in `process_binary()` without changing dependency ordering
- `tests/test_ida_analyze_bin.py:1`
  - Add parser regression coverage
  - Add process-binary skip behavior tests for prefilter, AND semantics, and runtime recheck
  - Update the existing ordering regression to prove `skip_if_exists` does not affect `prerequisite`
- `config.yaml:740`
  - Add the concrete `skip_if_exists` entry for `find-CEngineServiceMgr_DeactivateLoop`

### Task 1: Lock parser and ordering semantics with failing tests

**Files:**
- Modify: `tests/test_ida_analyze_bin.py:1`
- Reference: `ida_analyze_bin.py:1036`
- Reference: `ida_analyze_bin.py:1135`

- [ ] **Step 1: Add a parser regression for `skip_if_exists`**

```python
class TestParseConfig(unittest.TestCase):
    def test_parse_config_reads_skip_if_exists(self) -> None:
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
        expected_output:
          - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
        skip_if_exists:
          - ILoopType_DeallocateLoopMode.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual(
            ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
            modules[0]["skills"][0]["skip_if_exists"],
        )
```

- [ ] **Step 2: Extend the existing ordering regression so `skip_if_exists` is present but ignored**

```python
class TestSkillOrdering(unittest.TestCase):
    def test_topological_sort_skills_keeps_ilooptype_after_deactivateloop(
        self,
    ) -> None:
        skills = [
            {
                "name": "find-ILoopType_DeallocateLoopMode",
                "expected_output": ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
                "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                "prerequisite": ["find-CEngineServiceMgr_DeactivateLoop"],
            },
            {
                "name": "find-CEngineServiceMgr_DeactivateLoop",
                "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                "skip_if_exists": ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
            },
            {
                "name": "find-CEngineServiceMgr__MainLoop",
                "expected_output": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
            },
        ]

        ordered = ida_analyze_bin.topological_sort_skills(skills)

        self.assertLess(
            ordered.index("find-CEngineServiceMgr_DeactivateLoop"),
            ordered.index("find-ILoopType_DeallocateLoopMode"),
        )
```

- [ ] **Step 3: Run the new parser test and verify it fails before implementation**

Run: `pytest tests/test_ida_analyze_bin.py::TestParseConfig::test_parse_config_reads_skip_if_exists -q`
Expected: FAIL because `parse_config()` does not yet expose `skip_if_exists`.

### Task 2: Preserve `skip_if_exists` during config parsing

**Files:**
- Modify: `ida_analyze_bin.py:1056`
- Test: `tests/test_ida_analyze_bin.py:1`

- [ ] **Step 1: Add the new field to `parse_config()`**

```python
        skills = []
        for skill in module.get("skills", []):
            skill_name = skill.get("name")
            if skill_name:
                skills.append({
                    "name": skill_name,
                    "expected_output": skill.get("expected_output", []),
                    "expected_input": skill.get("expected_input", []),
                    "expected_input_windows": skill.get("expected_input_windows", []) or [],
                    "expected_input_linux": skill.get("expected_input_linux", []) or [],
                    "skip_if_exists": skill.get("skip_if_exists", []) or [],
                    "prerequisite": skill.get("prerequisite", []) or [],
                    "max_retries": skill.get("max_retries"),
                    "platform": skill.get("platform"),
                })
```

- [ ] **Step 2: Re-run the parser and ordering regressions**

Run: `pytest tests/test_ida_analyze_bin.py::TestParseConfig::test_parse_config_reads_skip_if_exists tests/test_ida_analyze_bin.py::TestSkillOrdering::test_topological_sort_skills_keeps_ilooptype_after_deactivateloop -q`
Expected: PASS.

### Task 3: Capture prefilter and runtime skip behavior with failing tests

**Files:**
- Modify: `tests/test_ida_analyze_bin.py:264`
- Reference: `ida_analyze_bin.py:1624`
- Reference: `ida_analyze_bin.py:1662`

- [ ] **Step 1: Add a prefilter regression that skips before IDA startup when all `skip_if_exists` artifacts exist**

```python
def test_process_binary_skips_when_all_skip_if_exists_artifacts_exist_before_ida_start(
    self,
) -> None:
    with TemporaryDirectory() as temp_dir:
        binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
        binary_dir.mkdir(parents=True, exist_ok=True)
        binary_path = str(binary_dir / "libengine2.so")
        (binary_dir / "ILoopType_DeallocateLoopMode.windows.yaml").write_text(
            "func_name: ILoopType_DeallocateLoopMode\n",
            encoding="utf-8",
        )

        with patch.object(ida_analyze_bin, "start_idalib_mcp") as mock_start_ida:
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=[
                    {
                        "name": "find-CEngineServiceMgr_DeactivateLoop",
                        "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                        "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                        "skip_if_exists": ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
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
```

- [ ] **Step 2: Add an AND-semantics regression so partial matches do not skip**

```python
def test_process_binary_does_not_skip_when_skip_if_exists_artifacts_are_partial(
    self,
) -> None:
    binary_path = str(Path("/tmp/bin/14141/engine/libengine2.so"))
    skills = [
        {
            "name": "find-CEngineServiceMgr_DeactivateLoop",
            "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
            "expected_input": [],
            "skip_if_exists": [
                "ILoopType_DeallocateLoopMode.{platform}.yaml",
                "ILoopType_OtherMode.{platform}.yaml",
            ],
        }
    ]

    with TemporaryDirectory() as temp_dir:
        binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
        binary_dir.mkdir(parents=True, exist_ok=True)
        binary_path = str(binary_dir / "libengine2.so")
        (binary_dir / "ILoopType_DeallocateLoopMode.windows.yaml").write_text(
            "func_name: ILoopType_DeallocateLoopMode\n",
            encoding="utf-8",
        )

        with patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=None) as mock_start_ida:
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=skills,
                agent="codex",
                host="127.0.0.1",
                port=13337,
                ida_args="",
                platform="windows",
                debug=False,
                max_retries=1,
            )

    self.assertEqual((0, 1, 0), (success, fail, skip))
    mock_start_ida.assert_called_once()
```

- [ ] **Step 3: Add a runtime recheck regression so a later skill is skipped after an earlier skill creates the substitute artifact**

```python
def test_process_binary_rechecks_skip_if_exists_before_running_skill(self) -> None:
    with TemporaryDirectory() as temp_dir:
        binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
        binary_dir.mkdir(parents=True, exist_ok=True)
        binary_path = str(binary_dir / "libengine2.so")
        (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
            "func_name: CEngineServiceMgr__MainLoop\n",
            encoding="utf-8",
        )

        def _fake_preprocess(*, skill_name, expected_outputs, **_kwargs):
            if skill_name == "produce-ilooptype":
                Path(expected_outputs[0]).write_text(
                    "func_name: ILoopType_DeallocateLoopMode\n",
                    encoding="utf-8",
                )
                return "success"
            return "failed"

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
            ) as mock_preprocess,
            patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
            patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
        ):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=[
                    {
                        "name": "produce-ilooptype",
                        "expected_output": ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
                        "expected_input": [],
                    },
                    {
                        "name": "find-CEngineServiceMgr_DeactivateLoop",
                        "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                        "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                        "skip_if_exists": ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
                        "prerequisite": ["produce-ilooptype"],
                    },
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

    self.assertEqual((1, 0, 1), (success, fail, skip))
    self.assertEqual(1, mock_preprocess.call_count)
    mock_run_skill.assert_not_called()
```

- [ ] **Step 4: Run the new process-binary regressions and verify they fail before implementation**

Run: `pytest tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_skips_when_all_skip_if_exists_artifacts_exist_before_ida_start tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_does_not_skip_when_skip_if_exists_artifacts_are_partial tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_rechecks_skip_if_exists_before_running_skill -q`
Expected: FAIL because `process_binary()` does not yet inspect `skip_if_exists`.

### Task 4: Implement `skip_if_exists` checks in `process_binary()`

**Files:**
- Modify: `ida_analyze_bin.py:1624`
- Test: `tests/test_ida_analyze_bin.py:264`

- [ ] **Step 1: Add a small helper for `skip_if_exists` path resolution and existence checks near the existing artifact helpers**

```python
def should_skip_skill_for_existing_artifacts(binary_dir, skill, platform):
    """Return resolved skip paths when all configured skip_if_exists artifacts exist."""
    skip_if_exists = list(skill.get("skip_if_exists", []) or [])
    if not skip_if_exists:
        return False, []

    resolved_paths = expand_expected_paths(binary_dir, skip_if_exists, platform)
    return all_expected_outputs_exist(resolved_paths), resolved_paths
```

- [ ] **Step 2: Use the helper during the prefilter pass before appending to `skills_to_process`**

```python
    skills_to_process = []
    for skill_name in sorted_skill_names:
        skill = skill_map[skill_name]
        skill_platform = skill.get("platform")
        if skill_platform and skill_platform != platform:
            print(f"  Skipping skill: {skill_name} (platform '{skill_platform}' != '{platform}')")
            skip_count += 1
            continue
        try:
            expected_outputs = expand_expected_paths(binary_dir, skill["expected_output"], platform)
        except ValueError as e:
            fail_count += 1
            print(f"  Failed: {skill_name} ({e})")
            continue
        if all_expected_outputs_exist(expected_outputs):
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
                skill_max_retries = skill.get("max_retries") or max_retries
                skills_to_process.append((skill_name, expected_outputs, skill_max_retries))
```

- [ ] **Step 3: Recheck the helper immediately before running each queued skill**

```python
        for skill_index, (skill_name, expected_outputs, skill_max_retries) in enumerate(skills_to_process):
            if all_expected_outputs_exist(expected_outputs):
                print(f"  Skipping skill: {skill_name} (all outputs exist)")
                skip_count += 1
                continue

            skill = skill_map[skill_name]
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
                continue

            process, mcp_ok = ensure_mcp_available(
                process, binary_path, host, port, ida_args, debug
            )
```

- [ ] **Step 4: Run the parser and process-binary skip regressions**

Run: `pytest tests/test_ida_analyze_bin.py::TestParseConfig::test_parse_config_reads_skip_if_exists tests/test_ida_analyze_bin.py::TestSkillOrdering::test_topological_sort_skills_keeps_ilooptype_after_deactivateloop tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_skips_when_all_skip_if_exists_artifacts_exist_before_ida_start tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_does_not_skip_when_skip_if_exists_artifacts_are_partial tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_rechecks_skip_if_exists_before_running_skill -q`
Expected: PASS.

### Task 5: Wire the real engine config entry and run the focused regression set

**Files:**
- Modify: `config.yaml:740`
- Test: `tests/test_ida_analyze_bin.py:234`
- Test: `tests/test_ida_analyze_bin.py:264`

- [ ] **Step 1: Add `skip_if_exists` to the concrete engine skill entry**

```yaml
      - name: find-CEngineServiceMgr_DeactivateLoop
        expected_output:
          - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
        skip_if_exists:
          - ILoopType_DeallocateLoopMode.{platform}.yaml
```

- [ ] **Step 2: Run the focused regression command after the config change**

Run: `pytest tests/test_ida_analyze_bin.py::TestParseConfig::test_parse_config_reads_skip_if_exists tests/test_ida_analyze_bin.py::TestSkillOrdering::test_topological_sort_skills_keeps_ilooptype_after_deactivateloop tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_skips_when_all_skip_if_exists_artifacts_exist_before_ida_start tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_does_not_skip_when_skip_if_exists_artifacts_are_partial tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_rechecks_skip_if_exists_before_running_skill -q`
Expected: PASS.

## Self-Review Checklist

- Spec coverage:
  - `skip_if_exists` config field: Task 1, Task 2, Task 5
  - AND semantics: Task 3
  - Prefilter skip before IDA startup: Task 3 and Task 4
  - Runtime recheck before queued skill executes: Task 3 and Task 4
  - No topology change: Task 1 and Task 2
- Placeholder scan:
  - No deferred implementation placeholders remain in this plan
- Type consistency:
  - `skip_if_exists` is consistently modeled as `list[str]`
  - The helper name `should_skip_skill_for_existing_artifacts()` is used consistently across implementation tasks
