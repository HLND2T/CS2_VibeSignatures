import ast
import unittest
from pathlib import Path

import ida_analyze_bin
import ida_analyze_util
from gamever_baseline import gamever_order_key


CONFIG_ROOT = Path("configs")
PREPROCESSOR_ROOT = Path("ida_preprocessor_scripts")


def _literal_assignment(script_path, assignment_name):
    tree = ast.parse(script_path.read_text(encoding="utf-8"), filename=str(script_path))
    for node in tree.body:
        value = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == assignment_name for target in node.targets
        ):
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == assignment_name
        ):
            value = node.value
        if value is None:
            continue
        try:
            return ast.literal_eval(value)
        except (TypeError, ValueError, SyntaxError) as exc:
            raise AssertionError(
                f"{script_path}:{node.lineno}: {assignment_name} must remain statically inspectable"
            ) from exc
    return []


def _required_xref_vtable_artifacts_by_skill():
    dependencies = {}
    for script_path in sorted(PREPROCESSOR_ROOT.glob("find-*.py")):
        relation_map = {
            func_name: vtable_ref
            for func_name, vtable_ref in _literal_assignment(script_path, "FUNC_VTABLE_RELATIONS")
            if ida_analyze_util._is_vtable_artifact_stem(vtable_ref)
        }
        required_artifacts = {
            relation_map[xref_spec.get("func_name")]
            for xref_spec in _literal_assignment(script_path, "FUNC_XREFS")
            if isinstance(xref_spec, dict) and xref_spec.get("func_name") in relation_map
        }
        if required_artifacts:
            dependencies[script_path.stem] = required_artifacts
    return dependencies


def _declared_expected_input_names(skill, platform):
    declared_inputs = list(skill.get("expected_input", []))
    declared_inputs.extend(skill.get(f"expected_input_{platform}", []))
    return {
        str(artifact_path).replace("{platform}", platform).replace("\\", "/").rsplit("/", 1)[-1]
        for artifact_path in declared_inputs
    }


def _source_yaml_stems_by_skill():
    stems = {}
    for script_path in sorted(PREPROCESSOR_ROOT.glob("find-*.py")):
        stem = _literal_assignment(script_path, "SOURCE_YAML_STEM")
        if isinstance(stem, str) and stem:
            stems[script_path.stem] = stem
    return stems


def _maintained_config_path():
    configs = [path for path in CONFIG_ROOT.glob("*.yaml") if gamever_order_key(path.stem) is not None]
    return max(configs, key=lambda path: gamever_order_key(path.stem))


class TestConfigSchedulingDependencies(unittest.TestCase):
    def test_all_configs_have_satisfied_dependency_graphs(self) -> None:
        for config_path in sorted(CONFIG_ROOT.glob("*.yaml")):
            with self.subTest(config=config_path.name):
                modules = ida_analyze_bin.parse_config(config_path)
                gaps = []
                for platform in ("windows", "linux"):
                    gaps.extend(ida_analyze_bin.find_module_skill_dependency_gaps(modules, platform))
                self.assertEqual([], gaps)
                ida_analyze_bin.validate_module_skill_dependencies(modules)

    def test_func_xref_vtable_artifacts_are_declared_as_expected_inputs(self) -> None:
        required_artifacts_by_skill = _required_xref_vtable_artifacts_by_skill()
        missing_declarations = []

        for config_path in sorted(CONFIG_ROOT.glob("*.yaml")):
            for module in ida_analyze_bin.parse_config(config_path):
                for skill in module["skills"]:
                    required_artifacts = required_artifacts_by_skill.get(skill["name"], set())
                    for platform in ("windows", "linux"):
                        if skill.get("platform") not in (None, platform):
                            continue
                        declared_inputs = _declared_expected_input_names(skill, platform)
                        for artifact_stem in sorted(required_artifacts):
                            artifact_name = f"{artifact_stem}.{platform}.yaml"
                            if artifact_name not in declared_inputs:
                                missing_declarations.append(
                                    f"{config_path}:{module['name']}/{skill['name']} "
                                    f"[{platform}] missing expected_input: {artifact_name}"
                                )

        self.assertEqual([], missing_declarations)

    def test_source_yaml_stem_is_declared_as_expected_input_in_maintained_config(self) -> None:
        # Scripts are shared across GAMEVERs but only the maintained config may be edited, so a
        # re-anchored SOURCE_YAML_STEM (e.g. #1064 moving OnSaveGame to StreamEntitiesToFile)
        # must be mirrored there or the scheduler may run the skill before its host exists.
        source_stems = _source_yaml_stems_by_skill()
        config_path = _maintained_config_path()
        missing_declarations = []

        for module in ida_analyze_bin.parse_config(config_path):
            for skill in module["skills"]:
                source_stem = source_stems.get(skill["name"])
                if source_stem is None:
                    continue
                for platform in ("windows", "linux"):
                    if skill.get("platform") not in (None, platform):
                        continue
                    artifact_name = f"{source_stem}.{platform}.yaml"
                    if artifact_name not in _declared_expected_input_names(skill, platform):
                        missing_declarations.append(
                            f"{config_path}:{module['name']}/{skill['name']} "
                            f"[{platform}] missing expected_input: {artifact_name}"
                        )

        self.assertEqual([], missing_declarations)


if __name__ == "__main__":
    unittest.main()
