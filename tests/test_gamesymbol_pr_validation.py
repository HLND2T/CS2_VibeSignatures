import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.model import ChangedPath
from gamesymbol_snapshot_lib.pr_validation import build_invalidation_plan, required_source_index_sides
from tests.gamesymbol_snapshot_test_support import module, skill, write_config


def snapshot(files):
    return {"schema_version": 2, "files": files}


class TestInvalidationPlan(unittest.TestCase):
    def _contracts(self, root: Path, modules, head_modules=None):
        base_config = root / "base.yaml"
        head_config = root / "head.yaml"
        write_config(base_config, modules)
        write_config(head_config, head_modules or modules)
        return (
            load_contract(base_config, "1", root / "bin"),
            load_contract(head_config, "1", root / "bin"),
        )

    def test_source_index_sides_follow_git_change_semantics(self) -> None:
        reference = "ida_preprocessor_scripts/references/server/Input.windows.yaml"
        preprocessor = "ida_preprocessor_scripts/find-target.py"
        cases = (
            (ChangedPath("M", reference, reference), (True, True)),
            (ChangedPath("D", preprocessor, None), (True, False)),
            (ChangedPath("A", None, reference), (False, True)),
            (ChangedPath("R", preprocessor, "ida_preprocessor_scripts/find-renamed.py"), (True, True)),
            (
                ChangedPath("C", reference, "ida_preprocessor_scripts/references/server/Copy.windows.yaml"),
                (False, True),
            ),
            (ChangedPath("M", "README.md", "README.md"), (False, False)),
        )

        for change, expected in cases:
            with self.subTest(status=change.status, old_path=change.old_path, new_path=change.new_path):
                self.assertEqual(expected, required_source_index_sides([change]))

    def test_unrelated_change_does_not_scan_workspace_sources(self) -> None:
        modules = [module("server", [skill("find-target", ["Target.{platform}.yaml"])], linux=False)]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            unchanged = snapshot({"server/Target.windows.yaml": {"value": 1}})
            with patch("gamesymbol_snapshot_lib.pr_validation.workspace_python_sources") as workspace_sources:
                plan = build_invalidation_plan(
                    base,
                    head,
                    unchanged,
                    unchanged,
                    [ChangedPath("M", "README.md", "README.md")],
                    root,
                )

        self.assertEqual(frozenset(), plan.paths)
        workspace_sources.assert_not_called()

    def test_snapshot_change_invalidates_whole_owner_and_downstream_closure(self) -> None:
        modules = [
            module(
                "server",
                [
                    skill("find-producer", ["A.{platform}.yaml", "B.{platform}.yaml"]),
                    skill("find-consumer", ["C.{platform}.yaml"], expected_input=["A.{platform}.yaml"]),
                ],
                linux=False,
            )
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            plan = build_invalidation_plan(
                base,
                head,
                snapshot({"server/A.windows.yaml": {"value": 1}}),
                snapshot({"server/A.windows.yaml": {"value": 2}}),
                [],
                root,
            )

        self.assertEqual(
            {
                "server/A.windows.yaml",
                "server/B.windows.yaml",
                "server/C.windows.yaml",
            },
            plan.paths,
        )

    def test_preprocessor_change_invalidates_matching_skill_when_snapshot_is_unchanged(self) -> None:
        modules = [module("server", [skill("find-target", ["Target.{platform}.yaml"])], linux=False)]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            plan = build_invalidation_plan(
                base,
                head,
                snapshot({"server/Target.windows.yaml": {"value": 1}}),
                snapshot({"server/Target.windows.yaml": {"value": 1}}),
                ["ida_preprocessor_scripts/find-target.py"],
                root,
            )

        self.assertEqual({"server/Target.windows.yaml"}, plan.paths)

    def test_core_runtime_change_keeps_snapshot_when_output_contract_matches(self) -> None:
        modules = [module("server", [skill("find-target", ["Target.{platform}.yaml"])], linux=False)]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            unchanged = snapshot({"server/Target.windows.yaml": {"value": 1}})
            plan = build_invalidation_plan(base, head, unchanged, unchanged, ["ida_analyze_bin.py"], root)

        self.assertEqual(frozenset(), plan.paths)
        self.assertEqual((), plan.reasons)

    def test_output_contract_version_change_invalidates_all_nodes(self) -> None:
        modules = [
            module(
                "server",
                [skill("find-a", ["A.{platform}.yaml"]), skill("find-b", ["B.{platform}.yaml"])],
                linux=False,
            )
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            head = replace(head, analysis_output_contract_version=2)
            unchanged = snapshot(
                {
                    "server/A.windows.yaml": {"value": 1},
                    "server/B.windows.yaml": {"value": 1},
                }
            )
            plan = build_invalidation_plan(base, head, unchanged, unchanged, [], root)

        self.assertEqual(set(unchanged["files"]), plan.paths)
        self.assertIn("analysis output contract version: 1 -> 2", plan.reasons)

    def test_config_change_and_deleted_output_remove_base_and_head_paths(self) -> None:
        base_modules = [module("server", [skill("find-target", ["Old.{platform}.yaml"])], linux=False)]
        head_modules = [module("server", [skill("find-target", ["New.{platform}.yaml"])], linux=False)]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, base_modules, head_modules)
            plan = build_invalidation_plan(
                base,
                head,
                snapshot({"server/Old.windows.yaml": {"value": 1}}),
                snapshot({"server/New.windows.yaml": {"value": 1}}),
                ["config.yaml"],
                root,
            )

        self.assertEqual({"server/Old.windows.yaml", "server/New.windows.yaml"}, plan.paths)

    def test_config_insertion_keeps_later_fingerprint_stable_and_does_not_invalidate_other_modules(self) -> None:
        base_modules = [
            module("SDL3", [skill("find-sdl", ["SDL.{platform}.yaml"])], linux=False),
            module(
                "server",
                [skill("find-a", ["A.{platform}.yaml"]), skill("find-b", ["B.{platform}.yaml"])],
                linux=False,
            ),
        ]
        head_modules = [
            base_modules[0],
            module(
                "server",
                [
                    skill("find-a", ["A.{platform}.yaml"]),
                    skill("find-inserted", ["Inserted.{platform}.yaml"]),
                    skill("find-b", ["B.{platform}.yaml"]),
                ],
                linux=False,
            ),
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, base_modules, head_modules)
            base_b = next(node for node in base.nodes.values() if node.skill_name == "find-b")
            head_b = next(node for node in head.nodes.values() if node.skill_name == "find-b")
            unchanged = snapshot(
                {
                    "SDL3/SDL.windows.yaml": {"value": 1},
                    "server/A.windows.yaml": {"value": 1},
                    "server/B.windows.yaml": {"value": 1},
                }
            )
            plan = build_invalidation_plan(
                base,
                head,
                unchanged,
                unchanged,
                [ChangedPath("M", "configs/1.yaml", "configs/1.yaml")],
                root,
            )

        self.assertEqual(base_b.fingerprint, head_b.fingerprint)
        self.assertEqual({"server/Inserted.windows.yaml"}, plan.paths)

    def test_other_game_version_config_change_is_ignored(self) -> None:
        modules = [module("server", [skill("find-target", ["Target.{platform}.yaml"])], linux=False)]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            unchanged = snapshot({"server/Target.windows.yaml": {"value": 1}})
            plan = build_invalidation_plan(
                base,
                head,
                unchanged,
                unchanged,
                [ChangedPath("M", "configs/2.yaml", "configs/2.yaml")],
                root,
            )

        self.assertEqual(frozenset(), plan.paths)

    def test_same_basename_in_other_module_is_not_invalidated(self) -> None:
        modules = [
            module("engine", [skill("find-engine", ["Same.{platform}.yaml"])], linux=False),
            module("server", [skill("find-server", ["Same.{platform}.yaml"])], linux=False),
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            plan = build_invalidation_plan(
                base,
                head,
                snapshot(
                    {
                        "engine/Same.windows.yaml": {"value": 1},
                        "server/Same.windows.yaml": {"value": 1},
                    }
                ),
                snapshot(
                    {
                        "engine/Same.windows.yaml": {"value": 2},
                        "server/Same.windows.yaml": {"value": 1},
                    }
                ),
                [],
                root,
            )

        self.assertEqual({"engine/Same.windows.yaml"}, plan.paths)

    def test_shared_helper_change_invalidates_transitive_importers(self) -> None:
        modules = [module("server", [skill("find-target", ["Target.{platform}.yaml"])], linux=False)]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "ida_preprocessor_scripts"
            scripts.mkdir()
            (scripts / "_helper.py").write_text("VALUE = 1\n", encoding="utf-8")
            (scripts / "find-target.py").write_text(
                "from ida_preprocessor_scripts._helper import VALUE\n", encoding="utf-8"
            )
            base, head = self._contracts(root, modules)
            plan = build_invalidation_plan(
                base,
                head,
                snapshot({"server/Target.windows.yaml": {"value": 1}}),
                snapshot({"server/Target.windows.yaml": {"value": 1}}),
                ["ida_preprocessor_scripts/_helper.py"],
                root,
            )

        self.assertEqual({"server/Target.windows.yaml"}, plan.paths)

    def test_reference_change_invalidates_source_consumer(self) -> None:
        modules = [module("server", [skill("find-target", ["Target.{platform}.yaml"])], linux=False)]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "ida_preprocessor_scripts"
            scripts.mkdir()
            (scripts / "find-target.py").write_text(
                'LLM_DECOMPILE = [{"reference_yaml_paths": ["references/server/Input.{platform}.yaml"]}]\n',
                encoding="utf-8",
            )
            base, head = self._contracts(root, modules)
            plan = build_invalidation_plan(
                base,
                head,
                snapshot({"server/Target.windows.yaml": {"value": 1}}),
                snapshot({"server/Target.windows.yaml": {"value": 1}}),
                ["ida_preprocessor_scripts/references/server/Input.windows.yaml"],
                root,
            )

        self.assertEqual({"server/Target.windows.yaml"}, plan.paths)

    def test_unknown_analysis_source_uses_broad_rebuild(self) -> None:
        modules = [
            module(
                "server",
                [skill("find-a", ["A.{platform}.yaml"]), skill("find-b", ["B.{platform}.yaml"])],
                linux=False,
            )
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "ida_preprocessor_scripts").mkdir()
            base, head = self._contracts(root, modules)
            unchanged = {
                "server/A.windows.yaml": {"value": 1},
                "server/B.windows.yaml": {"value": 1},
            }
            plan = build_invalidation_plan(
                base,
                head,
                snapshot(unchanged),
                snapshot(unchanged),
                ["ida_preprocessor_scripts/_unknown.py"],
                root,
            )

        self.assertEqual(set(unchanged), plan.paths)

    def test_agent_prompt_change_uses_broad_rebuild(self) -> None:
        modules = [
            module(
                "server",
                [skill("find-a", ["A.{platform}.yaml"]), skill("find-b", ["B.{platform}.yaml"])],
                linux=False,
            )
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, modules)
            unchanged = {
                "server/A.windows.yaml": {"value": 1},
                "server/B.windows.yaml": {"value": 1},
            }
            plan = build_invalidation_plan(
                base,
                head,
                snapshot(unchanged),
                snapshot(unchanged),
                [".claude/agents/sig-finder.md"],
                root,
            )

        self.assertEqual(set(unchanged), plan.paths)


if __name__ == "__main__":
    unittest.main()
