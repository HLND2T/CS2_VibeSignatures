import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.model import ChangedPath
from gamesymbol_snapshot_lib.pr_validation import build_invalidation_plan
from tests.gamesymbol_snapshot_test_support import module, skill, write_config


def snapshot(files=None):
    return {"schema_version": 2, "files": files or {}}


def find_source(*references: str) -> str:
    values = ",\n            ".join(repr(reference) for reference in references)
    return f"""LLM_DECOMPILE = [
    {{
        "reference_yaml_paths": [
            {values}
        ],
    }}
]
"""


def source_map(**sources: str) -> dict[str, str]:
    return {f"ida_preprocessor_scripts/{name}.py": source for name, source in sources.items()}


class TestReferenceInvalidation(unittest.TestCase):
    def _contracts(self, root: Path, base_skills, head_skills=None):
        base_config = root / "base.yaml"
        head_config = root / "head.yaml"
        write_config(base_config, [module("server", base_skills, linux=False)])
        write_config(
            head_config,
            [module("server", base_skills if head_skills is None else head_skills, linux=False)],
        )
        return (
            load_contract(base_config, "1", root / "bin"),
            load_contract(head_config, "1", root / "bin"),
        )

    def _plan(self, base, head, changes, root, base_sources, head_sources):
        return build_invalidation_plan(
            base,
            head,
            snapshot(),
            snapshot(),
            changes,
            root,
            base_sources=base_sources,
            head_sources=head_sources,
        )

    def test_modified_reference_uses_base_and_head_consumers(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(
                root,
                [skill("find-old", ["Old.{platform}.yaml"])],
                [skill("find-new", ["New.{platform}.yaml"])],
            )
            reference = "ida_preprocessor_scripts/references/server/Input.windows.yaml"
            plan = self._plan(
                base,
                head,
                [ChangedPath("M", reference, reference)],
                root,
                source_map(**{"find-old": find_source("references/server/Input.{platform}.yaml")}),
                source_map(**{"find-new": find_source("references/server/Input.{platform}.yaml")}),
            )

        self.assertEqual({"server/Old.windows.yaml", "server/New.windows.yaml"}, plan.paths)
        self.assertTrue(any("base=find-old" in reason and "HEAD=find-new" in reason for reason in plan.reasons))

    def test_deleted_reference_uses_base_consumer_after_consumer_is_removed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(
                root,
                [skill("find-old", ["Old.{platform}.yaml"])],
                [],
            )
            reference = "ida_preprocessor_scripts/references/server/Old.windows.yaml"
            plan = self._plan(
                base,
                head,
                [ChangedPath("D", reference, None)],
                root,
                source_map(**{"find-old": find_source("references/server/Old.{platform}.yaml")}),
                {},
            )

        self.assertEqual({"server/Old.windows.yaml"}, plan.paths)
        self.assertFalse(any("broad rebuild" in reason for reason in plan.reasons))

    def test_renamed_reference_uses_old_base_and_new_head_consumers(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(
                root,
                [skill("find-old", ["Old.{platform}.yaml"])],
                [skill("find-new", ["New.{platform}.yaml"])],
            )
            old = "ida_preprocessor_scripts/references/server/Old.windows.yaml"
            new = "ida_preprocessor_scripts/references/server/New.windows.yaml"
            plan = self._plan(
                base,
                head,
                [ChangedPath("R", old, new)],
                root,
                source_map(**{"find-old": find_source("references/server/Old.{platform}.yaml")}),
                source_map(**{"find-new": find_source("references/server/New.{platform}.yaml")}),
            )

        self.assertEqual({"server/Old.windows.yaml", "server/New.windows.yaml"}, plan.paths)
        self.assertIn(f"reference rename: base {old} -> HEAD {new}", plan.reasons)

    def test_added_or_modified_orphan_reference_warns_without_invalidating(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, [skill("find-target", ["Target.{platform}.yaml"])])
            reference = "ida_preprocessor_scripts/references/server/Orphan.windows.yaml"
            expected = {
                "A": f"warning: added orphan reference had no HEAD consumer: {reference}",
                "M": f"warning: modified orphan reference had no HEAD consumer: {reference}",
            }
            for change in (ChangedPath("A", None, reference), ChangedPath("M", reference, reference)):
                with self.subTest(status=change.status):
                    plan = self._plan(base, head, [change], root, {}, {})
                    self.assertEqual(frozenset(), plan.paths)
                    self.assertIn(expected[change.status], plan.reasons)

    def test_modified_reference_without_head_consumer_still_uses_base_consumer(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, [skill("find-old", ["Old.{platform}.yaml"])])
            reference = "ida_preprocessor_scripts/references/server/Input.windows.yaml"
            plan = self._plan(
                base,
                head,
                [ChangedPath("M", reference, reference)],
                root,
                source_map(**{"find-old": find_source("references/server/Input.{platform}.yaml")}),
                source_map(**{"find-old": "TARGET_FUNCTION_NAMES = []\n"}),
            )

        self.assertEqual({"server/Old.windows.yaml"}, plan.paths)
        self.assertIn(f"warning: modified orphan reference had no HEAD consumer: {reference}", plan.reasons)

    def test_deleted_orphan_reference_warns_without_invalidating(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base, head = self._contracts(root, [skill("find-target", ["Target.{platform}.yaml"])])
            reference = "ida_preprocessor_scripts/references/server/Orphan.windows.yaml"
            plan = self._plan(base, head, [ChangedPath("D", reference, None)], root, {}, {})

        self.assertEqual(frozenset(), plan.paths)
        self.assertIn(f"warning: deleted orphan reference had no base consumer: {reference}", plan.reasons)

    def test_reference_basename_in_another_module_does_not_cross_contaminate(self) -> None:
        modules = [
            module("engine", [skill("find-engine", ["Engine.{platform}.yaml"])], linux=False),
            module("server", [skill("find-server", ["Server.{platform}.yaml"])], linux=False),
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_config = root / "base.yaml"
            head_config = root / "head.yaml"
            write_config(base_config, modules)
            write_config(head_config, modules)
            base = load_contract(base_config, "1", root / "bin")
            head = load_contract(head_config, "1", root / "bin")
            sources = source_map(
                **{
                    "find-engine": find_source("references/engine/Same.{platform}.yaml"),
                    "find-server": find_source("references/server/Same.{platform}.yaml"),
                }
            )
            reference = "ida_preprocessor_scripts/references/engine/Same.windows.yaml"
            plan = self._plan(base, head, [ChangedPath("M", reference, reference)], root, sources, sources)

        self.assertEqual({"engine/Engine.windows.yaml"}, plan.paths)

    def test_module_name_template_scopes_consumer_to_changed_module_and_platform(self) -> None:
        modules = [
            module("client", [skill("find-shared", ["Client.{platform}.yaml"])]),
            module("server", [skill("find-shared", ["Server.{platform}.yaml"])]),
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_config = root / "base.yaml"
            head_config = root / "head.yaml"
            write_config(base_config, modules)
            write_config(head_config, modules)
            base = load_contract(base_config, "1", root / "bin")
            head = load_contract(head_config, "1", root / "bin")
            sources = source_map(**{"find-shared": find_source("references/{module_name}/Input.{platform}.yaml")})
            reference = "ida_preprocessor_scripts/references/client/Input.linux.yaml"
            plan = self._plan(
                base,
                head,
                [ChangedPath("A", None, reference)],
                root,
                sources,
                sources,
            )

        self.assertEqual({"client/Client.linux.yaml"}, plan.paths)
        self.assertTrue(any("find-shared[client/linux]" in reason for reason in plan.reasons))

    def test_pr_605_shaped_touch_change_does_not_invalidate_sdl3(self) -> None:
        base_modules = [
            module("SDL3", [skill("find-sdl", ["Mouse.windows.yaml"])], linux=False),
            module(
                "server",
                [
                    skill("find-old-touch", ["Start.windows.yaml", "End.windows.yaml"]),
                    skill("find-process", ["Touch.windows.yaml"], expected_input=["Start.windows.yaml"]),
                    skill("find-later", ["Later.windows.yaml"]),
                ],
                linux=False,
            ),
        ]
        head_modules = [
            base_modules[0],
            module(
                "server",
                [
                    skill("find-start", ["Start.windows.yaml"]),
                    skill("find-process", ["Touch.windows.yaml"], expected_input=["Start.windows.yaml"]),
                    skill("find-end", ["End.windows.yaml"]),
                    skill("find-later", ["Later.windows.yaml"]),
                ],
                linux=False,
            ),
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_config = root / "base.yaml"
            head_config = root / "head.yaml"
            write_config(base_config, base_modules)
            write_config(head_config, head_modules)
            base = load_contract(base_config, "1", root / "bin")
            head = load_contract(head_config, "1", root / "bin")
            old_reference = "ida_preprocessor_scripts/references/server/OldTouch.windows.yaml"
            new_reference = "ida_preprocessor_scripts/references/server/NewTouch.windows.yaml"
            base_sources = source_map(**{"find-old-touch": find_source("references/server/OldTouch.{platform}.yaml")})
            head_sources = source_map(**{"find-start": find_source("references/server/NewTouch.{platform}.yaml")})
            plan = build_invalidation_plan(
                base,
                head,
                snapshot({"server/Start.windows.yaml": {"value": 1}}),
                snapshot({"server/Start.windows.yaml": {"value": 2}}),
                [
                    ChangedPath("M", "configs/1.yaml", "configs/1.yaml"),
                    ChangedPath("D", old_reference, None),
                    ChangedPath("A", None, new_reference),
                ],
                root,
                base_sources=base_sources,
                head_sources=head_sources,
            )

        self.assertFalse(any(path.startswith("SDL3/") for path in plan.paths))
        self.assertFalse(any("broad rebuild" in reason for reason in plan.reasons))
        self.assertNotIn("server/Later.windows.yaml", plan.paths)


if __name__ == "__main__":
    unittest.main()
