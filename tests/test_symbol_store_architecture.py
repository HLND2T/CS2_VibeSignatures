import ast
import unittest
from pathlib import Path


PRODUCTION_CONSUMERS = (
    "update_gamedata.py",
    "gamedata_symbol_data.py",
    "cpp_tests_util.py",
    "run_cpp_tests.py",
)

POST_CHANGE_CALLERS = (
    "create-preprocessor-scripts",
    "create-cpp-tests",
    "create-agent-skill-fallback",
    "rename-preprocessor-scripts",
)


def _parse(path: str) -> ast.Module:
    return ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)


def _qualified_name(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _calls(path: str) -> list[tuple[str, int, ast.Call]]:
    calls = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Call):
            calls.append((_qualified_name(node.func) or "<dynamic>", node.lineno, node))
    return calls


def _imported_names(path: str) -> list[tuple[str, int]]:
    imported = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imported.extend((alias.name, node.lineno) for alias in node.names)
    return imported


def _argparse_options(path: str) -> list[tuple[str, int]]:
    options = []
    for call_name, line, node in _calls(path):
        if not call_name.endswith(".add_argument"):
            continue
        options.extend(
            (arg.value, line) for arg in node.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        )
    return options


class TestSymbolStoreArchitecture(unittest.TestCase):
    def test_production_consumers_use_snapshot_store_calls(self) -> None:
        expected_calls = {
            "update_gamedata.py": "open_snapshot_store",
            "gamedata_symbol_data.py": "store.get",
            "cpp_tests_util.py": "symbol_store.glob_module",
            "run_cpp_tests.py": "open_snapshot_store",
        }
        for path, expected_call in expected_calls.items():
            with self.subTest(path=path):
                call_names = [call_name for call_name, _line, _node in _calls(path)]
                self.assertIn(expected_call, call_names, f"{path}: missing required call {expected_call}")

        for path in ("update_gamedata.py", "run_cpp_tests.py"):
            with self.subTest(path=path, option="-bindir"):
                locations = [f"{path}:{line}" for option, line in _argparse_options(path) if option == "-bindir"]
                self.assertEqual([], locations, f"forbidden direct bin CLI boundary: {locations}")

    def test_directory_backend_and_direct_yaml_calls_are_absent(self) -> None:
        for path in PRODUCTION_CONSUMERS:
            with self.subTest(path=path, dependency="DirectorySymbolStore"):
                locations = [f"{path}:{line}" for name, line in _imported_names(path) if name == "DirectorySymbolStore"]
                self.assertEqual([], locations, f"forbidden directory backend import: {locations}")

        forbidden_calls = {
            "update_gamedata.py": {"load_yaml_data"},
            "cpp_tests_util.py": {"module_dir.glob", "yaml.safe_load"},
        }
        for path, forbidden in forbidden_calls.items():
            with self.subTest(path=path):
                locations = [
                    f"{path}:{line}:{call_name}" for call_name, line, _node in _calls(path) if call_name in forbidden
                ]
                self.assertEqual([], locations, f"forbidden production dependency calls: {locations}")

    def test_create_pr_delegates_post_change_delivery_to_ci(self) -> None:
        skill_root = Path(".claude/skills")
        create_pr = (skill_root / "create-pr/SKILL.md").read_text(encoding="utf-8")
        lifecycle = (
            "/prepare-post-change-candidate",
            "/post-change-validation",
            "/publish-post-change-candidate",
        )

        for skill_name in lifecycle:
            self.assertNotIn(skill_name, create_pr)
        self.assertIn("git diff --cached --quiet", create_pr)
        self.assertIn("git diff --cached --name-only", create_pr)
        self.assertIn("git commit", create_pr)
        self.assertIn("git push -u origin", create_pr)
        self.assertIn("gh pr create", create_pr)
        self.assertIn(".claude/skills/create-pr/scripts/classify_delivery.py", create_pr)
        self.assertIn("LIFECYCLE=0", create_pr)
        self.assertIn("pr-self-runner.yml", create_pr)
        self.assertIn("Candidate preparation, C++ validation", create_pr)

        for caller_name in POST_CHANGE_CALLERS:
            with self.subTest(caller=caller_name):
                caller = (skill_root / caller_name / "SKILL.md").read_text(encoding="utf-8")
                self.assertIn("/create-pr", caller)
                for lifecycle_skill in lifecycle:
                    self.assertNotIn(lifecycle_skill, caller)

    def test_pr_workflow_owns_post_change_delivery(self) -> None:
        workflow = Path(".github/workflows/pr-self-runner.yml").read_text(encoding="utf-8")
        for command in (
            "gamesymbol_candidate.py build",
            "gamedata_candidate.py build",
            "run_cpp_tests.py",
            "gamesymbol_candidate.py publish",
            "gamedata_candidate.py publish",
        ):
            self.assertIn(command, workflow)


if __name__ == "__main__":
    unittest.main()
