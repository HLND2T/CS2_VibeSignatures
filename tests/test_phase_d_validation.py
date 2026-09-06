import copy
import tempfile
import unittest
from pathlib import Path

from phase_d_validation import compare_inventories, experimental_plan, synthetic_base
from trusted_artifact_pr import GitTreeRepository, _digest


class PhaseDValidationTests(unittest.TestCase):
    def test_strategy_trial_preserves_the_original_plan_and_closure(self):
        original = {"execution_strategy": "fresh-full-v1", "execute_nodes": ["a"]}
        original["plan_sha256"] = _digest("trusted-pr-plan", original)
        before = copy.deepcopy(original)
        trial = experimental_plan(original, "base-inherited-selected-v1")
        self.assertEqual(before, original)
        self.assertEqual(["a"], trial["execute_nodes"])
        self.assertNotEqual(original["plan_sha256"], trial["plan_sha256"])
        unsigned = {key: value for key, value in trial.items() if key != "plan_sha256"}
        self.assertEqual(_digest("trusted-pr-plan", unsigned), trial["plan_sha256"])
        trial["execute_nodes"].append("b")
        self.assertEqual(["a"], original["execute_nodes"])

    def test_unknown_trial_strategy_is_rejected(self):
        with self.assertRaises(ValueError):
            experimental_plan({}, "unknown")

    def test_inventory_comparison_rejects_missing_extra_and_different_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            full, selected = root / "full", root / "selected"
            full.mkdir()
            selected.mkdir()
            (full / "a.yaml").write_bytes(b"expected")
            for filename, payload in (("b.yaml", b"expected"), ("a.yaml", b"drift")):
                candidate = selected / filename
                candidate.write_bytes(payload)
                with self.assertRaisesRegex(RuntimeError, "inventory"):
                    compare_inventories(full, selected)
                candidate.unlink()
            (selected / "a.yaml").write_bytes(b"expected")
            self.assertEqual(1, compare_inventories(full, selected)["file_count"])

    def test_synthetic_base_uses_git_objects_without_mutating_checkout_or_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = GitTreeRepository(root)
            repo.run("init")
            repo.run("config", "user.name", "Phase D Test")
            repo.run("config", "user.email", "phase-d@example.invalid")
            (root / "source.py").write_bytes(b"value = 1\n")
            repo.run("add", "source.py")
            repo.run("commit", "-m", "fixture")
            source = repo.resolve_commit("HEAD")
            index_tree = repo.run("write-tree")
            base = synthetic_base(repo, source, "source.py", b"value = 0\n", root / "scratch")
            self.assertEqual(b"value = 0\n", repo.read(base, "source.py"))
            self.assertEqual(b"value = 1\n", (root / "source.py").read_bytes())
            self.assertEqual(index_tree, repo.run("write-tree"))
            self.assertEqual(source, repo.resolve_commit("HEAD"))
