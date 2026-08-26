import unittest

from tests.workflow_contract_test_support import load_workflow, step_order, steps_by_id, workflow_job


class TestWarmupIdbWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load_workflow("warmup-idb.yml")
        self.job = workflow_job(self.workflow, "warmup")
        self.steps = steps_by_id(self.job)

    def test_cache_is_published_only_after_required_warmup(self) -> None:
        self.assertEqual("win64", self.job["environment"])
        self.assertEqual(["self-hosted", "windows", "x64"], self.job["runs-on"])
        order = step_order(
            self.job,
            "validate-source",
            "checkout-source",
            "verify-source",
            "setup-uv",
            "prepare-workspace",
            "prune-cache",
            "init-binaries",
            "resolve-ida",
            "probe-cache",
            "warmup-idb",
            "publish-cache",
            "resolve-output",
            "sync-accepted-bin",
        )
        self.assertEqual(sorted(order), order)
        self.assertIn("source_sha must be a full commit SHA", self.steps["validate-source"]["run"])
        self.assertIn("git rev-parse HEAD", self.steps["verify-source"]["run"])
        self.assertIn("idb_cache.py prune", self.steps["prune-cache"]["run"])
        self.assertNotIn("continue-on-error", self.steps["warmup-idb"])
        self.assertEqual("steps.probe-cache.outputs.cache-hit != 'true'", self.steps["warmup-idb"]["if"])
        self.assertIn("warmup_idb.py", self.steps["warmup-idb"]["run"])
        self.assertIn("--force", self.steps["warmup-idb"]["run"])
        self.assertIn("idb_cache.py publish", self.steps["publish-cache"]["run"])
        self.assertEqual("steps.probe-cache.outputs.cache-hit != 'true'", self.steps["publish-cache"]["if"])
        # The accepted-bin sync runs on every warmup path (cache hit or miss) so
        # accepted bin always reflects the binaries the warmup consumed.
        self.assertNotIn("if", self.steps["sync-accepted-bin"])
        self.assertIn("release_workflow.py sync-accepted-bin", self.steps["sync-accepted-bin"]["run"])
        self.assertIn("--persisted-root", self.steps["sync-accepted-bin"]["run"])
        self.assertIn("--repo-root", self.steps["sync-accepted-bin"]["run"])
        self.assertIn("--gamever", self.steps["sync-accepted-bin"]["run"])


if __name__ == "__main__":
    unittest.main()
