import unittest

from tests.workflow_contract_test_support import load_workflow, step_order, steps_by_id, workflow_job


class TestWarmupIdbWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load_workflow("warmup-idb.yml")
        self.job = workflow_job(self.workflow, "warmup")
        self.steps = steps_by_id(self.job)

    def test_reusable_and_manual_contract(self) -> None:
        triggers = self.workflow["on"]
        for trigger in ("workflow_call", "workflow_dispatch"):
            inputs = triggers[trigger]["inputs"]
            self.assertTrue(inputs["gamever"]["required"])
            self.assertTrue(inputs["source_sha"]["required"])
        self.assertIn("inputs.gamever", self.workflow["concurrency"]["group"])
        self.assertFalse(self.workflow["concurrency"]["cancel-in-progress"])
        self.assertEqual(
            "${{ jobs.warmup.outputs.generation }}", triggers["workflow_call"]["outputs"]["generation"]["value"]
        )
        self.assertEqual(
            "${{ jobs.warmup.outputs.cache_key }}", triggers["workflow_call"]["outputs"]["cache_key"]["value"]
        )

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


if __name__ == "__main__":
    unittest.main()
