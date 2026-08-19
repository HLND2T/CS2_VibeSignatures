import unittest

from tests.workflow_contract_test_support import load_workflow, step_order, steps_by_id, workflow_job


class TestPrSelfRunnerWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load_workflow("pr-self-runner.yml")
        self.validate = workflow_job(self.workflow, "validate")
        self.steps = steps_by_id(self.validate)

    def test_trigger_permissions_and_event_job_partition(self) -> None:
        self.assertEqual(
            ["opened", "synchronize", "reopened", "ready_for_review", "closed"],
            self.workflow["on"]["pull_request"]["types"],
        )
        self.assertEqual({"contents": "read"}, self.workflow["permissions"])
        self.assertIn("github.event.action != 'closed'", self.validate["if"])
        self.assertIn("startsWith(github.event.pull_request.head.ref, 'bump-download/')", self.validate["if"])
        self.assertIn("startsWith(github.event.pull_request.head.ref, 'gamesymbols/build/')", self.validate["if"])
        finalize = workflow_job(self.workflow, "finalize-pr-workspace")
        self.assertIn("github.event.action == 'closed'", finalize["if"])
        steps_by_id(finalize)

    def test_unit_and_contract_suites_precede_analysis_and_validation(self) -> None:
        run = self.steps["test-suites"]["run"]
        for suite_name in ("unit", "repository-contract", "redis-integration", "release-integration", "all"):
            self.assertIn(suite_name, run)
        order = step_order(
            self.validate,
            "format",
            "restore-base",
            "test-suites",
            "analyze",
            "build-snapshot",
            "compare-snapshot",
            "build-gamedata",
            "select-sdk",
            "cpp-tests",
            "restore-sdk",
            "mark-success",
            "cleanup",
        )
        self.assertEqual(sorted(order), order)

    def test_submodule_cache_uses_node24_action_and_shallow_update(self) -> None:
        self.assertEqual("actions/cache@v5", self.steps["restore-submodule-cache"]["uses"])
        self.assertIn(
            "git submodule update --init --recursive --depth 1 --jobs 8",
            self.steps["sync-submodules"]["run"],
        )

    def test_pr_validation_uses_one_candidate_and_never_publishes(self) -> None:
        self.assertIn("ACTUAL_CANDIDATE_SNAPSHOT=$candidate", self.steps["build-snapshot"]["run"])
        self.assertIn('-expected "$env:HEAD_SNAPSHOT"', self.steps["compare-snapshot"]["run"])
        gamedata = self.steps["build-gamedata"]["run"]
        self.assertIn('-snapshot "$env:ACTUAL_CANDIDATE_SNAPSHOT"', gamedata)
        self.assertIn("gamedata_candidate.py verify-tracked", gamedata)
        self.assertIn('-session "$env:GAMEDATA_SESSION"', gamedata)
        self.assertIn('-gamever "$env:GAMEVER"', gamedata)
        self.assertIn('-candidate "$env:ACTUAL_CANDIDATE_SNAPSHOT"', gamedata)
        self.assertIn('-configyaml "$env:HEAD_CONFIG"', gamedata)
        self.assertIn('-repo-root "$env:WORKSPACE"', gamedata)
        self.assertIn("-revision HEAD", gamedata)
        self.assertIn("tracked gamedata verification failed", gamedata)
        self.assertLess(
            gamedata.index("gamedata_candidate.py guard"), gamedata.index("gamedata_candidate.py verify-tracked")
        )
        self.assertLess(
            gamedata.index("gamedata_candidate.py verify-tracked"),
            gamedata.index("gamesymbol_candidate.py mark"),
        )
        self.assertIn('-snapshot "$env:ACTUAL_CANDIDATE_SNAPSHOT"', self.steps["cpp-tests"]["run"])
        commands = "\n".join(str(step.get("run", "")) for step in self.validate["steps"])
        self.assertNotIn("gamesymbol_candidate.py publish", commands)
        self.assertNotIn("gamedata_candidate.py publish", commands)
        self.assertNotIn("gh release", commands)
        self.assertNotIn("git commit", commands)
        self.assertNotIn("git push", commands)
        self.assertNotIn("gh pr", commands)

    def test_baseline_bootstrap_has_explicit_contract_and_path_safety_gates(self) -> None:
        run = self.steps["restore-base"]["run"]

        self.assertIn("gamesymbol_snapshot.py check-contract", run)
        self.assertIn("gamesymbol_snapshot.py restore", run)
        self.assertIn("gamesymbol_pr_validation.py invalidate", run)
        self.assertIn("if ($probeExitCode -eq 0)", run)
        self.assertIn("elseif ($probeExitCode -eq 3)", run)
        self.assertIn("Bootstrap cleanup path must not traverse a reparse point", run)
        self.assertIn('Get-ChildItem -LiteralPath $gameRoot -Recurse -File -Filter "*.yaml"', run)
        self.assertNotIn("Remove-Item -LiteralPath $gameRoot -Recurse", run)

    def test_version_config_and_sdk_identity_are_consistent(self) -> None:
        self.assertIn("PR_GAMEVER=$gamever", self.steps["select-version"]["run"])
        self.assertIn("BASE_GAMEVER=$baseGamever", self.steps["base-snapshot"]["run"])
        self.assertIn("HEAD_CONFIG=$headConfig", self.steps["base-snapshot"]["run"])
        self.assertIn('-configyaml "$env:HEAD_CONFIG"', self.steps["analyze"]["run"])
        self.assertIn('-configyaml "$env:HEAD_CONFIG"', self.steps["cpp-tests"]["run"])
        self.assertEqual("always()", self.steps["restore-sdk"]["if"])
        self.assertIn('git -C $sdkPath checkout --detach "$env:SDK_PINNED_SHA"', self.steps["restore-sdk"]["run"])

    def test_closed_event_cleanup_leaves_workspace_before_safe_deletion(self) -> None:
        finalize = workflow_job(self.workflow, "finalize-pr-workspace")
        step = steps_by_id(finalize)["finalize-workspace"]
        run = step["run"]

        self.assertIn("Set-Location $workspaceRoot", run)
        self.assertIn("Remove-Item -LiteralPath $prWorkspace -Recurse -Force", run)
        self.assertLess(run.index("Set-Location $workspaceRoot"), run.index("Remove-Item -LiteralPath $prWorkspace"))
        self.assertIn("Refusing to remove PR workspace because it is a reparse point", run)


if __name__ == "__main__":
    unittest.main()
