import unittest

from tests.workflow_contract_test_support import load_workflow, step_order, steps_by_id, workflow_job


class TestPrSelfRunnerWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load_workflow("pr-self-runner.yml")
        self.preflight = workflow_job(self.workflow, "pr-preflight")
        self.warmup = workflow_job(self.workflow, "pr-warmup-idb")
        self.full = workflow_job(self.workflow, "pr-validate-full")
        self.terminal = workflow_job(self.workflow, "pr-validate")
        self.steps = steps_by_id(self.full)

    def test_triggers_permissions_and_stable_terminal_check(self) -> None:
        self.assertEqual(
            ["opened", "synchronize", "reopened", "ready_for_review", "closed"],
            self.workflow["on"]["pull_request"]["types"],
        )
        self.assertNotIn("workflow_dispatch", self.workflow["on"])
        self.assertEqual({"contents": "read"}, self.workflow["permissions"])
        self.assertEqual({"pull-requests": "read"}, self.full["permissions"])
        self.assertEqual("pr-validate", self.terminal["name"])
        self.assertEqual(["pr-preflight", "pr-validate-full"], self.terminal["needs"])
        self.assertNotIn("pr-published-recheck", self.workflow["jobs"])
        terminal_run = steps_by_id(self.terminal)["terminal"]["run"]
        self.assertIn('PREFLIGHT_RESULT" == "success', terminal_run)
        self.assertIn('FULL_RESULT" == "success', terminal_run)
        self.assertNotIn("published-recheck", terminal_run)
        self.assertNotIn("RECHECK_RESULT", terminal_run)

    def test_event_normalization_and_phase_separated_concurrency(self) -> None:
        group = self.workflow["concurrency"]["group"]
        self.assertIn("github.event.pull_request.number", group)
        self.assertNotIn("inputs.pr_number", group)
        self.assertNotIn("recheck-{0}", group)
        self.assertNotIn("inputs.expected_head_sha", group)
        self.assertTrue(self.workflow["concurrency"]["cancel-in-progress"])
        self.assertNotIn("github.event_name == 'workflow_dispatch'", self.preflight["if"])
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", self.preflight["if"])
        preflight_steps = steps_by_id(self.preflight)
        self.assertNotIn("validate-dispatch-inputs", preflight_steps)
        self.assertNotIn("classify-published", preflight_steps)
        self.assertNotIn("dispatch", preflight_steps)
        self.assertNotIn("dispatch-merge", preflight_steps)

    def test_warmup_and_full_validation_only_run_on_full_path(self) -> None:
        self.assertEqual("pr-preflight", self.warmup["needs"])
        self.assertEqual("./.github/workflows/warmup-idb.yml", self.warmup["uses"])
        self.assertIn("validation_path == 'full'", self.warmup["if"])
        self.assertEqual("${{ needs.pr-preflight.outputs.gamever }}", self.warmup["with"]["gamever"])
        self.assertEqual("${{ needs.pr-preflight.outputs.source_sha }}", self.warmup["with"]["source_sha"])
        self.assertEqual(["pr-preflight", "pr-warmup-idb"], self.full["needs"])
        self.assertIn("needs.pr-preflight.outputs.validation_path == 'full'", self.full["if"])
        self.assertIn("needs.pr-warmup-idb.result == 'success'", self.full["if"])

    def test_full_validation_build_test_stage_order(self) -> None:
        test_run = self.steps["test-suites"]["run"]
        for suite_name in ("unit", "repository-contract", "redis-integration", "release-integration", "all"):
            self.assertIn(suite_name, test_run)
        order = step_order(
            self.full,
            "format",
            "restore-base",
            "test-suites",
            "analyze",
            "build-snapshot",
            "build-gamedata",
            "select-sdk",
            "cpp-tests",
            "restore-sdk",
            "mark-success",
            "stage-yaml",
            "cleanup",
        )
        self.assertEqual(sorted(order), order)
        self.assertNotIn("compare-snapshot", self.steps)
        self.assertNotIn("publication", self.steps)
        self.assertNotIn("push-publication", self.steps)
        self.assertNotIn("dispatch-published-recheck", self.steps)

    def test_candidate_and_gamedata_are_built_and_validated(self) -> None:
        build = self.steps["build-snapshot"]["run"]
        self.assertIn("ACTUAL_CANDIDATE_SNAPSHOT=$candidate", build)
        self.assertIn("SNAPSHOT_SHA256=$snapshotSha256", build)
        self.assertIn("gamedata-generators", build)
        gamedata = self.steps["build-gamedata"]["run"]
        self.assertIn('-snapshot "$env:ACTUAL_CANDIDATE_SNAPSHOT"', gamedata)
        self.assertIn('-modulesdir "$env:GAMEDATA_MODULES_DIR"', gamedata)
        self.assertIn("GAMEDATA_MANIFEST_SHA256=$gamedataManifestSha256", gamedata)
        self.assertNotIn("gamedata_candidate.py verify-tracked", gamedata)
        self.assertIn('-snapshot "$env:ACTUAL_CANDIDATE_SNAPSHOT"', self.steps["cpp-tests"]["run"])
        self.assertNotIn("gamesymbol_candidate.py publish", build)
        self.assertNotIn("gamedata_candidate.py publish", gamedata)

    def test_submodule_cache_and_bump_partition_are_preserved(self) -> None:
        self.assertEqual("actions/cache@v5", self.steps["restore-submodule-cache"]["uses"])
        self.assertIn(
            "git submodule update --init --recursive --depth 1 --jobs 8",
            self.steps["sync-submodules"]["run"],
        )
        self.assertIn("git ls-tree HEAD", self.steps["submodule-cache-key"]["run"])
        self.assertNotIn("submodule status --recursive", self.steps["submodule-cache-key"]["run"])
        condition = "steps.detect-bump.outputs.is-bump != 'true'"
        for step_id in ("submodule-cache-key", "restore-submodule-cache", "sync-submodules"):
            self.assertEqual(condition, self.steps[step_id]["if"])
        order = step_order(
            self.full,
            "checkout-merge",
            "verify-source",
            "detect-bump",
            "submodule-cache-key",
            "restore-submodule-cache",
            "sync-submodules",
            "format",
            "bump-light",
        )
        self.assertEqual(sorted(order), order)

    def test_baseline_cache_version_and_sdk_contracts_are_preserved(self) -> None:
        restore = self.steps["restore-base"]["run"]
        self.assertIn("gamesymbol_snapshot.py check-contract", restore)
        self.assertIn("gamesymbol_snapshot.py restore", restore)
        self.assertIn("gamesymbol_pr_validation.py invalidate", restore)
        self.assertIn("Bootstrap cleanup path must not traverse a reparse point", restore)
        self.assertNotIn("Remove-Item -LiteralPath $gameRoot -Recurse", restore)
        self.assertIn("idb_cache.py restore", self.steps["restore-idb-cache"]["run"])
        self.assertIn("IDB_CACHE_GENERATION", self.steps["restore-idb-cache"]["run"])
        self.assertIn("--cache-key", self.steps["restore-idb-cache"]["run"])
        self.assertIn("PR_GAMEVER=$gamever", self.steps["select-version"]["run"])
        self.assertIn("HEAD_CONFIG=$headConfig", self.steps["base-snapshot"]["run"])
        self.assertIn('Export-GitBlob "HEAD" "configs/$validationGamever.yaml"', self.steps["base-snapshot"]["run"])
        self.assertIn("-require_warm_idb", self.steps["analyze"]["run"])
        self.assertEqual("always()", self.steps["restore-sdk"]["if"])
        self.assertIn('git -C $sdkPath checkout --detach "$env:SDK_PINNED_SHA"', self.steps["restore-sdk"]["run"])

    def test_analyzed_yaml_staging_is_final_validation_output(self) -> None:
        run = self.steps["stage-yaml"]["run"]
        self.assertIn('Join-Path $env:PERSISTED_WORKSPACE "pr-yaml-staging"', run)
        self.assertIn('robocopy $gameRoot $runStaging "*.yaml" /S', run)
        self.assertIn("gamever.txt", run)
        order = step_order(self.full, "mark-success", "stage-yaml", "cleanup")
        self.assertEqual(sorted(order), order)
        self.assertNotIn("select-publication-head", self.steps)

    def test_full_checkout_uses_normalized_preflight_values(self) -> None:
        checkout = self.steps["checkout-merge"]
        self.assertEqual("actions/checkout@v5", checkout["uses"])
        self.assertEqual("${{ needs.pr-preflight.outputs.source_sha }}", checkout["with"]["ref"])
        self.assertEqual(0, checkout["with"]["fetch-depth"])
        self.assertIn("PR_SOURCE_SHA", self.steps["verify-source"]["run"])
        self.assertNotIn("PR_HEAD_SHA", self.full["env"])
        self.assertEqual("${{ needs.pr-preflight.outputs.head_ref }}", self.full["env"]["PR_HEAD_REF"])

    def test_untrusted_pr_fields_are_passed_via_environment(self) -> None:
        identify = steps_by_id(self.preflight)["pull-request"]
        detect = self.steps["detect-bump"]
        for step in (identify, detect):
            run = step["run"]
            self.assertIn("$env:PR_TITLE", run)
            self.assertIn("$env:PR_HEAD_REF", run)
            self.assertIn("$env:PR_USER_LOGIN", run)
            self.assertNotIn("${{ github.event.pull_request.title }}", run)

    def test_closed_event_still_promotes_staged_yaml_on_merge(self) -> None:
        finalize = workflow_job(self.workflow, "finalize-pr-workspace")
        self.assertIn("github.event.action == 'closed'", finalize["if"])
        run = steps_by_id(finalize)["finalize-workspace"]["run"]
        self.assertIn("pr-yaml-staging", run)
        self.assertIn("gamever.txt", run)
        self.assertIn('robocopy $latestRun.FullName $targetGamever "*.yaml" /S', run)
        self.assertNotIn("*.i64", run)
        self.assertNotIn("$RUNNER_WORKSPACE", run)


if __name__ == "__main__":
    unittest.main()
