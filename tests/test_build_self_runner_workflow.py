import unittest

from tests.workflow_contract_test_support import load_workflow, step_order, steps_by_id, workflow_job


class TestBuildSelfRunnerWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.build_workflow = load_workflow("build-on-self-runner.yml")
        self.build_job = workflow_job(self.build_workflow, "build")
        self.build_steps = steps_by_id(self.build_job)

    def test_dispatch_contract_permissions_and_job_dependency(self) -> None:
        triggers = self.build_workflow["on"]
        dispatch_inputs = triggers["workflow_dispatch"]["inputs"]

        self.assertEqual(["build-on-self-runner"], triggers["repository_dispatch"]["types"])
        self.assertEqual("string", dispatch_inputs["gamever"]["type"])
        self.assertEqual("string", dispatch_inputs["source_sha"]["type"])
        self.assertEqual(["new", "republish"], dispatch_inputs["mode"]["options"])
        self.assertEqual(False, dispatch_inputs["allow_legacy_bootstrap"]["default"])
        self.assertEqual(
            {"actions": "read", "contents": "write", "pull-requests": "write"},
            self.build_workflow["permissions"],
        )
        self.assertEqual("preflight", self.build_job["needs"])
        preflight = workflow_job(self.build_workflow, "preflight")
        self.assertEqual("${{ steps.resolve.outputs.source_sha }}", preflight["outputs"]["source_sha"])
        self.assertIn("github.repository == 'HLND2T/CS2_VibeSignatures'", preflight["if"])

    def test_fast_and_full_test_suites_run_before_analysis(self) -> None:
        tests_step = self.build_steps["test-suites"]
        run = tests_step["run"]

        self.assertIn("format_repo_files.py --check", run)
        for suite_name in ("unit", "repository-contract", "redis-integration", "release-integration", "all"):
            self.assertIn(suite_name, run)
        self.assertIn("tests/run_test_suite.py $suite -b --durations 30", run)
        self.assertEqual(
            sorted(step_order(self.build_job, "test-suites", "analyze", "build-candidates", "cpp-tests")),
            step_order(self.build_job, "test-suites", "analyze", "build-candidates", "cpp-tests"),
        )

    def test_submodule_cache_uses_node24_action_and_shallow_update(self) -> None:
        self.assertEqual("actions/cache@v5", self.build_steps["restore-submodule-cache"]["uses"])
        self.assertIn(
            "git submodule update --init --recursive --depth 1 --jobs 8",
            self.build_steps["sync-submodules"]["run"],
        )

    def test_submodule_cache_key_is_deterministic(self) -> None:
        key_step = self.build_steps["submodule-cache-key"]["run"]
        self.assertIn("git ls-tree HEAD", key_step)
        self.assertNotIn("submodule status --recursive", key_step)

    def test_candidate_validation_precedes_staging_and_output_pr(self) -> None:
        expected_order = step_order(
            self.build_job,
            "analyze",
            "build-candidates",
            "select-sdk",
            "cpp-tests",
            "restore-sdk",
            "publish-candidate",
            "stage-pending",
            "create-output-pr",
            "cleanup",
        )
        self.assertEqual(sorted(expected_order), expected_order)
        self.assertIn("gamesymbol_candidate.py build", self.build_steps["build-candidates"]["run"])
        self.assertIn("gamedata_candidate.py build", self.build_steps["build-candidates"]["run"])
        self.assertIn("run_cpp_tests.py", self.build_steps["cpp-tests"]["run"])
        self.assertIn("gamesymbol_candidate.py publish", self.build_steps["publish-candidate"]["run"])
        self.assertIn("release_workflow.py stage-build", self.build_steps["stage-pending"]["run"])
        self.assertIn("gh pr create", self.build_steps["create-output-pr"]["run"])
        self.assertEqual("always()", self.build_steps["restore-sdk"]["if"])
        build_commands = "\n".join(str(step.get("run", "")) for step in self.build_job["steps"])
        self.assertNotIn("gh release", build_commands)

    def test_exact_source_config_and_sdk_identity_are_threaded_through_build(self) -> None:
        checkout = self.build_steps["checkout-source"]
        self.assertEqual("actions/checkout@v5", checkout["uses"])
        self.assertEqual("${{ needs.preflight.outputs.source_sha }}", checkout["with"]["ref"])
        self.assertIn("ANALYSIS_CONFIG=$config", self.build_steps["resolve-config"]["run"])
        self.assertIn("'-configyaml', $env:ANALYSIS_CONFIG", self.build_steps["analyze"]["run"])
        self.assertIn('-configyaml "$env:ANALYSIS_CONFIG"', self.build_steps["cpp-tests"]["run"])
        self.assertIn(
            'git -C $sdkPath checkout --detach "$env:SDK_PINNED_SHA"',
            self.build_steps["restore-sdk"]["run"],
        )

    def test_promotion_is_bound_to_accepted_merge_and_validation_order(self) -> None:
        workflow = load_workflow("promote-release-after-output-merge.yml")
        promote = workflow_job(workflow, "promote")
        steps = steps_by_id(promote)

        self.assertEqual({"contents": "write", "pull-requests": "read"}, workflow["permissions"])
        self.assertEqual(["closed"], workflow["on"]["pull_request"]["types"])
        self.assertEqual("resolve", promote["needs"])
        self.assertIn("github.event.pull_request.merged == true", promote["if"])
        self.assertIn("github.event.pull_request.base.ref == github.event.repository.default_branch", promote["if"])
        promotion_order = step_order(
            promote,
            "verify",
            "reconstruct",
            "create-archives",
            "promote-bin",
            "tag",
            "release-metadata",
            "publish-release",
            "finalize-promotion",
            "cleanup-completed",
        )
        self.assertEqual(sorted(promotion_order), promotion_order)
        self.assertIn("release_workflow.py verify-promotion", steps["verify"]["run"])
        self.assertIn("release_workflow.py promote-bin", steps["promote-bin"]["run"])
        self.assertIn("gh release", steps["publish-release"]["run"])
        self.assertIn("release_workflow.py finalize-promotion", steps["finalize-promotion"]["run"])

    def test_bump_merge_dispatches_build_without_publishing_release_state(self) -> None:
        bump = load_workflow("bump-download.yml")
        bump_job = workflow_job(bump, "bump")
        bump_steps = steps_by_id(bump_job)
        order = step_order(bump_job, "checkout", "sync-refs", "configure-git", "preview", "bump", "branch", "create-pr")

        self.assertEqual(sorted(order), order)
        self.assertEqual({"contents": "write", "pull-requests": "write"}, bump["permissions"])
        self.assertIn("git fetch origin --prune --prune-tags --tags", bump_steps["sync-refs"]["run"])
        self.assertNotIn("git tag", "\n".join(str(step.get("run", "")) for step in bump_job["steps"]))

        dispatch = load_workflow("tag-bump-after-merge.yml")
        dispatch_job = workflow_job(dispatch, "dispatch-build")
        dispatch_step = steps_by_id(dispatch_job)["dispatch-build"]
        self.assertEqual(["closed"], dispatch["on"]["pull_request"]["types"])
        self.assertIn("github.event.pull_request.merged == true", dispatch_job["if"])
        self.assertIn('event_type = "build-on-self-runner"', dispatch_step["run"])
        self.assertIn('mode = "new"', dispatch_step["run"])

    def test_generated_output_pr_validation_is_read_only_and_provenance_bound(self) -> None:
        workflow = load_workflow("validate-generated-output-pr.yml")
        validate = workflow_job(workflow, "validate")
        steps = steps_by_id(validate)

        self.assertEqual({"contents": "read"}, workflow["permissions"])
        self.assertEqual(
            ["opened", "synchronize", "reopened", "ready_for_review"], workflow["on"]["pull_request"]["types"]
        )
        self.assertIn("startsWith(github.event.pull_request.head.ref, 'gamesymbols/build/')", validate["if"])
        self.assertEqual(
            sorted(step_order(validate, "checkout-output", "setup-uv", "checkout-tooling", "verify-output")),
            step_order(validate, "checkout-output", "setup-uv", "checkout-tooling", "verify-output"),
        )
        self.assertIn("release_workflow.py verify-output-pr", steps["verify-output"]["run"])


if __name__ == "__main__":
    unittest.main()
