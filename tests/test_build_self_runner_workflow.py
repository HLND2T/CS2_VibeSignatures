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
        self.assertNotIn("allow_legacy_bootstrap", dispatch_inputs)
        self.assertEqual(
            {"actions": "read", "contents": "read", "pull-requests": "read"},
            self.build_workflow["permissions"],
        )
        self.assertEqual(["preflight", "warmup-idb"], self.build_job["needs"])
        preflight = workflow_job(self.build_workflow, "preflight")
        self.assertEqual("${{ steps.resolve.outputs.source_sha }}", preflight["outputs"]["source_sha"])
        self.assertIn("github.repository == 'HLND2T/CS2_VibeSignatures'", preflight["if"])
        warmup = workflow_job(self.build_workflow, "warmup-idb")
        self.assertEqual("preflight", warmup["needs"])
        self.assertEqual("./.github/workflows/warmup-idb.yml", warmup["uses"])
        self.assertEqual("${{ needs.preflight.outputs.gamever }}", warmup["with"]["gamever"])
        self.assertEqual("${{ needs.preflight.outputs.source_sha }}", warmup["with"]["source_sha"])
        self.assertEqual("inherit", warmup["secrets"])

    def test_repository_dispatch_requires_merged_bump_pr_provenance(self) -> None:
        preflight = workflow_job(self.build_workflow, "preflight")
        resolve = steps_by_id(preflight)["resolve"]["run"]

        self.assertIn('if ("${{ github.event_name }}" -eq "repository_dispatch")', resolve)
        self.assertIn("repository_dispatch requires a numeric source_pull_request", resolve)
        self.assertIn('gh api "repos/${{ github.repository }}/pulls/$sourcePullRequest"', resolve)
        self.assertIn('$pull.head.ref -ne "bump-download/$gamever"', resolve)
        self.assertIn("$pull.merge_commit_sha -ne $sourceSha", resolve)

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
        self.assertEqual(
            "${{ secrets.HLND2T_GH_TOKEN }}",
            self.build_steps["create-output-pr"]["env"]["GH_TOKEN"],
        )
        self.assertFalse(self.build_steps["checkout-source"]["with"]["persist-credentials"])
        self.assertNotIn("token", self.build_steps["checkout-source"]["with"])
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

    def test_binsync_prepare_verify_and_protected_publish_are_separated(self) -> None:
        order = step_order(
            self.build_job,
            "verify-artifact-rebuild",
            "binsync-prepare",
            "build-candidates",
            "cpp-tests",
            "build-release-bundle",
            "upload-binsync-candidate",
            "upload-release-bundle",
            "publish-candidate",
        )
        self.assertEqual(sorted(order), order)
        prepare = self.build_steps["binsync-prepare"]["run"]
        self.assertIn("--prepare-only", prepare)
        self.assertIn("--artifactdir", prepare)
        self.assertIn("--preparation", prepare)
        self.assertIn("--python", prepare)

        verify = workflow_job(self.build_workflow, "verify-binsync")
        publish = workflow_job(self.build_workflow, "publish-binsync")
        verify_release = workflow_job(self.build_workflow, "verify-release")
        publish_release = workflow_job(self.build_workflow, "publish-release")
        self.assertEqual("./.github/workflows/verify-binsync-candidate.yml", verify["uses"])
        self.assertEqual("./.github/workflows/publish-binsync-candidate.yml", publish["uses"])
        self.assertEqual("./.github/workflows/verify-release-bundle.yml", verify_release["uses"])
        self.assertEqual("./.github/workflows/publish-release-bundle.yml", publish_release["uses"])
        self.assertIn("verify-binsync", publish["needs"])
        self.assertIn("verify-release", publish_release["needs"])
        self.assertIn("publish-binsync", publish_release["needs"])
        self.assertEqual({"actions": "read", "contents": "write"}, publish_release["permissions"])

    def test_build_restores_required_published_cache_before_analysis(self) -> None:
        order = step_order(
            self.build_job,
            "prepare-workspace",
            "resolve-consumer-ida",
            "restore-idb-cache",
            "init-binaries",
            "analyze",
        )
        self.assertEqual(sorted(order), order)
        self.assertIn("idb_cache.py restore", self.build_steps["restore-idb-cache"]["run"])
        self.assertIn("IDB_CACHE_GENERATION", self.build_steps["restore-idb-cache"]["run"])
        self.assertIn('--ida-version "$env:IDA_VERSION"', self.build_steps["restore-idb-cache"]["run"])
        self.assertIn("warmup_idb_worker.py --print-ida-version", self.build_steps["resolve-consumer-ida"]["run"])
        self.assertIn("*.i64", self.build_steps["prepare-workspace"]["run"])
        self.assertIn("/XF", self.build_steps["prepare-workspace"]["run"])
        self.assertIn("-require_warm_idb", self.build_steps["analyze"]["run"])
        self.assertNotIn("warmup-idb", self.build_steps)

    def test_promotion_is_bound_to_accepted_merge_and_validation_order(self) -> None:
        workflow = load_workflow("promote-release-after-output-merge.yml")
        cleanup_unmerged = workflow_job(workflow, "cleanup-unmerged")
        promote = workflow_job(workflow, "promote")
        steps = steps_by_id(promote)

        self.assertEqual("Promote output PR #${{ github.event.pull_request.number }}", workflow["run-name"])
        self.assertEqual({"contents": "write", "pull-requests": "read"}, workflow["permissions"])
        self.assertEqual(["closed"], workflow["on"]["pull_request"]["types"])
        self.assertEqual("resolve", promote["needs"])
        self.assertEqual(
            "gamever-state-${{ github.repository }}-${{ needs.resolve.outputs.gamever }}",
            promote["concurrency"]["group"],
        )
        self.assertEqual(promote["concurrency"], cleanup_unmerged["concurrency"])
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
        self.assertIn('"-x!*.idb"', steps["create-archives"]["run"])
        self.assertIn("gh release", steps["publish-release"]["run"])
        self.assertIn("release_workflow.py finalize-promotion", steps["finalize-promotion"]["run"])

    def test_bump_merge_dispatches_build_without_publishing_release_state(self) -> None:
        bump = load_workflow("bump-download.yml")
        bump_job = workflow_job(bump, "bump")
        bump_steps = steps_by_id(bump_job)
        order = step_order(bump_job, "checkout", "sync-refs", "configure-git", "preview", "bump", "branch", "create-pr")

        self.assertEqual(sorted(order), order)
        self.assertIn("git fetch origin --prune --prune-tags --tags", bump_steps["sync-refs"]["run"])
        self.assertNotIn("git tag", "\n".join(str(step.get("run", "")) for step in bump_job["steps"]))
        self.assertNotIn("dispatch-existing", bump_steps)
        self.assertNotIn("dispatch_build", "\n".join(str(step.get("run", "")) for step in bump_job["steps"]))

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
