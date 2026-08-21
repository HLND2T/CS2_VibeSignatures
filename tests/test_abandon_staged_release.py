import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.workflow_contract_test_support import load_workflow, step_order, steps_by_id, workflow_job


SCRIPT = Path(".claude/skills/abandon-staged-release/scripts/abandon_staged_release.py")
SPEC = importlib.util.spec_from_file_location("abandon_staged_release", SCRIPT)
abandon = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(abandon)


def completed(command, *, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def pull_request_payload(number=582, **overrides) -> dict:
    payload = {
        "number": number,
        "state": "closed",
        "merged_at": "2026-07-19T12:48:13Z",
        "html_url": f"https://github.com/HLND2T/CS2_VibeSignatures/pull/{number}",
        "user": {"login": "github-actions[bot]"},
        "head": {
            "ref": "gamesymbols/build/14168/29686825445-1",
            "sha": "6a44f19be35e6fc876d9e74b46f494f214b383d1",
            "repo": {"full_name": "HLND2T/CS2_VibeSignatures"},
        },
        "base": {"ref": "main"},
    }
    payload.update(overrides)
    return payload


def build_run_payload(run_id=29686825445, *, attempt=1, conclusion="success", **overrides) -> dict:
    payload = {
        "id": run_id,
        "run_attempt": attempt,
        "path": ".github/workflows/build-on-self-runner.yml",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": conclusion,
        "display_title": "Release build 14168",
        "repository": {"full_name": "HLND2T/CS2_VibeSignatures"},
    }
    payload.update(overrides)
    return payload


class TestAbandonStagedRelease(unittest.TestCase):
    def test_script_resolves_its_own_repository_root(self) -> None:
        expected = SCRIPT.resolve().parents[4]
        with patch.object(abandon, "run_command", return_value=completed([], stdout=f"{expected}\n")):
            self.assertEqual(expected, abandon.repository_root())

    def test_direct_target_must_match_exact_confirmation(self) -> None:
        self.assertEqual(
            ("14168", "29686825445-1"),
            abandon.resolve_target_identity(
                Path("."),
                "HLND2T/CS2_VibeSignatures",
                "14168/29686825445-1",
                "ABANDON 14168/29686825445-1",
            ),
        )
        with self.assertRaisesRegex(abandon.AbandonError, "does not match confirmation"):
            abandon.resolve_target_identity(
                Path("."),
                "HLND2T/CS2_VibeSignatures",
                "14168/29686825445-2",
                "ABANDON 14168/29686825445-1",
            )

    def test_confirmation_and_reason_are_strict(self) -> None:
        with self.assertRaisesRegex(abandon.AbandonError, "confirmation"):
            abandon.parse_confirmation("ABANDON 14168/wrong")
        with self.assertRaisesRegex(abandon.AbandonError, "one non-empty line"):
            abandon.validate_reason("bad\nreason")

    def test_run_url_can_identify_the_staged_build_itself(self) -> None:
        run = build_run_payload()
        with patch.object(abandon, "run_command", return_value=completed([], stdout=json.dumps(run))) as command:
            identity = abandon.resolve_target_identity(
                Path("."),
                "HLND2T/CS2_VibeSignatures",
                "https://github.com/HLND2T/CS2_VibeSignatures/actions/runs/29686825445/job/1",
                "ABANDON 14168/29686825445-1",
            )
        self.assertEqual(("14168", "29686825445-1"), identity)
        self.assertIn("repos/HLND2T/CS2_VibeSignatures/actions/runs/29686825445", command.call_args.args[0])

    def test_blocked_run_url_can_identify_its_unique_ready_blocker(self) -> None:
        run = build_run_payload(run_id=29688978009, conclusion="failure")
        log = "Error: another ready staged build blocks 14168: ***\\release-staging\\14168\\29686825445-1\n"
        with patch.object(
            abandon,
            "run_command",
            side_effect=[completed([], stdout=json.dumps(run)), completed([], stdout=log)],
        ) as command:
            identity = abandon.resolve_target_identity(
                Path("."),
                "HLND2T/CS2_VibeSignatures",
                "https://github.com/HLND2T/CS2_VibeSignatures/actions/runs/29688978009/job/88198248637",
                "ABANDON 14168/29686825445-1",
            )
        self.assertEqual(("14168", "29686825445-1"), identity)
        self.assertIn("--log-failed", command.call_args_list[1].args[0])

    def test_run_url_rejects_untrusted_or_ambiguous_evidence(self) -> None:
        cases = (
            (
                build_run_payload(path=".github/workflows/other.yml"),
                "",
                "trusted release build workflow",
            ),
            (
                build_run_payload(run_id=29688978009, conclusion="failure"),
                "Error: another ready staged build blocks 14168: ***\\release-staging\\14168\\111-1\n",
                "does not report the confirmed READY build",
            ),
            (
                build_run_payload(run_id=29688978009, conclusion="failure"),
                "Error: another ready staged build blocks 14168: "
                "***\\release-staging\\14168\\29686825445-1\n"
                "Error: another ready staged build blocks 14168: "
                "***\\release-staging\\14168\\111-1\n",
                "multiple READY build identities",
            ),
        )
        for run, log, message in cases:
            responses = [completed([], stdout=json.dumps(run))]
            if log:
                responses.append(completed([], stdout=log))
            with (
                self.subTest(message=message),
                patch.object(abandon, "run_command", side_effect=responses),
                self.assertRaisesRegex(abandon.AbandonError, message),
            ):
                abandon.resolve_target_identity(
                    Path("."),
                    "HLND2T/CS2_VibeSignatures",
                    f"https://github.com/HLND2T/CS2_VibeSignatures/actions/runs/{run['id']}",
                    "ABANDON 14168/29686825445-1",
                )

    def test_run_url_must_match_the_owning_repository(self) -> None:
        with self.assertRaisesRegex(abandon.AbandonError, "repository does not match"):
            abandon.resolve_target_identity(
                Path("."),
                "HLND2T/CS2_VibeSignatures",
                "https://github.com/other/repository/actions/runs/29686825445",
                "ABANDON 14168/29686825445-1",
            )

    def test_unique_trusted_merged_pr_is_discovered_from_build_identity(self) -> None:
        pulls = [pull_request_payload()]
        with patch.object(
            abandon,
            "run_command",
            side_effect=[completed([], stdout=json.dumps(pulls)), completed([], stdout="[]")],
        ) as command:
            identity = abandon.discover_pr_identity(Path("."), "HLND2T/CS2_VibeSignatures", "14168", "29686825445-1")
        self.assertEqual(582, identity["pr_number"])
        self.assertEqual("6a44f19be35e6fc876d9e74b46f494f214b383d1", identity["head_sha"])
        discovery = command.call_args_list[0].args[0]
        self.assertIn("head=HLND2T:gamesymbols/build/14168/29686825445-1", discovery)
        self.assertNotIn("582", discovery)

    def test_exact_legacy_trusted_merged_pr_is_discovered_for_historical_recovery(self) -> None:
        legacy = pull_request_payload(
            number=575,
            head={
                "ref": "gamesymbols/14168b/build-29568028525-1",
                "sha": "018b2af391d7e4db6f04f103e80a68c73a6ebfba",
                "repo": {"full_name": "HLND2T/CS2_VibeSignatures"},
            },
        )
        with patch.object(
            abandon,
            "run_command",
            side_effect=[completed([], stdout="[]"), completed([], stdout=json.dumps([legacy]))],
        ) as command:
            identity = abandon.discover_pr_identity(Path("."), "HLND2T/CS2_VibeSignatures", "14168b", "29568028525-1")
        self.assertEqual(575, identity["pr_number"])
        self.assertEqual("gamesymbols/14168b/build-29568028525-1", identity["output_branch"])
        legacy_discovery = command.call_args_list[1].args[0]
        self.assertIn("head=HLND2T:gamesymbols/14168b/build-29568028525-1", legacy_discovery)

    def test_pr_discovery_rejects_missing_untrusted_or_ambiguous_matches(self) -> None:
        untrusted = pull_request_payload(user={"login": "someone"})
        malformed_legacy = pull_request_payload(
            head={
                "ref": "gamesymbols/14168/build-29686825445-1/extra",
                "sha": "6a44f19be35e6fc876d9e74b46f494f214b383d1",
                "repo": {"full_name": "HLND2T/CS2_VibeSignatures"},
            }
        )
        duplicate = pull_request_payload(
            number=583,
            head={
                "ref": "gamesymbols/build/14168/29686825445-1",
                "sha": "7a44f19be35e6fc876d9e74b46f494f214b383d1",
                "repo": {"full_name": "HLND2T/CS2_VibeSignatures"},
            },
        )
        cases = (
            (([], []), "no trusted merged"),
            (([untrusted], []), "no trusted merged"),
            (([], [malformed_legacy]), "no trusted merged"),
            (([pull_request_payload()], [duplicate]), "multiple trusted merged"),
        )
        for responses, message in cases:
            with (
                self.subTest(message=message),
                patch.object(
                    abandon,
                    "run_command",
                    side_effect=[completed([], stdout=json.dumps(pulls)) for pulls in responses],
                ),
                self.assertRaisesRegex(abandon.AbandonError, message),
            ):
                abandon.discover_pr_identity(Path("."), "HLND2T/CS2_VibeSignatures", "14168", "29686825445-1")

    def test_duplicate_active_workflow_is_rejected(self) -> None:
        runs = [
            {
                "databaseId": 123,
                "displayTitle": "Abandon staged release PR #582",
                "status": "in_progress",
                "url": "https://github.com/example/run",
            }
        ]
        with patch.object(abandon, "list_runs", return_value=runs):
            with self.assertRaisesRegex(abandon.AbandonError, "already active"):
                abandon.require_no_duplicate(Path("."), 582)

    def test_legacy_truncated_active_workflow_is_rejected(self) -> None:
        runs = [
            {
                "databaseId": 123,
                "displayTitle": "Abandon staged release PR",
                "status": "queued",
                "url": "https://github.com/example/legacy-run",
            }
        ]
        with patch.object(abandon, "list_runs", return_value=runs):
            with self.assertRaisesRegex(abandon.AbandonError, "legacy-truncated title"):
                abandon.require_no_duplicate(Path("."), 582)

    def test_discover_run_reports_matching_new_run_url(self) -> None:
        run = {
            "databaseId": 124,
            "displayTitle": "Abandon staged release PR #582",
            "status": "queued",
            "url": "https://github.com/example/run/124",
            "headSha": "a" * 40,
            "event": "workflow_dispatch",
        }
        with patch.object(abandon, "list_runs", return_value=[run]):
            self.assertEqual(
                "https://github.com/example/run/124",
                abandon.discover_run(Path("."), {123}, pr_number=582, source_sha="a" * 40),
            )

    def test_discover_run_reports_unexpected_title_and_candidate_url(self) -> None:
        run = {
            "databaseId": 124,
            "displayTitle": "Abandon staged release PR",
            "status": "queued",
            "url": "https://github.com/example/run/124",
            "headSha": "a" * 40,
            "event": "workflow_dispatch",
        }
        with patch.object(abandon, "list_runs", return_value=[run]):
            with self.assertRaisesRegex(
                abandon.AbandonError,
                "unexpected title.*https://github.com/example/run/124",
            ):
                abandon.discover_run(Path("."), {123}, pr_number=582, source_sha="a" * 40)

    def test_dispatch_uses_only_discovered_identity_and_audit_inputs(self) -> None:
        identity = {
            "pr_number": 582,
            "confirmation": "ABANDON 14168/29686825445-1",
            "reason": "Promotion failed before promote-bin",
        }
        with patch.object(abandon, "run_command", return_value=completed([])) as run:
            abandon.dispatch(Path("."), identity)
        command = run.call_args.args[0]
        self.assertIn("abandon-staged-release.yml", command)
        self.assertIn("pr_number=582", command)
        self.assertIn("confirmation=ABANDON 14168/29686825445-1", command)
        self.assertIn("reason=Promotion failed before promote-bin", command)
        self.assertNotIn("staging_root", " ".join(command))

    def test_execute_reports_the_dispatched_recovery_run(self) -> None:
        identity = {
            "pr_number": 582,
            "pr_url": "https://github.com/HLND2T/CS2_VibeSignatures/pull/582",
            "gamever": "14168",
            "build_id": "29686825445-1",
            "head_sha": "6" * 40,
        }
        with (
            patch.object(abandon, "repository_root", return_value=Path(".")),
            patch.object(abandon, "require_repository", return_value="HLND2T/CS2_VibeSignatures"),
            patch.object(abandon, "require_github_access"),
            patch.object(abandon, "resolve_main", return_value="a" * 40),
            patch.object(
                abandon,
                "resolve_target_identity",
                return_value=("14168", "29686825445-1"),
            ),
            patch.object(abandon, "discover_pr_identity", return_value=identity.copy()),
            patch.object(abandon, "require_no_duplicate", return_value={1}),
            patch.object(abandon, "require_main_unchanged"),
            patch.object(abandon, "dispatch") as dispatch,
            patch.object(abandon, "discover_run", return_value="https://github.com/example/run"),
        ):
            result = abandon.execute(
                "14168/29686825445-1",
                "ABANDON 14168/29686825445-1",
                "Promotion failed before promote-bin",
            )
        dispatch.assert_called_once()
        self.assertEqual("https://github.com/example/run", result["run_url"])
        self.assertEqual("a" * 40, result["source_sha"])

    def test_recovery_workflow_still_derives_identity_and_uses_gamever_state_concurrency(self) -> None:
        workflow = load_workflow("abandon-staged-release.yml")
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        resolve = workflow_job(workflow, "resolve")
        abandon_job = workflow_job(workflow, "abandon")
        identity = steps_by_id(resolve)["identity"]
        abandon_steps = steps_by_id(abandon_job)

        self.assertEqual({"pr_number", "confirmation", "reason"}, set(inputs))
        self.assertEqual({"contents": "read", "pull-requests": "read"}, workflow["permissions"])
        self.assertIn('gh api "repos/${{ github.repository }}/pulls/$env:PR_NUMBER"', identity["run"])
        self.assertIn("^gamesymbols/(?<gamever>[0-9]{4,10}[a-z]?)/build-", identity["run"])
        self.assertEqual("resolve", abandon_job["needs"])
        self.assertEqual("win64", abandon_job["environment"])
        self.assertEqual(["self-hosted", "windows", "x64"], abandon_job["runs-on"])
        self.assertEqual(
            "gamever-state-${{ github.repository }}-${{ needs.resolve.outputs.gamever }}",
            abandon_job["concurrency"]["group"],
        )
        self.assertEqual(
            sorted(step_order(abandon_job, "checkout", "abandon-pending", "verify-cleanup")),
            step_order(abandon_job, "checkout", "abandon-pending", "verify-cleanup"),
        )
        self.assertIn("release_workflow.py abandon-pending", abandon_steps["abandon-pending"]["run"])
        self.assertIn('--pr-number "$env:PR_NUMBER"', abandon_steps["abandon-pending"]["run"])


if __name__ == "__main__":
    unittest.main()
