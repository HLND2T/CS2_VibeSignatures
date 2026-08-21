import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(".claude/skills/trigger-release-build/scripts/trigger_release_build.py")
SPEC = importlib.util.spec_from_file_location("trigger_release_build", SCRIPT)
trigger = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(trigger)


def completed(command, *, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


class TestTriggerReleaseBuild(unittest.TestCase):
    def test_script_resolves_its_own_repository_root(self) -> None:
        expected = SCRIPT.resolve().parents[4]
        with patch.object(trigger, "run_command", return_value=completed([], stdout=f"{expected}\n")):
            self.assertEqual(expected, trigger.repository_root())

    def test_skill_requires_explicit_invocation_in_both_metadata_surfaces(self) -> None:
        skill = Path(".claude/skills/trigger-release-build/SKILL.md").read_text(encoding="utf-8")
        agent = Path(".claude/skills/trigger-release-build/agents/openai.yaml").read_text(encoding="utf-8")
        self.assertIn("disable-model-invocation: true", skill)
        self.assertIn("mode=new", skill)
        self.assertIn("mode=republish", skill)
        self.assertIn("allow_implicit_invocation: false", agent)
        self.assertIn("publish or republish", agent)

    def test_latest_uses_last_download_entry(self) -> None:
        self.assertEqual("14169", trigger.select_version("latest", ["14168", "14168b", "14169"]))

    def test_requested_version_must_exist_at_source_sha(self) -> None:
        self.assertEqual("14168b", trigger.select_version("14168b", ["14168", "14168b"]))
        with self.assertRaisesRegex(trigger.TriggerError, "absent"):
            trigger.select_version("14170", ["14168"])

    def test_origin_repository_must_be_allowlisted(self) -> None:
        with patch.object(
            trigger,
            "run_command",
            return_value=completed([], stdout="https://github.com/other/repository.git\n"),
        ):
            with self.assertRaisesRegex(trigger.TriggerError, "not allowlisted"):
                trigger.require_repository(Path("."))

    def test_github_auth_failure_stops_before_permission_checks(self) -> None:
        with patch.object(trigger, "run_command", side_effect=trigger.TriggerError("gh auth status failed")) as run:
            with self.assertRaisesRegex(trigger.TriggerError, "auth status"):
                trigger.require_github_access(Path("."), "HLND2T/CS2_VibeSignatures")
        run.assert_called_once_with(["gh", "auth", "status", "--hostname", "github.com"], Path("."))

    def test_release_state_selects_new_or_republish(self) -> None:
        new_responses = [
            completed([], returncode=2),
            completed([], returncode=1, stderr="gh: Not Found (HTTP 404)"),
        ]
        with patch.object(trigger, "run_command", side_effect=new_responses):
            self.assertEqual(
                "new",
                trigger.resolve_mode(Path("."), "HLND2T/CS2_VibeSignatures", "14170"),
            )

        republish_responses = [
            completed([], stdout="sha\trefs/tags/14170\n"),
            completed([]),
        ]
        with patch.object(trigger, "run_command", side_effect=republish_responses):
            self.assertEqual(
                "republish",
                trigger.resolve_mode(Path("."), "HLND2T/CS2_VibeSignatures", "14170"),
            )

    def test_inconsistent_release_states_are_rejected(self) -> None:
        tag_only = [
            completed([], stdout="sha\trefs/tags/14170\n"),
            completed([], returncode=1, stderr="gh: Not Found (HTTP 404)"),
        ]
        with patch.object(trigger, "run_command", side_effect=tag_only):
            with self.assertRaisesRegex(trigger.TriggerError, "tag exists but Release is absent"):
                trigger.resolve_mode(Path("."), "HLND2T/CS2_VibeSignatures", "14170")

        release_only = [completed([], returncode=2), completed([])]
        with patch.object(trigger, "run_command", side_effect=release_only):
            with self.assertRaisesRegex(trigger.TriggerError, "Release exists but tag is absent"):
                trigger.resolve_mode(Path("."), "HLND2T/CS2_VibeSignatures", "14170")

    def test_release_lookup_failure_is_not_treated_as_absent(self) -> None:
        responses = [
            completed([], returncode=2),
            completed([], returncode=1, stderr="gh: API rate limit exceeded (HTTP 403)"),
        ]
        with patch.object(trigger, "run_command", side_effect=responses):
            with self.assertRaisesRegex(trigger.TriggerError, "failed to query Release"):
                trigger.resolve_mode(Path("."), "HLND2T/CS2_VibeSignatures", "14170")

    def test_open_output_pr_blocks_dispatch(self) -> None:
        pulls = json.dumps([{"headRefName": "gamesymbols/build/14170/1-1", "url": "https://pr"}])
        with patch.object(trigger, "run_command", return_value=completed([], stdout=pulls)):
            with self.assertRaisesRegex(trigger.TriggerError, "already open"):
                trigger.require_no_duplicate(Path("."), "14170")

    def test_legacy_output_pr_blocks_dispatch_with_migration_error(self) -> None:
        pulls = json.dumps([{"headRefName": "gamesymbols/14170/build-1-1", "url": "https://legacy-pr"}])
        with patch.object(trigger, "run_command", return_value=completed([], stdout=pulls)):
            with self.assertRaisesRegex(trigger.TriggerError, "legacy-format.*must be resolved"):
                trigger.require_no_duplicate(Path("."), "14170")

    def test_unrelated_version_leaf_branch_does_not_block_dispatch(self) -> None:
        pulls = json.dumps([{"headRefName": "gamesymbols/14170", "url": "https://historical-pr"}])
        with patch.object(
            trigger,
            "run_command",
            side_effect=[completed([], stdout=pulls), completed([], stdout="[]")],
        ):
            self.assertEqual(set(), trigger.require_no_duplicate(Path("."), "14170"))

    def test_active_workflow_run_blocks_dispatch(self) -> None:
        responses = [
            completed([], stdout="[]"),
            completed(
                [],
                stdout=json.dumps(
                    [
                        {
                            "databaseId": 10,
                            "displayTitle": "Release build 14170",
                            "status": "in_progress",
                            "url": "https://run/10",
                        }
                    ]
                ),
            ),
        ]
        with patch.object(trigger, "run_command", side_effect=responses):
            with self.assertRaisesRegex(trigger.TriggerError, "already active"):
                trigger.require_no_duplicate(Path("."), "14170")

    def test_dispatch_uses_selected_workflow_mode(self) -> None:
        root = Path("repo")
        for mode in ("new", "republish"):
            with (
                self.subTest(mode=mode),
                patch.object(
                    trigger,
                    "run_command",
                    return_value=completed([]),
                ) as run,
            ):
                trigger.dispatch(root, "14170", "1" * 40, mode)

            run.assert_called_once_with(
                [
                    "gh",
                    "workflow",
                    "run",
                    "build-on-self-runner.yml",
                    "--ref",
                    "main",
                    "-f",
                    "gamever=14170",
                    "-f",
                    f"source_sha={'1' * 40}",
                    "-f",
                    f"mode={mode}",
                ],
                root,
            )

        with self.assertRaisesRegex(trigger.TriggerError, "invalid release mode"):
            trigger.dispatch(root, "14170", "1" * 40, "unsafe")

    def test_dispatch_stops_if_origin_main_advanced(self) -> None:
        with patch.object(trigger, "run_command", return_value=completed([], stdout=f"{'2' * 40}\trefs/heads/main\n")):
            with self.assertRaisesRegex(trigger.TriggerError, "advanced"):
                trigger.require_main_unchanged(Path("."), "1" * 40)

    def test_discover_run_reports_matching_new_run_url(self) -> None:
        run = {
            "databaseId": 12,
            "displayTitle": "Release build 14170",
            "status": "queued",
            "url": "https://run/12",
            "headSha": "1" * 40,
            "event": "workflow_dispatch",
        }
        with patch.object(trigger, "list_runs", return_value=[run]):
            self.assertEqual(
                "https://run/12",
                trigger.discover_run(Path("."), {11}, gamever="14170", source_sha="1" * 40),
            )

    def test_execute_resolves_main_then_dispatches_and_reports_provenance(self) -> None:
        root = Path("repo")
        with (
            patch.object(trigger, "repository_root", return_value=root),
            patch.object(trigger, "require_repository", return_value="HLND2T/CS2_VibeSignatures"),
            patch.object(trigger, "require_github_access") as access,
            patch.object(trigger, "resolve_source", return_value=("1" * 40, "subject")),
            patch.object(trigger, "available_versions", return_value=["14169", "14170"]),
            patch.object(trigger, "resolve_mode", return_value="new") as resolve_mode,
            patch.object(trigger, "require_no_duplicate", return_value={10}),
            patch.object(trigger, "require_main_unchanged") as unchanged,
            patch.object(trigger, "dispatch") as dispatch,
            patch.object(trigger, "discover_run", return_value="https://run/11"),
        ):
            result = trigger.execute("latest")

        self.assertEqual("14170", result["gamever"])
        self.assertEqual("new", result["mode"])
        self.assertEqual("https://run/11", result["run_url"])
        access.assert_called_once()
        resolve_mode.assert_called_once_with(root, "HLND2T/CS2_VibeSignatures", "14170")
        unchanged.assert_called_once_with(root, "1" * 40)
        dispatch.assert_called_once_with(root, "14170", "1" * 40, "new")

    def test_main_reports_selected_mode(self) -> None:
        result = {
            "gamever": "14170",
            "mode": "new",
            "source_sha": "1" * 40,
            "subject": "subject",
            "run_url": "https://run/11",
        }
        with patch.object(trigger, "execute", return_value=result) as execute, patch("builtins.print") as output:
            self.assertEqual(0, trigger.main(["14170"]))

        execute.assert_called_once_with("14170")
        output.assert_any_call("Mode: new")


if __name__ == "__main__":
    unittest.main()
