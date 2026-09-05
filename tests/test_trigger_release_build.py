import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


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

    def test_latest_uses_last_download_entry(self) -> None:
        self.assertEqual("14169", trigger.select_version("latest", ["14168", "14168b", "14169"]))

    def test_requested_version_must_exist_at_source_sha(self) -> None:
        self.assertEqual("14168b", trigger.select_version("14168b", ["14168", "14168b"]))
        with self.assertRaisesRegex(trigger.TriggerError, "absent"):
            trigger.select_version("14170", ["14168"])

    def test_publication_mode_must_be_supported(self) -> None:
        self.assertEqual("verify-only", trigger.require_publication_mode("verify-only"))
        self.assertEqual("publish", trigger.require_publication_mode("publish"))
        with self.assertRaisesRegex(trigger.TriggerError, "unsupported publication mode"):
            trigger.require_publication_mode("clobber")

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

    def test_active_workflow_run_blocks_dispatch(self) -> None:
        response = completed(
            [],
            stdout=json.dumps(
                [
                    {
                        "databaseId": 10,
                        "displayTitle": "Release publish 14170",
                        "status": "in_progress",
                        "url": "https://run/10",
                    }
                ]
            ),
        )
        with patch.object(trigger, "run_command", return_value=response):
            with self.assertRaisesRegex(trigger.TriggerError, "already active"):
                trigger.require_no_duplicate(Path("."), "14170", "publish")

    def test_dispatch_uses_only_immutable_source_identity(self) -> None:
        root = Path("repo")
        with patch.object(trigger, "run_command", return_value=completed([])) as run:
            trigger.dispatch(root, "14170", "1" * 40, "publish")

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
                "publication_mode=publish",
            ],
            root,
        )

    def test_source_artifact_preflight_runs_in_detached_temporary_worktree(self) -> None:
        manager = MagicMock()
        manager.__enter__.return_value = "temporary"
        with (
            patch.object(trigger.tempfile, "TemporaryDirectory", return_value=manager),
            patch.object(trigger, "run_command", return_value=completed([])) as run,
        ):
            trigger.require_source_artifacts(Path("repo"), "HLND2T/CS2_VibeSignatures", "14170", "1" * 40)

        commands = [call.args[0] for call in run.call_args_list]
        source_root = str(Path("temporary") / "source")
        self.assertEqual(["git", "worktree", "add", "--detach", source_root, "1" * 40], commands[0])
        self.assertIn("release_source_preflight.py", commands[1])
        self.assertEqual(["git", "worktree", "remove", "--force", source_root], commands[2])

    def test_dispatch_stops_if_origin_main_advanced(self) -> None:
        with patch.object(trigger, "run_command", return_value=completed([], stdout=f"{'2' * 40}\trefs/heads/main\n")):
            with self.assertRaisesRegex(trigger.TriggerError, "advanced"):
                trigger.require_main_unchanged(Path("."), "1" * 40)

    def test_discover_run_reports_matching_new_run_url(self) -> None:
        run = {
            "databaseId": 12,
            "displayTitle": "Release verify-only 14170",
            "status": "queued",
            "url": "https://run/12",
            "headSha": "1" * 40,
            "event": "workflow_dispatch",
        }
        with patch.object(trigger, "list_runs", return_value=[run]):
            self.assertEqual(
                "https://run/12",
                trigger.discover_run(
                    Path("."),
                    {11},
                    gamever="14170",
                    source_sha="1" * 40,
                    publication_mode="verify-only",
                ),
            )

    def test_execute_resolves_main_then_dispatches_and_reports_provenance(self) -> None:
        root = Path("repo")
        with (
            patch.object(trigger, "repository_root", return_value=root),
            patch.object(trigger, "require_repository", return_value="HLND2T/CS2_VibeSignatures"),
            patch.object(trigger, "require_github_access") as access,
            patch.object(trigger, "resolve_source", return_value=("1" * 40, "subject")),
            patch.object(trigger, "available_versions", return_value=["14169", "14170"]),
            patch.object(trigger, "require_no_duplicate", return_value={10}) as duplicate,
            patch.object(trigger, "require_main_unchanged") as unchanged,
            patch.object(trigger, "require_source_artifacts") as source_artifacts,
            patch.object(trigger, "dispatch") as dispatch,
            patch.object(trigger, "discover_run", return_value="https://run/11") as discover,
        ):
            result = trigger.execute("latest", "verify-only")

        self.assertEqual("14170", result["gamever"])
        self.assertEqual("verify-only", result["publication_mode"])
        self.assertEqual("https://run/11", result["run_url"])
        access.assert_called_once()
        self.assertEqual(2, unchanged.call_count)
        source_artifacts.assert_called_once_with(root, "HLND2T/CS2_VibeSignatures", "14170", "1" * 40)
        duplicate.assert_called_once_with(root, "14170", "verify-only")
        dispatch.assert_called_once_with(root, "14170", "1" * 40, "verify-only")
        discover.assert_called_once_with(
            root,
            {10},
            gamever="14170",
            source_sha="1" * 40,
            publication_mode="verify-only",
        )

    def test_main_reports_immutable_source(self) -> None:
        result = {
            "gamever": "14170",
            "publication_mode": "verify-only",
            "source_sha": "1" * 40,
            "subject": "subject",
            "run_url": "https://run/11",
        }
        with patch.object(trigger, "execute", return_value=result) as execute, patch("builtins.print") as output:
            self.assertEqual(0, trigger.main(["14170", "--mode", "verify-only"]))

        execute.assert_called_once_with("14170", "verify-only")
        output.assert_any_call(f"SOURCE_SHA: {'1' * 40}")


if __name__ == "__main__":
    unittest.main()
