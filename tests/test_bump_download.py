import argparse
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import ANY, call, patch

import bump_download
import bump_download_candidate as bdc
from tests.gamesymbol_snapshot_test_support import write_binary, write_config


class TestBumpDownload(unittest.TestCase):
    def test_patch_version_to_tag_removes_dots(self) -> None:
        self.assertEqual("14161", bump_download.patch_version_to_tag("1.41.6.1"))

    def test_patch_version_to_tag_rejects_malformed_version(self) -> None:
        with self.assertRaises(bump_download.BumpError):
            bump_download.patch_version_to_tag("1.41")

    def test_parse_manifest_id_from_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest_2347771_6999933698852825529.txt"
            path.write_text("Content Manifest for Depot 2347771\n", encoding="utf-8")

            self.assertEqual(
                "6999933698852825529",
                bump_download.find_manifest_id(Path(tmp), "2347771"),
            )

    def test_parse_manifest_id_rejects_multiple_manifest_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "manifest_2347771_123.txt").write_text("", encoding="utf-8")
            (path / "manifest_2347773_456.txt").write_text("", encoding="utf-8")

            with self.assertRaises(bump_download.BumpError):
                bump_download.find_manifest_id(path, "2347771")

    def test_parse_manifest_id_rejects_unexpected_depot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "manifest_2347773_456.txt").write_text("", encoding="utf-8")

            with self.assertRaises(bump_download.BumpError):
                bump_download.find_manifest_id(path, "2347771")

    def test_parse_manifest_id_rejects_non_numeric_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "manifest_2347771_abc.txt").write_text("", encoding="utf-8")

            with self.assertRaises(bump_download.BumpError):
                bump_download.find_manifest_id(path, "2347771")

    def test_parse_patch_version_from_steam_inf(self) -> None:
        text = "\n".join(
            [
                "ClientVersion=2000777",
                "ServerVersion=2000777",
                "PatchVersion=1.41.6.1",
                "ProductName=cs2",
            ]
        )

        self.assertEqual("1.41.6.1", bump_download.parse_patch_version(text))

    def test_parse_patch_version_rejects_malformed_patch_version(self) -> None:
        text = "\n".join(
            [
                "ClientVersion=2000777",
                "ServerVersion=2000777",
                "PatchVersion=1.41",
                "ProductName=cs2",
            ]
        )

        with self.assertRaises(bump_download.BumpError):
            bump_download.parse_patch_version(text)

    @patch("builtins.print")
    @patch("depot_util.subprocess.run")
    def test_run_command_redacts_password_in_logs(self, mock_run, mock_print) -> None:
        command = ["DepotDownloader", "-app", "730", "-password", "secret"]

        bump_download.run_command(command)

        printed = mock_print.call_args.args[0]
        self.assertIn("-password <redacted>", printed)
        self.assertNotIn("secret", printed)
        mock_run.assert_called_once_with(command, check=True)
        self.assertEqual("secret", mock_run.call_args.args[0][4])

    @patch("depot_util.time.sleep")
    @patch("depot_util.subprocess.run")
    def test_run_command_retries_after_subprocess_failure(self, mock_run, mock_sleep) -> None:
        command = ["DepotDownloader", "-app", "730"]
        mock_run.side_effect = [
            bump_download.subprocess.CalledProcessError(1, command),
            None,
        ]

        bump_download.run_command(command, retry_delay_seconds=0)

        self.assertEqual(2, mock_run.call_count)
        mock_run.assert_has_calls([call(command, check=True), call(command, check=True)])
        mock_sleep.assert_called_once_with(0)

    @patch("depot_util.time.sleep")
    @patch("depot_util.subprocess.run")
    def test_run_command_raises_after_retry_attempts_exhausted(self, mock_run, mock_sleep) -> None:
        command = ["DepotDownloader", "-app", "730"]
        first_error = bump_download.subprocess.CalledProcessError(1, command)
        final_error = bump_download.subprocess.CalledProcessError(1, command)
        mock_run.side_effect = [first_error, final_error]

        with self.assertRaises(bump_download.subprocess.CalledProcessError) as ctx:
            bump_download.run_command(command, max_attempts=2, retry_delay_seconds=0)

        self.assertIs(final_error, ctx.exception)
        self.assertEqual(2, mock_run.call_count)
        mock_sleep.assert_called_once_with(0)

    @patch("depot_util.subprocess.run")
    def test_fetch_manifest_only_uses_isolated_directory(self, mock_run) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            isolated = Path(tmp) / "manifest"
            isolated.mkdir()
            (isolated / "manifest_2347771_12345.txt").write_text("", encoding="utf-8")

            manifest_id = bump_download.fetch_manifest_id(
                depot="2347771",
                app="730",
                os_name="all-platform",
                output_dir=isolated,
                username="user",
                password="pass",
                remember_password=True,
            )

        self.assertEqual("12345", manifest_id)
        expected_command = [
            "DepotDownloader",
            "-app",
            "730",
            "-depot",
            "2347771",
            "-os",
            "all-platform",
            "-dir",
            str(isolated),
            "-username",
            "user",
            "-password",
            "pass",
            "-remember-password",
            "-manifest-only",
        ]
        mock_run.assert_called_once_with(expected_command, check=True)

    @patch("depot_util.subprocess.run")
    def test_download_steam_inf_uses_manifest_and_filelist(self, mock_run) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            depot_dir = Path(tmp)
            steam_inf = depot_dir / "game" / "csgo" / "steam.inf"
            steam_inf.parent.mkdir(parents=True)
            steam_inf.write_text("PatchVersion=1.41.6.1\n", encoding="utf-8")

            patch_version = bump_download.download_and_parse_steam_inf(
                manifest_id="999",
                app="730",
                os_name="all-platform",
                depot_dir=depot_dir,
                username=None,
                password=None,
                remember_password=False,
            )

        self.assertEqual("1.41.6.1", patch_version)
        command = mock_run.call_args.args[0]
        filelist_path = Path(command[command.index("-filelist") + 1])
        expected_command = [
            "DepotDownloader",
            "-app",
            "730",
            "-depot",
            "2347770",
            "-os",
            "all-platform",
            "-dir",
            str(depot_dir),
            "-manifest",
            "999",
            "-filelist",
            str(filelist_path),
        ]
        mock_run.assert_called_once_with(expected_command, check=True)
        self.assertFalse(filelist_path.exists())

    @patch("depot_util.subprocess.run")
    def test_download_steam_inf_deletes_temporary_filelist(self, mock_run) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            depot_dir = Path(tmp)
            steam_inf = depot_dir / "game" / "csgo" / "steam.inf"
            steam_inf.parent.mkdir(parents=True)
            steam_inf.write_text("PatchVersion=1.41.6.1\n", encoding="utf-8")

            bump_download.download_and_parse_steam_inf(
                manifest_id="999",
                app="730",
                os_name="all-platform",
                depot_dir=depot_dir,
                username=None,
                password=None,
                remember_password=False,
            )

            command = mock_run.call_args.args[0]
            filelist_path = Path(command[command.index("-filelist") + 1])
            self.assertFalse(filelist_path.exists())

    @patch("bump_download.download_and_parse_steam_inf", return_value="1.41.6.1")
    @patch("bump_download.fetch_manifest_id", side_effect=["base", "win", "linux"])
    def test_discover_latest_fetches_patch_version_and_manifests(
        self,
        mock_fetch_manifest_id,
        mock_download_and_parse_steam_inf,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            depot_dir = Path(tmp) / "depot"

            patch_version, manifests = bump_download.discover_latest(
                app="730",
                os_name="all-platform",
                depot_dir=depot_dir,
                username="user",
                password="pass",
                remember_password=True,
            )

        self.assertEqual("1.41.6.1", patch_version)
        self.assertEqual({"2347771": "win", "2347773": "linux"}, manifests)
        self.assertEqual(
            ["2347770", "2347771", "2347773"],
            [mock_call.kwargs["depot"] for mock_call in mock_fetch_manifest_id.call_args_list],
        )
        mock_fetch_manifest_id.assert_has_calls(
            [
                call(
                    depot="2347770",
                    app="730",
                    os_name="all-platform",
                    output_dir=ANY,
                    username="user",
                    password="pass",
                    remember_password=True,
                ),
                call(
                    depot="2347771",
                    app="730",
                    os_name="all-platform",
                    output_dir=ANY,
                    username="user",
                    password="pass",
                    remember_password=True,
                ),
                call(
                    depot="2347773",
                    app="730",
                    os_name="all-platform",
                    output_dir=ANY,
                    username="user",
                    password="pass",
                    remember_password=True,
                ),
            ]
        )
        mock_download_and_parse_steam_inf.assert_called_once_with(
            manifest_id="base",
            app="730",
            os_name="all-platform",
            depot_dir=depot_dir,
            username="user",
            password="pass",
            remember_password=True,
        )

    def test_plan_new_entry_for_new_patch_version(self) -> None:
        downloads = [
            {
                "tag": "14160",
                "name": "1.41.6.0",
                "manifests": {"2347771": "1", "2347773": "2"},
            }
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertTrue(plan.updated)
        self.assertEqual("14161", plan.tag)

    def test_plan_suffix_for_same_version_new_manifests(self) -> None:
        downloads = [
            {
                "tag": "14161",
                "name": "1.41.6.1",
                "manifests": {"2347771": "11", "2347773": "22"},
            },
            {
                "tag": "14161b",
                "name": "1.41.6.1",
                "manifests": {"2347771": "33", "2347773": "44"},
            },
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "55", "2347773": "66"},
        )

        self.assertTrue(plan.updated)
        self.assertEqual("14161c", plan.tag)

    def test_plan_no_update_for_existing_manifest_pair(self) -> None:
        downloads = [
            {
                "tag": "14161",
                "name": "1.41.6.1",
                "manifests": {"2347771": "11", "2347773": "22"},
            }
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertFalse(plan.updated)
        self.assertEqual("14161", plan.tag)

    def test_plan_rejects_missing_input_manifest_key(self) -> None:
        with self.assertRaises(bump_download.BumpError):
            bump_download.plan_download_entry(
                [],
                patch_version="1.41.6.1",
                manifests={"2347771": "11"},
            )

    def test_plan_rejects_missing_entry_manifest_key(self) -> None:
        downloads = [
            {
                "tag": "14161",
                "name": "1.41.6.1",
                "manifests": {"2347771": "11"},
            }
        ]

        with self.assertRaises(bump_download.BumpError):
            bump_download.plan_download_entry(
                downloads,
                patch_version="1.41.6.1",
                manifests={"2347771": "11", "2347773": "22"},
            )

    def test_plan_rejects_non_mapping_input_manifests(self) -> None:
        with self.assertRaises(bump_download.BumpError):
            bump_download.plan_download_entry(
                [],
                patch_version="1.41.6.1",
                manifests=["11", "22"],
            )

    def test_plan_rejects_non_mapping_entry_manifests(self) -> None:
        downloads = [
            {
                "tag": "14161",
                "name": "1.41.6.1",
                "manifests": ["11", "22"],
            }
        ]

        with self.assertRaises(bump_download.BumpError):
            bump_download.plan_download_entry(
                downloads,
                patch_version="1.41.6.1",
                manifests={"2347771": "11", "2347773": "22"},
            )

    def test_plan_copies_manifest_mapping(self) -> None:
        manifests = {"2347771": "11", "2347773": "22"}

        plan = bump_download.plan_download_entry(
            [],
            patch_version="1.41.6.1",
            manifests=manifests,
        )
        manifests["2347771"] = "changed"

        self.assertEqual({"2347771": "11", "2347773": "22"}, plan.manifests)

    def test_branch_entries_do_not_dedupe_default_branch(self) -> None:
        downloads = [
            {
                "tag": "14161",
                "name": "1.41.6.1",
                "branch": "animgraph_2_beta",
                "manifests": {"2347771": "11", "2347773": "22"},
            }
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertTrue(plan.updated)
        self.assertEqual("14161b", plan.tag)

    def test_append_download_entry_preserves_existing_inline_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text(
                "\n".join(
                    [
                        "downloads:",
                        '  - tag: "14160" # keep me',
                        "    name: 1.41.6.0",
                        "    manifests:",
                        '      "2347771": "1"',
                        '      "2347773": "2"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            data, downloads = bump_download.load_config(config)
            bump_download.append_download_entry(
                downloads,
                bump_download.BumpPlan(
                    updated=True,
                    tag="14161",
                    patch_version="1.41.6.1",
                    manifests={"2347771": "11", "2347773": "22"},
                ),
            )
            bump_download.save_config(config, data)

            text = config.read_text(encoding="utf-8")

        self.assertIn("# keep me", text)
        self.assertIn('tag: "14161"', text)
        self.assertIn("name: 1.41.6.1", text)
        self.assertIn('"2347771": "11"', text)
        self.assertIn('"2347773": "22"', text)

    def test_write_github_output_for_update_and_no_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.txt"
            bump_download.write_github_output(output, updated=True, tag="14161")
            self.assertEqual(
                "updated=true\ntag=14161\n",
                output.read_text(encoding="utf-8"),
            )

            bump_download.write_github_output(output, updated=False, tag=None)
            self.assertEqual(
                "updated=true\ntag=14161\nupdated=false\n",
                output.read_text(encoding="utf-8"),
            )

    @patch("bump_download.subprocess.run")
    def test_create_commit_does_not_create_a_release_tag(self, mock_run) -> None:
        bump_download.create_commit(
            config_path=Path("download.yaml"),
            patch_version="1.41.6.1",
        )

        self.assertEqual(
            [
                call(["git", "add", "download.yaml"], check=True),
                call(
                    ["git", "commit", "-m", "chore(download): Update download manifest for 1.41.6.1"],
                    check=True,
                ),
            ],
            mock_run.call_args_list,
        )

    @patch("bump_download.subprocess.run")
    def test_git_output_raises_bump_error_on_command_failure(self, mock_run) -> None:
        mock_run.return_value = bump_download.subprocess.CompletedProcess(
            ["git", "status"],
            128,
            stdout="",
            stderr="fatal: not a git repository\n",
        )

        with self.assertRaisesRegex(bump_download.BumpError, "fatal: not a git repository"):
            bump_download.git_output(["git", "status"])

        mock_run.assert_called_once_with(
            ["git", "status"],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch("bump_download.subprocess.run")
    def test_local_tag_exists_returns_false_for_missing_ref(self, mock_run) -> None:
        mock_run.return_value = bump_download.subprocess.CompletedProcess(
            ["git", "show-ref"],
            1,
            stdout="",
            stderr="",
        )

        self.assertFalse(bump_download.local_tag_exists("14161"))

        mock_run.assert_called_once_with(
            ["git", "show-ref", "--verify", "--quiet", "refs/tags/14161"],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch("bump_download.subprocess.run")
    def test_local_tag_exists_raises_on_git_failure(self, mock_run) -> None:
        mock_run.return_value = bump_download.subprocess.CompletedProcess(
            ["git", "show-ref"],
            128,
            stdout="",
            stderr="fatal: not a git repository\n",
        )

        with self.assertRaisesRegex(bump_download.BumpError, "fatal: not a git repository"):
            bump_download.local_tag_exists("14161")

    @patch("bump_download.subprocess.run")
    def test_remote_tag_exists_returns_false_for_no_matching_ref(self, mock_run) -> None:
        mock_run.return_value = bump_download.subprocess.CompletedProcess(
            ["git", "ls-remote"],
            2,
            stdout="",
            stderr="",
        )

        self.assertFalse(bump_download.remote_tag_exists("14161"))

        mock_run.assert_called_once_with(
            ["git", "ls-remote", "--exit-code", "--tags", "origin", "14161"],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch("bump_download.subprocess.run")
    def test_remote_tag_exists_raises_on_git_failure(self, mock_run) -> None:
        mock_run.return_value = bump_download.subprocess.CompletedProcess(
            ["git", "ls-remote"],
            128,
            stdout="",
            stderr="fatal: unable to access origin\n",
        )

        with self.assertRaisesRegex(bump_download.BumpError, "fatal: unable to access origin"):
            bump_download.remote_tag_exists("14161")

    @patch("bump_download.create_commit")
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_dry_run_does_not_commit(self, _discover, commit) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text(
                "downloads:\n"
                '  - tag: "14160"\n'
                "    name: 1.41.6.0\n"
                "    manifests:\n"
                '      "2347771": "1"\n'
                '      "2347773": "2"\n',
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config),
                depotdir=str(Path(tmp) / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=None,
                dry_run=True,
            )

            self.assertEqual(0, bump_download.run(args))

        commit.assert_not_called()

    @patch("bump_download.remote_tag_exists")
    @patch("bump_download.local_tag_exists")
    @patch("bump_download.create_commit")
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_dry_run_existing_entry_is_no_update_without_release_checks(
        self,
        _discover,
        commit,
        local_tag_exists,
        remote_tag_exists,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            output = Path(tmp) / "github_output.txt"
            config.write_text(
                "downloads:\n"
                '  - tag: "14161"\n'
                "    name: 1.41.6.1\n"
                "    manifests:\n"
                '      "2347771": "11"\n'
                '      "2347773": "22"\n',
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config),
                depotdir=str(Path(tmp) / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=str(output),
                dry_run=True,
            )

            self.assertEqual(0, bump_download.run(args))
            output_text = output.read_text(encoding="utf-8")

        commit.assert_not_called()
        local_tag_exists.assert_not_called()
        remote_tag_exists.assert_not_called()
        self.assertEqual("updated=false\n", output_text)

    @patch("bump_download.create_commit")
    @patch("bump_download.remote_tag_exists", return_value=False)
    @patch("bump_download.local_tag_exists", return_value=False)
    @patch("bump_download.ensure_clean_worktree")
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_run_new_entry_commits_config_without_creating_tag_and_writes_output(
        self,
        _discover,
        ensure_clean_worktree,
        local_tag_exists,
        remote_tag_exists,
        create_commit,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            output = Path(tmp) / "github_output.txt"
            config.write_text(
                "downloads:\n"
                '  - tag: "14160"\n'
                "    name: 1.41.6.0\n"
                "    manifests:\n"
                '      "2347771": "1"\n'
                '      "2347773": "2"\n',
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config),
                depotdir=str(Path(tmp) / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=str(output),
                dry_run=False,
            )

            self.assertEqual(0, bump_download.run(args))
            text = config.read_text(encoding="utf-8")
            output_text = output.read_text(encoding="utf-8")

        ensure_clean_worktree.assert_called_once_with()
        local_tag_exists.assert_called_once_with("14161")
        remote_tag_exists.assert_called_once_with("14161")
        create_commit.assert_called_once_with(config, "1.41.6.1")
        self.assertIn('tag: "14161"', text)
        self.assertIn("name: 1.41.6.1", text)
        self.assertIn('"2347771": "11"', text)
        self.assertIn('"2347773": "22"', text)
        self.assertEqual("updated=true\ntag=14161\n", output_text)

    @patch("bump_download.create_commit")
    @patch("bump_download.ensure_clean_worktree")
    @patch("bump_download.remote_tag_exists")
    @patch("bump_download.local_tag_exists")
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_run_existing_entry_is_no_update_without_release_checks(
        self,
        _discover,
        local_tag_exists,
        remote_tag_exists,
        ensure_clean_worktree,
        create_commit,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            output = Path(tmp) / "github_output.txt"
            original_text = (
                "downloads:\n"
                '  - tag: "14161"\n'
                "    name: 1.41.6.1\n"
                "    manifests:\n"
                '      "2347771": "11"\n'
                '      "2347773": "22"\n'
            )
            config.write_text(original_text, encoding="utf-8")
            args = argparse.Namespace(
                config=str(config),
                depotdir=str(Path(tmp) / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=str(output),
                dry_run=False,
            )

            self.assertEqual(0, bump_download.run(args))
            self.assertEqual(original_text, config.read_text(encoding="utf-8"))
            output_text = output.read_text(encoding="utf-8")

        local_tag_exists.assert_not_called()
        remote_tag_exists.assert_not_called()
        ensure_clean_worktree.assert_not_called()
        create_commit.assert_not_called()
        self.assertEqual("updated=false\n", output_text)

    @patch("bump_download.parse_args", return_value=argparse.Namespace())
    def test_main_maps_known_errors_to_exit_codes(self, _parse_args) -> None:
        cases = [
            (bump_download.BumpError("bad config"), 1),
            (FileNotFoundError(), 1),
            (bump_download.subprocess.CalledProcessError(7, ["git"]), 7),
        ]

        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                with patch("bump_download.run", side_effect=error):
                    with patch("builtins.print"):
                        self.assertEqual(expected, bump_download.main())

    def test_load_config_wraps_invalid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text("downloads:\n  - tag: [broken\n", encoding="utf-8")

            with self.assertRaises(bump_download.BumpError):
                bump_download.load_config(config)

    def test_load_config_rejects_duplicate_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text(
                "\n".join(
                    [
                        "downloads:",
                        '  - tag: "14161"',
                        "    name: 1.41.6.1",
                        "    manifests:",
                        '      "2347771": "11"',
                        '      "2347773": "22"',
                        '  - tag: "14161"',
                        "    name: 1.41.6.1",
                        "    manifests:",
                        '      "2347771": "33"',
                        '      "2347773": "44"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaises(bump_download.BumpError):
                bump_download.load_config(config)

    def test_versioned_config_plan_uses_immediate_previous_default_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            configs = Path(tmp) / "configs"
            configs.mkdir()
            (configs / "14168.yaml").write_bytes(b"# exact seed\r\nmodules: []\r\n")
            downloads = [
                {"tag": "14168", "name": "1.41.6.8", "manifests": {"2347771": "1", "2347773": "2"}},
                {
                    "tag": "14150b",
                    "name": "1.41.5.0",
                    "branch": "animgraph_2_beta",
                    "manifests": {"2347771": "3", "2347773": "4"},
                },
            ]
            plan = bump_download.plan_download_entry(
                downloads,
                "1.41.6.9",
                {"2347771": "11", "2347773": "22"},
                configs_dir=configs,
            )
            self.assertEqual("14168", plan.analysis_config_source_gamever)
            self.assertEqual("configs/14169.yaml", plan.analysis_config_path)

    def test_config_seed_paths_preserve_caller_path_spelling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            configs = root / "nested" / ".." / "configs"
            configs.mkdir(parents=True)
            source = configs / "14160.yaml"
            source.write_bytes(b"modules: []\n")

            actual_source, actual_target = bump_download._config_seed_paths(configs, "14160", "14161")

            self.assertEqual(source, actual_source)
            self.assertEqual(configs / "14161.yaml", actual_target)

    @patch("bump_download.create_commit")
    @patch("bump_download.remote_tag_exists", return_value=False)
    @patch("bump_download.local_tag_exists", return_value=False)
    @patch("bump_download.ensure_clean_worktree")
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_strict_run_copies_and_commits_download_and_version_config(
        self,
        _discover,
        _clean,
        _local_tag,
        _remote_tag,
        create_commit,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "download.yaml"
            configs = root / "configs"
            output = root / "output.txt"
            configs.mkdir()
            seed = b"# preserve comments\r\nmodules: []\r\n"
            (configs / "14160.yaml").write_bytes(seed)
            config.write_text(
                'downloads:\n  - tag: "14160"\n    name: 1.41.6.0\n    manifests:\n      "2347771": "1"\n      "2347773": "2"\n',
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config),
                configs_dir=str(configs),
                depotdir=str(root / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=str(output),
                dry_run=False,
            )
            self.assertEqual(0, bump_download.run(args))
            target = configs / "14161.yaml"
            self.assertEqual(seed, target.read_bytes())
            create_commit.assert_called_once_with([config, target], "1.41.6.1")
            self.assertIn("analysis_config_source_gamever=14160", output.read_text(encoding="utf-8"))
            self.assertIn("analysis_config_path=configs/14161.yaml", output.read_text(encoding="utf-8"))

    @patch("bump_download.remote_tag_exists", return_value=False)
    @patch("bump_download.discover_latest", return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}))
    def test_recovery_dry_run_requires_existing_accepted_config(self, _discover, _remote_tag) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            configs = root / "configs"
            configs.mkdir()
            config = root / "download.yaml"
            config.write_text(
                'downloads:\n  - tag: "14161"\n    name: 1.41.6.1\n    manifests:\n      "2347771": "11"\n      "2347773": "22"\n',
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config),
                configs_dir=str(configs),
                depotdir=str(root / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=None,
                dry_run=True,
            )
            with self.assertRaisesRegex(bump_download.BumpError, "Missing accepted analysis config"):
                bump_download.run(args)

    def test_load_config_rejects_missing_downloads_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text("not_downloads: []\n", encoding="utf-8")

            with self.assertRaises(bump_download.BumpError):
                bump_download.load_config(config)


class TestBumpDownloadCandidate(unittest.TestCase):
    repository = "HLND2T/CS2_VibeSignatures"
    gamever = "14161"
    source_gamever = "14160"

    def _git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            self.fail(result.stderr or f"git {' '.join(arguments)} failed")
        return result.stdout.strip()

    def _producer(self, root: Path, *, enroll_lock: bool = True) -> str:
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.email", "test@example.com")
        self._git(root, "config", "user.name", "Test")
        write_config(
            root / "configs" / f"{self.source_gamever}.yaml",
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": [],
                }
            ],
        )
        (root / "download.yaml").write_text(
            'downloads:\n  - tag: "14160"\n    name: 1.41.6.0\n    manifests:\n'
            '      "2347771": "1"\n      "2347773": "2"\n',
            encoding="utf-8",
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")
        document, downloads = bump_download.load_config(root / "download.yaml")
        bump_download.append_download_entry(
            downloads,
            bump_download.BumpPlan(
                updated=True,
                tag=self.gamever,
                patch_version="1.41.6.1",
                manifests={"2347771": "11", "2347773": "22"},
            ),
        )
        bump_download.save_config(root / "download.yaml", document)
        (root / "configs" / f"{self.gamever}.yaml").write_bytes(
            (root / "configs" / f"{self.source_gamever}.yaml").read_bytes()
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "bump")
        if enroll_lock:
            binary_root = root.parent / "fresh-binary-root" / self.gamever
            write_binary(binary_root / "server" / "server.dll", b"fresh depot binary")
            bdc.enroll_bump_binary_lock(
                repo_root=root,
                base_sha=base_sha,
                gamever=self.gamever,
                source_gamever=self.source_gamever,
                repository=self.repository,
                binary_root=binary_root,
            )
        return base_sha

    def test_candidate_is_verified_and_recommitted_by_hosted_publisher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            base_sha = self._producer(root)
            candidate_root = Path(temporary) / "candidate"
            manifest = bdc.build_bump_candidate(
                repo_root=root,
                base_sha=base_sha,
                gamever=self.gamever,
                source_gamever=self.source_gamever,
                repository=self.repository,
                workflow_run_id="123",
                workflow_run_attempt="1",
                output_root=candidate_root,
            )
            self._git(root, "checkout", "--detach", base_sha)

            result = bdc.prepare_bump_commit(
                repo_root=root,
                candidate_root=candidate_root,
                manifest=candidate_root / "candidate-manifest.json",
                repository=self.repository,
                base_sha=base_sha,
                gamever=self.gamever,
                source_gamever=self.source_gamever,
                actions_artifact_name=manifest["actions_artifact_name"],
                actions_artifact_digest="sha256:" + "a" * 64,
                workflow_run_id="123",
                workflow_run_attempt="1",
                workflow_run_url="https://github.example/run/123",
            )

            self.assertEqual(base_sha, result["parent_sha"])
            self.assertEqual(
                ["binary_locks/14161.json", "configs/14161.yaml", "download.yaml"],
                result["changed_paths"],
            )
            self.assertRegex(manifest["binary_lock_sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(result["commit_sha"], self._git(root, "rev-parse", "HEAD"))

    def test_enrollment_requires_checkout_external_fresh_binary_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            base_sha = self._producer(root, enroll_lock=False)
            binary_root = root / "bin" / self.gamever

            with self.assertRaisesRegex(bdc.BumpDownloadCandidateError, "outside the repository"):
                bdc.enroll_bump_binary_lock(
                    repo_root=root,
                    base_sha=base_sha,
                    gamever=self.gamever,
                    source_gamever=self.source_gamever,
                    repository=self.repository,
                    binary_root=binary_root,
                )

            external_root = root.parent / "fresh-with-extra" / self.gamever
            write_binary(external_root / "server" / "server.dll")
            write_binary(external_root / "unexpected.bin")
            with self.assertRaisesRegex(bdc.BumpDownloadCandidateError, "allowlist mismatch"):
                bdc.enroll_bump_binary_lock(
                    repo_root=root,
                    base_sha=base_sha,
                    gamever=self.gamever,
                    source_gamever=self.source_gamever,
                    repository=self.repository,
                    binary_root=external_root,
                )

    def test_candidate_rejects_extra_producer_changes_and_package_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            base_sha = self._producer(root)
            (root / "README.md").write_text("unexpected\n", encoding="utf-8")
            self._git(root, "add", "README.md")
            self._git(root, "commit", "--amend", "--no-edit")
            with self.assertRaisesRegex(bdc.BumpDownloadCandidateError, "changed-path allowlist"):
                bdc.build_bump_candidate(
                    repo_root=root,
                    base_sha=base_sha,
                    gamever=self.gamever,
                    source_gamever=self.source_gamever,
                    repository=self.repository,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    output_root=Path(temporary) / "rejected",
                )

            self._git(root, "rm", "README.md")
            self._git(root, "commit", "--amend", "--no-edit")
            candidate_root = Path(temporary) / "candidate"
            manifest = bdc.build_bump_candidate(
                repo_root=root,
                base_sha=base_sha,
                gamever=self.gamever,
                source_gamever=self.source_gamever,
                repository=self.repository,
                workflow_run_id="123",
                workflow_run_attempt="1",
                output_root=candidate_root,
            )
            (candidate_root / "files" / "download.yaml").write_bytes(b"downloads: []\n")
            self._git(root, "checkout", "--detach", base_sha)
            with self.assertRaisesRegex(bdc.BumpDownloadCandidateError, "inventory"):
                bdc.prepare_bump_commit(
                    repo_root=root,
                    candidate_root=candidate_root,
                    manifest=candidate_root / "candidate-manifest.json",
                    repository=self.repository,
                    base_sha=base_sha,
                    gamever=self.gamever,
                    source_gamever=self.source_gamever,
                    actions_artifact_name=manifest["actions_artifact_name"],
                    actions_artifact_digest="sha256:" + "a" * 64,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    workflow_run_url="https://github.example/run/123",
                )

    def test_hosted_prepare_rejects_forged_self_hosted_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            base_sha = self._producer(root)
            candidate_root = Path(temporary) / "candidate"
            manifest = bdc.build_bump_candidate(
                repo_root=root,
                base_sha=base_sha,
                gamever=self.gamever,
                source_gamever=self.source_gamever,
                repository=self.repository,
                workflow_run_id="123",
                workflow_run_attempt="1",
                output_root=candidate_root,
            )
            self._git(root, "checkout", "--detach", base_sha)
            valid = {
                "repo_root": root,
                "candidate_root": candidate_root,
                "manifest": candidate_root / "candidate-manifest.json",
                "repository": self.repository,
                "base_sha": base_sha,
                "gamever": self.gamever,
                "source_gamever": self.source_gamever,
                "actions_artifact_name": manifest["actions_artifact_name"],
                "actions_artifact_digest": "sha256:" + "a" * 64,
                "workflow_run_id": "123",
                "workflow_run_attempt": "1",
                "workflow_run_url": "https://github.example/run/123",
            }

            cases = (
                ({"gamever": "14161;Write-Host owned"}, "GAMEVER identity"),
                ({"actions_artifact_name": "forged-candidate"}, "publication identity"),
                ({"actions_artifact_digest": "sha256:not-a-digest"}, "Artifact digest"),
            )
            for overrides, message in cases:
                with self.subTest(overrides=overrides):
                    arguments = {**valid, **overrides}
                    with self.assertRaisesRegex(bdc.BumpDownloadCandidateError, message):
                        bdc.prepare_bump_commit(**arguments)


if __name__ == "__main__":
    unittest.main()
