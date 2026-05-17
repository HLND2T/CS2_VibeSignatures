import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import ANY, call, patch

import bump_download


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
    @patch("bump_download.subprocess.run")
    def test_run_command_redacts_password_in_logs(self, mock_run, mock_print) -> None:
        command = ["DepotDownloader", "-app", "730", "-password", "secret"]

        bump_download.run_command(command)

        printed = mock_print.call_args.args[0]
        self.assertIn("-password <redacted>", printed)
        self.assertNotIn("secret", printed)
        mock_run.assert_called_once_with(command, check=True)
        self.assertEqual("secret", mock_run.call_args.args[0][4])

    @patch("bump_download.subprocess.run")
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

    @patch("bump_download.subprocess.run")
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

    @patch("bump_download.subprocess.run")
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
    def test_create_commit_and_tag_runs_expected_git_commands(self, mock_run) -> None:
        bump_download.create_commit_and_tag(
            config_path=Path("download.yaml"),
            tag="14161",
            patch_version="1.41.6.1",
        )

        self.assertEqual(
            [
                call(["git", "add", "download.yaml"], check=True),
                call(
                    ["git", "commit", "-m", "chore(download): 更新 1.41.6.1 下载清单"],
                    check=True,
                ),
                call(["git", "tag", "14161"], check=True),
            ],
            mock_run.call_args_list,
        )

    @patch("bump_download.create_commit_and_tag")
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
    @patch("bump_download.create_commit_and_tag")
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_dry_run_existing_entry_does_not_check_git(
        self,
        _discover,
        commit,
        local_tag_exists,
        remote_tag_exists,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
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
                github_output=None,
                dry_run=True,
            )

            self.assertEqual(0, bump_download.run(args))

        commit.assert_not_called()
        local_tag_exists.assert_not_called()
        remote_tag_exists.assert_not_called()

    @patch("bump_download.remote_tag_exists", return_value=False)
    @patch("bump_download.local_tag_exists", return_value=False)
    def test_tag_repair_when_entry_exists_but_remote_tag_missing(
        self, _local, _remote
    ) -> None:
        downloads = [
            {
                "tag": "14161",
                "name": "1.41.6.1",
                "manifests": {"2347771": "11", "2347773": "22"},
            }
        ]

        plan = bump_download.plan_tag_repair(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertIsNotNone(plan)
        self.assertTrue(plan.updated)
        self.assertTrue(plan.repair_tag)
        self.assertEqual("14161", plan.tag)

    @patch("bump_download.create_commit_and_tag")
    @patch("bump_download.remote_tag_exists", return_value=False)
    @patch("bump_download.local_tag_exists", return_value=False)
    @patch("bump_download.ensure_clean_worktree")
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_run_new_entry_commits_tag_and_writes_output(
        self,
        _discover,
        ensure_clean_worktree,
        local_tag_exists,
        remote_tag_exists,
        create_commit_and_tag,
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
        create_commit_and_tag.assert_called_once_with(config, "14161", "1.41.6.1")
        self.assertIn('tag: "14161"', text)
        self.assertIn("name: 1.41.6.1", text)
        self.assertIn('"2347771": "11"', text)
        self.assertIn('"2347773": "22"', text)
        self.assertEqual("updated=true\ntag=14161\n", output_text)

    @patch("bump_download.create_commit_and_tag")
    @patch("bump_download.ensure_clean_worktree")
    @patch("bump_download.remote_tag_exists", return_value=True)
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_run_existing_entry_remote_tag_present_writes_no_update(
        self,
        _discover,
        remote_tag_exists,
        ensure_clean_worktree,
        create_commit_and_tag,
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

        remote_tag_exists.assert_called_once_with("14161")
        ensure_clean_worktree.assert_not_called()
        create_commit_and_tag.assert_not_called()
        self.assertEqual("updated=false\n", output_text)

    @patch("bump_download.create_commit_and_tag")
    @patch("bump_download.create_repair_tag")
    @patch("bump_download.ensure_local_tag_matches_head")
    @patch("bump_download.ensure_clean_worktree")
    @patch("bump_download.remote_tag_exists", return_value=False)
    @patch(
        "bump_download.discover_latest",
        return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}),
    )
    def test_run_repair_mode_creates_tag_and_writes_update(
        self,
        _discover,
        remote_tag_exists,
        ensure_clean_worktree,
        ensure_local_tag_matches_head,
        create_repair_tag,
        create_commit_and_tag,
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

        remote_tag_exists.assert_called_once_with("14161")
        ensure_clean_worktree.assert_called_once_with()
        ensure_local_tag_matches_head.assert_called_once_with("14161")
        create_repair_tag.assert_called_once_with("14161")
        create_commit_and_tag.assert_not_called()
        self.assertEqual("updated=true\ntag=14161\n", output_text)

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

    def test_load_config_rejects_missing_downloads_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text("not_downloads: []\n", encoding="utf-8")

            with self.assertRaises(bump_download.BumpError):
                bump_download.load_config(config)


if __name__ == "__main__":
    unittest.main()
