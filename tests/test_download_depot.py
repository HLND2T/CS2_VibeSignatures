import argparse
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

import depot_util
import download_depot


class TestDownloadDepot(unittest.TestCase):
    def _write_yaml(self, content: str) -> str:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", delete=False) as tmp:
            tmp.write(content)
            return tmp.name

    def test_load_downloads_and_find_entry_exact_match(self) -> None:
        config_path = self._write_yaml(
            """
downloads:
  - tag: alpha
    manifests:
      "2347771": "111"
  - tag: beta
    manifests:
      "2347773": "222"
"""
        )
        try:
            downloads = download_depot.load_downloads(config_path)
            self.assertEqual(2, len(downloads))

            entry = download_depot.find_download_entry(downloads, "alpha")
            self.assertEqual("alpha", entry["tag"])
            self.assertEqual("111", entry["manifests"]["2347771"])
        finally:
            os.unlink(config_path)

    def test_find_download_entry_raises_when_tag_not_found(self) -> None:
        config_path = self._write_yaml(
            """
downloads:
  - tag: alpha
    manifests:
      "2347771": "111"
"""
        )
        try:
            downloads = download_depot.load_downloads(config_path)
            with self.assertRaises(download_depot.ConfigError):
                download_depot.find_download_entry(downloads, "missing")
        finally:
            os.unlink(config_path)

    def test_find_download_entry_raises_when_tag_duplicated(self) -> None:
        config_path = self._write_yaml(
            """
downloads:
  - tag: alpha
    manifests:
      "2347771": "111"
  - tag: alpha
    manifests:
      "2347773": "222"
"""
        )
        try:
            downloads = download_depot.load_downloads(config_path)
            with self.assertRaises(download_depot.ConfigError):
                download_depot.find_download_entry(downloads, "alpha")
        finally:
            os.unlink(config_path)

    def test_load_downloads_raises_when_top_level_is_not_mapping(self) -> None:
        config_path = self._write_yaml(
            """
- tag: alpha
  manifests:
    "2347771": "111"
"""
        )
        try:
            with self.assertRaises(download_depot.ConfigError):
                download_depot.load_downloads(config_path)
        finally:
            os.unlink(config_path)

    def test_load_module_filelist_collects_windows_and_linux_paths(self) -> None:
        config_path = self._write_yaml(
            textwrap.dedent(
                """
                modules:
                  - name: SDL3
                    path_windows: game/bin/win64/SDL3.dll
                    path_linux: game/bin/linuxsteamrt64/libSDL3.so.0
                  - name: server
                    path_windows: game/csgo/bin/win64/server.dll
                """
            )
        )
        try:
            paths = download_depot.load_module_filelist(config_path)
        finally:
            os.unlink(config_path)

        self.assertEqual(
            [
                "game/bin/linuxsteamrt64/libSDL3.so.0",
                "game/bin/win64/SDL3.dll",
                "game/csgo/bin/win64/server.dll",
            ],
            paths,
        )

    def test_load_module_filelist_raises_on_empty_modules(self) -> None:
        config_path = self._write_yaml("modules: []\n")
        try:
            with self.assertRaises(download_depot.ConfigError):
                download_depot.load_module_filelist(config_path)
        finally:
            os.unlink(config_path)

    def test_load_module_filelist_raises_when_modules_missing(self) -> None:
        config_path = self._write_yaml("other: value\n")
        try:
            with self.assertRaises(download_depot.ConfigError):
                download_depot.load_module_filelist(config_path)
        finally:
            os.unlink(config_path)

    def _filelist_capture_side_effect(self, captured: list[str]):
        """Read the temp -filelist before DepotDownloader subprocess.run completes."""

        def _side_effect(command, check=True):
            self.assertTrue(check)
            self.assertIn("-filelist", command)
            filelist_path = Path(command[command.index("-filelist") + 1])
            captured.append(filelist_path.read_text(encoding="utf-8"))
            return None

        return _side_effect

    def test_download_manifests_dispatches_declared_depots_only(self) -> None:
        manifests = {
            "2347771": "111",
            "2347773": "222",
        }
        filelist = [
            "game/bin/win64/SDL3.dll",
            "game/bin/linuxsteamrt64/libSDL3.so.0",
        ]
        captured: list[str] = []

        with patch(
            "depot_util.subprocess.run",
            side_effect=self._filelist_capture_side_effect(captured),
        ) as mock_run:
            download_depot.download_manifests(
                manifests=manifests,
                app="730",
                os_name="all-platform",
                depot_dir="cs2_depot",
                filelist=filelist,
            )

        self.assertEqual(2, mock_run.call_count)

        observed_filelist_paths = set()
        for call_args in mock_run.call_args_list:
            command = call_args.args[0]
            filelist_index = command.index("-filelist")
            filelist_path = command[filelist_index + 1]
            observed_filelist_paths.add(filelist_path)

            self.assertEqual(
                [
                    "DepotDownloader",
                    "-app",
                    "730",
                    "-os",
                    "all-platform",
                    "-dir",
                    "cs2_depot",
                ],
                [command[0], command[1], command[2], command[5], command[6], command[7], command[8]],
            )
            self.assertEqual("-depot", command[3])
            self.assertIn(command[4], manifests.keys())
            self.assertEqual("-manifest", command[-4])
            self.assertEqual(manifests[command[4]], command[-3])
            self.assertEqual("-filelist", command[-2])

        # All depots share the same temp filelist file path
        self.assertEqual(1, len(observed_filelist_paths))
        self.assertEqual(2, len(captured))
        expected_contents = "\n".join(filelist) + "\n"
        self.assertEqual([expected_contents, expected_contents], captured)
        # Temp file is cleaned up afterwards
        self.assertFalse(Path(next(iter(observed_filelist_paths))).exists())

    def test_download_manifests_adds_branch_when_configured(self) -> None:
        manifests = {"2347771": "111"}
        filelist = ["game/bin/win64/SDL3.dll"]

        with patch(
            "depot_util.subprocess.run",
            side_effect=self._filelist_capture_side_effect([]),
        ) as mock_run:
            download_depot.download_manifests(
                manifests=manifests,
                app="730",
                os_name="all-platform",
                depot_dir="cs2_depot",
                filelist=filelist,
                branch="animgraph_2_beta",
            )

        self.assertEqual(1, mock_run.call_count)
        command = mock_run.call_args.args[0]
        self.assertIn("-branch", command)
        branch_index = command.index("-branch")
        self.assertEqual("animgraph_2_beta", command[branch_index + 1])
        self.assertIn("-manifest", command)
        self.assertIn("-filelist", command)

    def test_download_manifests_appends_auth_arguments(self) -> None:
        manifests = {"2347771": "111"}
        filelist = ["game/bin/win64/SDL3.dll"]

        with patch(
            "depot_util.subprocess.run",
            side_effect=self._filelist_capture_side_effect([]),
        ) as mock_run:
            download_depot.download_manifests(
                manifests=manifests,
                app="730",
                os_name="all-platform",
                depot_dir="cs2_depot",
                filelist=filelist,
                username="user",
                password="secret",
                remember_password=True,
            )

        command = mock_run.call_args.args[0]
        self.assertIn("-username", command)
        self.assertEqual("user", command[command.index("-username") + 1])
        self.assertIn("-password", command)
        self.assertEqual("secret", command[command.index("-password") + 1])
        self.assertIn("-remember-password", command)

    def test_download_manifests_raises_when_filelist_empty(self) -> None:
        with self.assertRaises(download_depot.ConfigError):
            download_depot.download_manifests(
                manifests={"2347771": "111"},
                app="730",
                os_name="all-platform",
                depot_dir="cs2_depot",
                filelist=[],
            )

    @patch("depot_util.time.sleep")
    @patch("depot_util.subprocess.run")
    def test_download_manifests_retries_on_subprocess_failure(self, mock_run, mock_sleep) -> None:
        manifests = {"2347771": "111"}
        filelist = ["game/bin/win64/SDL3.dll"]
        mock_run.side_effect = [
            subprocess.CalledProcessError(1, ["DepotDownloader"]),
            None,
        ]

        download_depot.download_manifests(
            manifests=manifests,
            app="730",
            os_name="all-platform",
            depot_dir="cs2_depot",
            filelist=filelist,
        )

        self.assertEqual(2, mock_run.call_count)
        mock_sleep.assert_called_once_with(depot_util.DEFAULT_DEPOTDOWNLOADER_RETRY_DELAY_SECONDS)

    def test_main_stores_depot_under_gamever_subdirectory(self) -> None:
        fake_args = argparse.Namespace(
            tag="14168",
            config="download.yaml",
            configyaml=str(Path(__file__).resolve()),
            depotdir="cs2_depot",
            app="730",
            os="all-platform",
            username=None,
            password=None,
            remember_password=False,
        )
        fake_entry = {
            "tag": "14168",
            "manifests": {"2347771": "111"},
        }

        with (
            patch("download_depot.parse_args", return_value=fake_args),
            patch("download_depot.load_downloads", return_value=[fake_entry]),
            patch("download_depot.find_download_entry", return_value=fake_entry),
            patch(
                "download_depot.load_module_filelist",
                return_value=["game/bin/win64/SDL3.dll"],
            ),
            patch("depot_util.subprocess.run") as mock_run,
        ):
            self.assertEqual(0, download_depot.main())

        command = mock_run.call_args.args[0]
        self.assertEqual(os.path.join("cs2_depot", "14168"), command[command.index("-dir") + 1])

    def test_main_returns_nonzero_when_depotdownloader_missing(self) -> None:
        fake_args = argparse.Namespace(
            tag="14168",
            config="download.yaml",
            configyaml=str(Path(__file__).resolve()),
            depotdir="cs2_depot",
            app="730",
            os="all-platform",
            username=None,
            password=None,
            remember_password=False,
        )
        fake_entry = {
            "tag": "14168",
            "manifests": {"2347771": "111"},
        }

        with (
            patch("download_depot.parse_args", return_value=fake_args),
            patch("download_depot.load_downloads", return_value=[fake_entry]),
            patch("download_depot.find_download_entry", return_value=fake_entry),
            patch(
                "download_depot.load_module_filelist",
                return_value=["game/bin/win64/SDL3.dll"],
            ),
            patch("depot_util.subprocess.run", side_effect=FileNotFoundError("DepotDownloader")),
            patch("builtins.print") as mock_print,
        ):
            exit_code = download_depot.main()

        self.assertNotEqual(0, exit_code)
        printed = [" ".join(str(part) for part in one_call.args) for one_call in mock_print.call_args_list]
        self.assertTrue(any("DepotDownloader executable not found" in line for line in printed))


if __name__ == "__main__":
    unittest.main()
