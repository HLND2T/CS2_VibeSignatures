import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from unittest import mock as unittest_mock


SCRIPT = Path("init_gamebin.py")
SPEC = importlib.util.spec_from_file_location("init_gamebin", SCRIPT)
init_gamebin = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(init_gamebin)


def completed(command, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def response(*, status=200, chunks=(), reason="OK", headers=None):
    result = MagicMock()
    result.status_code = status
    result.reason = reason
    result.headers = dict(headers or {})
    result.iter_content.return_value = iter(chunks)
    result.__enter__.return_value = result
    result.__exit__.return_value = False
    return result


def git(cwd: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True)


class TestInitGamebin(unittest.TestCase):
    def test_script_resolves_its_own_repository_root(self) -> None:
        expected = SCRIPT.resolve().parent
        with patch.object(init_gamebin, "run_command", return_value=completed([], stdout=f"{expected}\n")):
            self.assertEqual(expected, init_gamebin.repository_root())

    def test_load_versions_preserves_order_and_rejects_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "download.yaml"
            path.write_text('downloads:\n  - tag: "14168"\n  - tag: "14169"\n', encoding="utf-8")
            self.assertEqual(["14168", "14169"], init_gamebin.load_versions(path))
            path.write_text('downloads:\n  - tag: "14168"\n  - tag: "14168"\n', encoding="utf-8")
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "duplicate"):
                init_gamebin.load_versions(path)

    def test_latest_and_exact_versions_must_come_from_download_yaml(self) -> None:
        versions = ["14168", "14168b", "14169"]
        self.assertEqual("14169", init_gamebin.select_version("latest", versions))
        self.assertEqual("14168b", init_gamebin.select_version("14168b", versions))
        with self.assertRaisesRegex(init_gamebin.InitGamebinError, "absent"):
            init_gamebin.select_version("14170", versions)

    def test_download_200_streams_and_404_is_the_only_missing_case(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "gamebin.7z"
            with patch.object(init_gamebin.requests, "get", return_value=response(chunks=[b"abc", b"def"])):
                self.assertTrue(init_gamebin.download_release_asset("https://example/archive", archive))
            self.assertEqual(b"abcdef", archive.read_bytes())
            archive.unlink()
            with patch.object(init_gamebin.requests, "get", return_value=response(status=404, reason="Not Found")):
                self.assertFalse(init_gamebin.download_release_asset("https://example/missing", archive))
            self.assertFalse(archive.exists())

    def test_download_non_404_http_failure_does_not_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "gamebin.7z"
            with patch.object(init_gamebin.requests, "get", return_value=response(status=503, reason="Unavailable")):
                with self.assertRaisesRegex(init_gamebin.InitGamebinError, "HTTP 503"):
                    init_gamebin.download_release_asset("https://example/archive", archive)

    def test_github_token_prefers_environment_over_gh(self) -> None:
        init_gamebin.github_token.cache_clear()
        with patch.object(
            init_gamebin,
            "subprocess",
            unittest_mock.MagicMock(**{"run.return_value": completed([], stdout="cli-token\n")}),
        ) as fake:
            with patch.dict(os.environ, {"GH_TOKEN": "  env-token  "}, clear=False):
                self.assertEqual("env-token", init_gamebin.github_token())
            fake.run.assert_not_called()

    def test_github_token_falls_back_to_gh_when_environment_is_empty(self) -> None:
        init_gamebin.github_token.cache_clear()
        with patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}, clear=False):
            with patch.object(init_gamebin.shutil, "which", return_value="/usr/bin/gh"):
                with patch.object(
                    init_gamebin,
                    "subprocess",
                    unittest_mock.MagicMock(**{"run.return_value": completed([], stdout="cli-token\n")}),
                ) as fake:
                    self.assertEqual("cli-token", init_gamebin.github_token())
        self.assertEqual(
            ["gh", "auth", "token", "--hostname", "github.com"],
            fake.run.call_args.args[0],
        )

    def test_github_token_is_none_without_environment_or_gh(self) -> None:
        init_gamebin.github_token.cache_clear()
        with patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}, clear=False):
            with patch.object(init_gamebin.shutil, "which", return_value=None):
                self.assertIsNone(init_gamebin.github_token())
        self.assertEqual({}, init_gamebin.github_request_headers())

    def test_release_requests_use_the_resolved_token(self) -> None:
        init_gamebin.github_token.cache_clear()
        with patch.dict(os.environ, {"GH_TOKEN": "env-token"}, clear=False):
            headers = init_gamebin.github_request_headers()
            self.assertEqual({"Authorization": "Bearer env-token", "X-GitHub-Api-Version": "2022-11-28"}, headers)
            init_gamebin.github_token.cache_clear()

    def test_release_tag_lookup_sends_authentication_headers(self) -> None:
        init_gamebin.github_token.cache_clear()
        document = {"object": {"type": "commit", "sha": "b" * 40}}
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "gamebin.7z"
            with patch.dict(os.environ, {"GH_TOKEN": "env-token"}, clear=False):
                with patch.object(init_gamebin.requests, "get", return_value=response(chunks=[b"x"])) as get:
                    init_gamebin.download_release_asset("https://example/archive", archive)
                init_gamebin.github_token.cache_clear()
            self.assertEqual(
                {"Authorization": "Bearer env-token", "X-GitHub-Api-Version": "2022-11-28"},
                get.call_args.kwargs["headers"],
            )
        init_gamebin.github_token.cache_clear()
        with patch.dict(os.environ, {"GH_TOKEN": "env-token"}, clear=False):
            with patch.object(init_gamebin.requests, "get", return_value=response(chunks=[])) as get:
                get.return_value.json.return_value = document
                self.assertEqual("b" * 40, init_gamebin.release_tag_target("14180"))
            self.assertEqual(
                {"Authorization": "Bearer env-token", "X-GitHub-Api-Version": "2022-11-28"},
                get.call_args.kwargs["headers"],
            )
        init_gamebin.github_token.cache_clear()

    def test_anonymous_quota_failure_reports_an_actionable_reason(self) -> None:
        init_gamebin.github_token.cache_clear()
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "gamebin.7z"
            with patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}, clear=False):
                with patch.object(init_gamebin.shutil, "which", return_value=None):
                    with patch.object(
                        init_gamebin.requests,
                        "get",
                        return_value=response(status=403, reason="Forbidden", headers={"x-ratelimit-remaining": "0"}),
                    ):
                        with self.assertRaisesRegex(init_gamebin.InitGamebinError, r"GH_TOKEN|authenticate gh"):
                            init_gamebin.download_release_asset("https://example/archive", archive)
                    with patch.object(
                        init_gamebin.requests,
                        "get",
                        return_value=response(status=403, reason="Forbidden"),
                    ):
                        with self.assertRaisesRegex(init_gamebin.InitGamebinError, "HTTP 403 Forbidden"):
                            init_gamebin.release_tag_target("14180")

    def test_downloaded_gamebin_binds_manifest_checksums_and_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            gamever = "14180"
            source_sha = "a" * 40
            archive_name = f"gamebin-{gamever}.7z"
            archive_key = f"archives/{archive_name}"
            archive = root / archive_name
            archive.write_bytes(b"verified archive")
            archive_record = {
                "path": archive_key,
                "name": archive_name,
                "size": archive.stat().st_size,
                "sha256": init_gamebin.sha256_file(archive),
            }
            expected_files = [{"path": f"bin/{gamever}/server/server.dll", "size": 3, "sha256": "b" * 64}]
            manifest = {
                "repository": "HLND2T/CS2_VibeSignatures",
                "release_version": gamever,
                "game_version": gamever,
                "source_sha": source_sha,
                "public_assets": [archive_record],
                "archives": {archive_key: {"files": expected_files}},
            }
            manifest_path = root / f"release-manifest-{gamever}.json"
            manifest_path.write_bytes(init_gamebin.canonical_json_bytes(manifest))
            checksums = root / f"SHA256SUMS-{gamever}.txt"
            checksums.write_text(
                f"{archive_record['sha256']}  {archive_key}\n"
                f"{init_gamebin.sha256_file(manifest_path)}  {manifest_path.name}\n",
                encoding="utf-8",
                newline="\n",
            )

            with (
                patch("release_bundle.validate_release_manifest"),
                patch.object(init_gamebin, "release_tag_target", return_value=source_sha),
            ):
                actual = init_gamebin.verify_downloaded_release_assets(
                    gamever=gamever,
                    manifest_path=manifest_path,
                    checksums_path=checksums,
                    archive_path=archive,
                )

            self.assertEqual(expected_files, actual)
            archive.write_bytes(b"tampered archive")
            with (
                patch("release_bundle.validate_release_manifest"),
                patch.object(init_gamebin, "release_tag_target", return_value=source_sha),
                self.assertRaisesRegex(init_gamebin.InitGamebinError, "differs from the Release manifest"),
            ):
                init_gamebin.verify_downloaded_release_assets(
                    gamever=gamever,
                    manifest_path=manifest_path,
                    checksums_path=checksums,
                    archive_path=archive,
                )

    def test_extract_archive_rejects_directory_link_before_extraction(self) -> None:
        listing = (
            "Path = linked\nSize = 0\nFolder = +\nSymbolic Link = ../outside\n\n"
            "Path = linked/payload\nSize = 1\nFolder = -\n"
        )
        with (
            patch.object(init_gamebin, "run_command", return_value=completed([], stdout=listing)) as run,
            self.assertRaisesRegex(init_gamebin.InitGamebinError, "link or unsupported"),
        ):
            init_gamebin.extract_archive(
                Path("repo"),
                Path("gamebin.7z"),
                Path("destination"),
                [{"path": "linked/payload", "size": 1, "sha256": "a" * 64}],
            )
        run.assert_called_once()

    def test_merge_archive_bin_copies_missing_and_preserves_existing_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "extract" / "bin" / "14168" / "server"
            source.mkdir(parents=True)
            (source / "server.dll").write_bytes(b"new")
            (source / "server.so").write_bytes(b"linux")
            target = root / "local-bin" / "14168" / "server"
            target.mkdir(parents=True)
            (target / "server.dll").write_bytes(b"existing")

            copied, skipped = init_gamebin.merge_archive_bin(root / "extract", root / "local-bin", "14168")

            self.assertEqual((1, 1), (copied, skipped))
            self.assertEqual(b"existing", (target / "server.dll").read_bytes())
            self.assertEqual(b"linux", (target / "server.so").read_bytes())

    def test_iter_configured_binaries_preserves_platform_order_and_deduplicates_real_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            module = root / "bin" / "14175" / "engine"
            module.mkdir(parents=True)
            windows = module / "engine2.dll"
            linux = module / "libengine2.so"
            windows.write_bytes(b"windows")
            linux.write_bytes(b"linux")
            config = root / "config.yaml"
            config.write_text(
                "modules:\n"
                "  - name: engine\n"
                "    path_windows: game/bin/win64/engine2.dll\n"
                "    path_linux: game/bin/linuxsteamrt64/libengine2.so\n"
                "  - name: engine\n"
                "    path_windows: game/bin/win64/engine2.dll\n",
                encoding="utf-8",
            )

            self.assertEqual(
                [windows.resolve(), linux.resolve()],
                [path for _, _, path in init_gamebin.iter_configured_binaries(root, "14175", config)],
            )

    def test_iter_configured_binaries_fails_when_a_declared_binary_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            config.write_text(
                "modules:\n  - name: engine\n    path_windows: game/bin/win64/engine2.dll\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "missing after preparation"):
                [path for _, _, path in init_gamebin.iter_configured_binaries(root, "14175", config)]

    def test_distinct_modules_may_use_the_same_binary_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                "modules:\n"
                "  - name: first\n    path_windows: game/first/shared.dll\n"
                "  - name: second\n    path_windows: game/second/shared.dll\n",
                encoding="utf-8",
            )
            expected = [(root / "bin" / "14175" / module / "shared.dll").resolve() for module in ("first", "second")]
            for binary in expected:
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"binary")
            self.assertEqual(
                expected,
                [path for _, _, path in init_gamebin.iter_configured_binaries(root, "14175", config)],
            )

    def test_iter_configured_binaries_can_enumerate_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            config.write_text(
                "modules:\n"
                "  - name: engine\n"
                "    path_windows: game/bin/win64/engine2.dll\n"
                "    path_linux: game/bin/linuxsteamrt64/libengine2.so\n"
                "  - name: engine\n"
                "    path_windows: game/bin/win64/engine2.dll\n",
                encoding="utf-8",
            )

            self.assertEqual(
                [
                    ("engine", "windows", (root / "bin" / "14175" / "engine" / "engine2.dll").resolve()),
                    ("engine", "linux", (root / "bin" / "14175" / "engine" / "libengine2.so").resolve()),
                ],
                list(init_gamebin.iter_configured_binaries(root, "14175", config, require_existing=False)),
            )
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "missing after preparation"):
                list(init_gamebin.iter_configured_binaries(root, "14175", config))

    def test_depot_fallback_uses_workflow_commands_in_order(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        with (
            patch.object(init_gamebin, "run_command", return_value=completed([])) as run,
        ):
            init_gamebin.run_depot_fallback(root, "14168", config)
        self.assertEqual("download_depot.py", run.call_args_list[0].kwargs["label"])
        self.assertEqual("copy_depot_bin.py", run.call_args_list[1].kwargs["label"])
        self.assertIn("-tag", run.call_args_list[0].args[0])
        self.assertIn("all-platform", run.call_args_list[1].args[0])

    def test_checkonly_configuration_error_stops_preparation(self) -> None:
        with patch.object(init_gamebin, "run_command", return_value=completed([], returncode=2)):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "configuration or argument"):
                init_gamebin.check_binaries(Path("repo"), "14168", Path("repo/configs/14168.yaml"))

    def test_prepare_skips_network_when_binaries_are_ready(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[True, True]),
            patch.object(init_gamebin, "download_release_asset") as download,
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(init_gamebin, "verify_source_binary_root") as verify,
        ):
            result = init_gamebin.prepare(root, "14168")
        self.assertEqual("existing local binaries", result["source"])
        download.assert_not_called()
        verify.assert_called_once_with(
            repo_root=root,
            gamever="14168",
            binary_root=root / "bin" / "14168",
            label="initialized binary tree",
        )

    def test_prepare_404_uses_depot_fallback(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[False, True]),
            patch.object(init_gamebin, "download_release_asset", return_value=False),
            patch.object(init_gamebin, "run_depot_fallback") as fallback,
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(init_gamebin, "verify_source_binary_root"),
        ):
            result = init_gamebin.prepare(root, "14168")
        self.assertEqual("Steam depot fallback", result["source"])
        fallback.assert_called_once_with(root, "14168", config)

    def test_prepare_rejects_complete_binary_tree_that_differs_from_source_lock(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[True, True]),
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(
                init_gamebin,
                "verify_source_binary_root",
                side_effect=init_gamebin.ReleaseWorkflowError("binary identity mismatch"),
            ),
            patch.object(init_gamebin, "download_verified_release_gamebin") as download,
        ):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "source binary lock"):
                init_gamebin.prepare(root, "14168")
        download.assert_not_called()

    def test_prepare_with_idb_merges_declared_warm_idb_archive(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        manifest = {
            "archives": {"archives/gamebin-with-idb-14168.7z": {"files": [{"path": "bin/14168/x.i64"}]}},
            "public_assets": [{"path": "archives/gamebin-with-idb-14168.7z"}],
        }
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[True, True]),
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(init_gamebin, "fetch_release_manifest", return_value=manifest),
            patch.object(init_gamebin, "download_verified_release_archive", return_value=(Path("idb.7z"), [])) as fetch,
            patch.object(init_gamebin, "extract_archive") as extract,
            patch.object(init_gamebin, "merge_archive_bin", return_value=(4, 0)) as merge,
            patch.object(init_gamebin, "verify_source_binary_root"),
        ):
            result = init_gamebin.prepare(root, "14168", with_idb=True)
        self.assertEqual((4, 0), result["idb"])
        self.assertEqual("existing local binaries", result["source"])
        fetch.assert_called_once_with(manifest, "14168", "gamebin-with-idb-14168.7z", unittest_mock.ANY)
        merge.assert_called_once_with(unittest_mock.ANY, root / "bin", "14168")
        extract.assert_called_once()

    def test_prepare_with_idb_fails_when_archive_is_not_declared(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        manifest = {"archives": {}, "public_assets": []}
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[True, True]),
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(init_gamebin, "fetch_release_manifest", return_value=manifest),
            patch.object(init_gamebin, "download_verified_release_archive") as fetch,
            patch.object(init_gamebin, "verify_source_binary_root"),
        ):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "publishes no"):
                init_gamebin.prepare(root, "14168", with_idb=True)
        fetch.assert_not_called()

    def test_check_idb_reports_availability(self) -> None:
        available = {
            "archives": {"archives/gamebin-with-idb-14168.7z": {"files": []}},
            "public_assets": [{"path": "archives/gamebin-with-idb-14168.7z"}],
        }
        unavailable = {"archives": {}, "public_assets": []}
        with patch.object(init_gamebin, "fetch_release_manifest", return_value=available):
            self.assertEqual((True, ""), init_gamebin.check_idb("14168", Path("tmp")))
        with patch.object(init_gamebin, "fetch_release_manifest", return_value=unavailable):
            ok, reason = init_gamebin.check_idb("14168", Path("tmp"))
        self.assertFalse(ok)
        self.assertIn("does not declare", reason)
        with patch.object(init_gamebin, "fetch_release_manifest", return_value=None):
            ok, reason = init_gamebin.check_idb("14168", Path("tmp"))
        self.assertFalse(ok)
        self.assertIn("no published Release", reason)

    def test_main_reports_skipped_idb_merge(self) -> None:
        result = {
            "gamever": "14169",
            "source": "existing local binaries",
            "copied": 0,
            "skipped": 0,
            "idb": None,
        }
        output = io.StringIO()
        with (
            patch.object(init_gamebin, "repository_root", return_value=Path("repo")),
            patch.object(init_gamebin, "prepare", return_value=result),
            patch("sys.stdout", output),
        ):
            self.assertEqual(0, init_gamebin.main(["prepare", "14169"]))
        self.assertIn("Warm IDB merge: skipped", output.getvalue())

    def test_main_reports_binary_preparation_only(self) -> None:
        result = {
            "gamever": "14169",
            "source": "release archive",
            "copied": 3,
            "skipped": 0,
            "idb": (4, 0),
        }
        output = io.StringIO()
        with (
            patch.object(init_gamebin, "repository_root", return_value=Path("repo")),
            patch.object(init_gamebin, "prepare", return_value=result),
            patch("sys.stdout", output),
        ):
            self.assertEqual(0, init_gamebin.main(["prepare", "14169"]))
        self.assertIn("Selected GAMEVER: 14169", output.getvalue())
        self.assertIn("Warm IDB merge: 4 copied, 0 skipped", output.getvalue())
        self.assertNotIn("Symbol snapshot:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
