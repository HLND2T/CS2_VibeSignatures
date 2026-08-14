import base64
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


SCRIPT = Path("init_gamebin.py")
SPEC = importlib.util.spec_from_file_location("init_gamebin", SCRIPT)
init_gamebin = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(init_gamebin)


def completed(command, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def response(*, status=200, chunks=(), reason="OK"):
    result = MagicMock()
    result.status_code = status
    result.reason = reason
    result.iter_content.return_value = iter(chunks)
    result.__enter__.return_value = result
    result.__exit__.return_value = False
    return result


def binsync_summary(**overrides):
    result = {
        "targets": 2,
        "remote_verified": 2,
        "remote_created": 0,
        "remote_restored": 0,
        "remote_initialized": 0,
        "sidecar_created": 2,
        "sidecar_existing": 0,
    }
    result.update(overrides)
    return result


def git(cwd: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True)


class TestInitGamebin(unittest.TestCase):
    def test_script_resolves_its_own_repository_root(self) -> None:
        expected = SCRIPT.resolve().parent
        with patch.object(init_gamebin, "run_command", return_value=completed([], stdout=f"{expected}\n")):
            self.assertEqual(expected, init_gamebin.repository_root())

    def test_skill_delegates_snapshot_restoration_and_removes_idb_renaming(self) -> None:
        skill = Path(".claude/skills/init-gamebin/SKILL.md").read_text(encoding="utf-8")
        agent = Path(".claude/skills/init-gamebin/agents/openai.yaml").read_text(encoding="utf-8")
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("allow_implicit_invocation: false", agent)
        self.assertIn("$restore-from-snapshot", skill)
        self.assertIn("<MODULE_FILENAME>.binsync.json", skill)
        self.assertIn("BinSync recovery", agent)
        self.assertNotIn("gamesymbol_snapshot.py", source)
        self.assertNotIn("gamesymbol_snapshot_lib", source)
        self.assertNotIn("--force-base-snapshot", source)
        self.assertNotIn("Need to sync existing symbols to idb?", skill)
        self.assertNotIn("ida_analyze_bin.py", skill)

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

    def test_configured_binary_paths_preserves_platform_order_and_deduplicates_real_paths(self) -> None:
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
                init_gamebin.configured_binary_paths(root, "14175", config),
            )

    def test_configured_binary_paths_fails_when_a_declared_binary_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            config.write_text(
                "modules:\n  - name: engine\n    path_windows: game/bin/win64/engine2.dll\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "missing after preparation"):
                init_gamebin.configured_binary_paths(root, "14175", config)

    def test_expected_sidecar_uses_full_binary_filename_for_repo_path(self) -> None:
        binary = Path("bin/14175/engine/engine2.dll")
        repo_name, remote, repo_path, sidecar = init_gamebin.expected_sidecar(binary, "a" * 32, "14175", "HZDEV")
        self.assertEqual("CS2_VibeSignatures_binsync_14175_engine2.dll", repo_name)
        self.assertEqual("https://github.com/HLND2T/CS2_VibeSignatures_binsync_14175_engine2.dll", remote)
        self.assertEqual(binary.parent / "engine2.dll.bsproj", repo_path)
        self.assertEqual("engine2.dll.bsproj", sidecar["repo_path"])
        self.assertEqual(False, sidecar["force_user"])
        self.assertEqual(True, sidecar["auto_clone"])

    def test_sidecar_validation_is_semantic_but_schema_strict(self) -> None:
        expected = {
            "user": "HZDEV",
            "remote": "https://github.com/HLND2T/repo",
            "repo_path": "engine2.dll.bsproj",
            "expected_md5": "a" * 32,
            "force_user": False,
            "auto_clone": True,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            sidecar = Path(temp_dir) / "engine2.dll.binsync.json"
            sidecar.write_text(json.dumps(dict(reversed(list(expected.items())))), encoding="utf-8")
            self.assertTrue(init_gamebin.validate_sidecar(sidecar, expected))

            sidecar.write_text(json.dumps({**expected, "extra": True}), encoding="utf-8")
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "conflicting schema"):
                init_gamebin.validate_sidecar(sidecar, expected)

            sidecar.write_text(json.dumps({**expected, "auto_clone": False}), encoding="utf-8")
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "auto_clone"):
                init_gamebin.validate_sidecar(sidecar, expected)

    def test_write_sidecar_atomic_uses_canonical_json(self) -> None:
        data = {
            "user": "HZDEV",
            "remote": "https://github.com/HLND2T/repo",
            "repo_path": "engine2.dll.bsproj",
            "expected_md5": "a" * 32,
            "force_user": False,
            "auto_clone": True,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "engine2.dll.binsync.json"
            init_gamebin.write_sidecar_atomic(path, data)
            self.assertEqual(json.dumps(data, indent=4) + "\n", path.read_text(encoding="utf-8"))

            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "refusing to overwrite"):
                init_gamebin.write_sidecar_atomic(path, {**data, "user": "other"})
            self.assertEqual(data, json.loads(path.read_text(encoding="utf-8")))

    def test_normalize_github_remote_accepts_equivalent_urls(self) -> None:
        expected = ("hlnd2t", "repo")
        self.assertEqual(expected, init_gamebin.normalize_github_remote("https://github.com/HLND2T/repo"))
        self.assertEqual(expected, init_gamebin.normalize_github_remote("https://github.com/HLND2T/repo.git"))
        self.assertEqual(expected, init_gamebin.normalize_github_remote("git@github.com:HLND2T/repo.git"))
        self.assertIsNone(init_gamebin.normalize_github_remote("https://example.com/HLND2T/repo"))

    def test_minimal_binsync_repo_matches_root_commit_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            init_gamebin.initialize_minimal_binsync_repo(repo, "a" * 32, "repo", "HZDEV")
            branches = git(repo, "for-each-ref", "--format=%(refname)", "refs/heads/binsync/").stdout.splitlines()
            self.assertEqual(["refs/heads/binsync/HZDEV", "refs/heads/binsync/__root__"], sorted(branches))
            self.assertEqual(
                git(repo, "rev-parse", "refs/heads/binsync/__root__").stdout,
                git(repo, "rev-parse", "refs/heads/binsync/HZDEV").stdout,
            )
            self.assertEqual("Root commit", git(repo, "log", "-1", "--format=%s").stdout.strip())
            self.assertEqual(
                ".gitignore\nbinary_hash", git(repo, "ls-tree", "--name-only", "binsync/__root__").stdout.strip()
            )
            self.assertEqual("a" * 32, git(repo, "show", "binsync/__root__:binary_hash").stdout)

    def test_validate_local_repo_accepts_equivalent_origin_and_reports_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            init_gamebin.initialize_minimal_binsync_repo(repo, "a" * 32, "repo", "HZDEV")
            git(repo, "remote", "add", "origin", "git@github.com:HLND2T/repo.git")
            (repo / ".git" / "binsync.lock").write_text("", encoding="utf-8")
            self.assertEqual((True, True), init_gamebin.validate_local_binsync_repo(repo, "a" * 32, "repo"))

    def test_validate_local_repo_rejects_hash_and_origin_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            init_gamebin.initialize_minimal_binsync_repo(repo, "a" * 32, "repo", "HZDEV")
            git(repo, "remote", "add", "origin", "https://github.com/HLND2T/other")
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "binary_hash mismatch"):
                init_gamebin.validate_local_binsync_repo(repo, "b" * 32, "repo")
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "origin conflicts"):
                init_gamebin.validate_local_binsync_repo(repo, "a" * 32, "repo")

    def test_push_local_binsync_history_pushes_every_local_binsync_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "local"
            remote = root / "remote.git"
            repo.mkdir()
            remote.mkdir()
            init_gamebin.initialize_minimal_binsync_repo(repo, "a" * 32, "repo", "HZDEV")
            git(repo, "branch", "binsync/Other")
            git(remote, "init", "--bare")
            git(repo, "remote", "add", "origin", str(remote))

            init_gamebin.push_local_binsync_history(repo)

            branches = git(remote, "for-each-ref", "--format=%(refname)", "refs/heads/binsync/").stdout.splitlines()
            self.assertEqual(
                [
                    "refs/heads/binsync/HZDEV",
                    "refs/heads/binsync/Other",
                    "refs/heads/binsync/__root__",
                ],
                sorted(branches),
            )

    def test_gh_api_treats_only_explicit_http_404_as_missing(self) -> None:
        missing = completed([], returncode=1, stderr="gh: Not Found (HTTP 404)")
        with patch.object(init_gamebin, "run_command", return_value=missing):
            self.assertIsNone(init_gamebin.gh_api(Path("repo"), "repos/HLND2T/missing", allow_404=True))

        failed = completed([], returncode=1, stderr="gh: API rate limit exceeded (HTTP 403)")
        with patch.object(init_gamebin, "run_command", return_value=failed):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "HTTP 403"):
                init_gamebin.gh_api(Path("repo"), "repos/HLND2T/repo", allow_404=True)

    def test_inspect_remote_classifies_missing_empty_and_valid_without_real_gh(self) -> None:
        root = Path("repo")
        with patch.object(init_gamebin, "gh_api", return_value=None):
            self.assertEqual("missing", init_gamebin.inspect_remote(root, "repo", "a" * 32).status)
        with patch.object(init_gamebin, "gh_api", side_effect=[{"default_branch": None, "private": False}, []]):
            self.assertEqual("empty", init_gamebin.inspect_remote(root, "repo", "a" * 32).status)
        encoded = base64.b64encode(("a" * 32).encode()).decode()
        with patch.object(
            init_gamebin,
            "gh_api",
            side_effect=[
                {"default_branch": "binsync/__root__", "private": False},
                [{"name": "binsync/__root__"}],
                {"encoding": "base64", "content": encoded},
            ],
        ):
            self.assertEqual("valid", init_gamebin.inspect_remote(root, "repo", "a" * 32).status)

    def test_inspect_remote_rejects_default_branch_and_hash_conflicts(self) -> None:
        with patch.object(init_gamebin, "gh_api", return_value={"default_branch": None, "private": True}):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "not public"):
                init_gamebin.inspect_remote(Path("repo"), "repo", "a" * 32)

        with patch.object(
            init_gamebin,
            "gh_api",
            side_effect=[{"default_branch": "main", "private": False}, [{"name": "main"}]],
        ):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "default branch"):
                init_gamebin.inspect_remote(Path("repo"), "repo", "a" * 32)

        encoded = base64.b64encode(("b" * 32).encode()).decode()
        with patch.object(
            init_gamebin,
            "gh_api",
            side_effect=[
                {"default_branch": "binsync/__root__", "private": False},
                [{"name": "binsync/__root__"}],
                {"encoding": "base64", "content": encoded},
            ],
        ):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "binary_hash mismatch"):
                init_gamebin.inspect_remote(Path("repo"), "repo", "a" * 32)

    def test_execute_plans_initializes_empty_remote_before_writing_sidecar(self) -> None:
        binary = Path("bin/14175/engine/engine2.dll")
        _, _, repo_path, sidecar_data = init_gamebin.expected_sidecar(binary, "a" * 32, "14175", "HZDEV")
        plan = init_gamebin.BinSyncPlan(
            binary_path=binary,
            binary_md5="a" * 32,
            repo_name="CS2_VibeSignatures_binsync_14175_engine2.dll",
            remote_url=sidecar_data["remote"],
            repo_path=repo_path,
            sidecar_path=Path(f"{binary}.binsync.json"),
            sidecar_data=sidecar_data,
            sidecar_exists=False,
            local_repo_exists=False,
            local_repo_locked=False,
            remote_state=init_gamebin.RemoteState("empty"),
        )
        events = []
        remote_states = iter([init_gamebin.RemoteState("empty"), init_gamebin.RemoteState("valid")])
        with (
            patch.object(init_gamebin, "file_md5", return_value="a" * 32),
            patch.object(
                init_gamebin,
                "inspect_remote",
                side_effect=lambda *_: events.append("inspect") or next(remote_states),
            ),
            patch.object(
                init_gamebin,
                "initialize_minimal_binsync_remote",
                side_effect=lambda *_: events.append("initialize"),
            ),
            patch.object(
                init_gamebin,
                "set_remote_default_branch",
                side_effect=lambda *_: events.append("default"),
            ),
            patch.object(init_gamebin, "validate_sidecar", return_value=False),
            patch.object(
                init_gamebin,
                "write_sidecar_atomic",
                side_effect=lambda *_: events.append("sidecar"),
            ),
        ):
            summary = init_gamebin.execute_binsync_plans(Path("repo"), [plan], "HZDEV")
        self.assertEqual(["inspect", "initialize", "default", "inspect", "sidecar"], events)
        self.assertEqual(1, summary["remote_initialized"])
        self.assertEqual(1, summary["sidecar_created"])

    def test_execute_plans_restores_local_history_only_for_empty_remote(self) -> None:
        binary = Path("bin/14175/engine/engine2.dll")
        _, _, repo_path, sidecar_data = init_gamebin.expected_sidecar(binary, "a" * 32, "14175", "HZDEV")
        plan = init_gamebin.BinSyncPlan(
            binary_path=binary,
            binary_md5="a" * 32,
            repo_name="CS2_VibeSignatures_binsync_14175_engine2.dll",
            remote_url=sidecar_data["remote"],
            repo_path=repo_path,
            sidecar_path=Path(f"{binary}.binsync.json"),
            sidecar_data=sidecar_data,
            sidecar_exists=True,
            local_repo_exists=True,
            local_repo_locked=False,
            remote_state=init_gamebin.RemoteState("empty"),
        )
        with (
            patch.object(init_gamebin, "file_md5", return_value="a" * 32),
            patch.object(
                init_gamebin,
                "inspect_remote",
                side_effect=[init_gamebin.RemoteState("empty"), init_gamebin.RemoteState("valid")],
            ),
            patch.object(init_gamebin, "validate_local_binsync_repo", return_value=(True, False)),
            patch.object(init_gamebin, "validate_sidecar", return_value=True),
            patch.object(init_gamebin, "push_local_binsync_history") as push,
            patch.object(init_gamebin, "set_remote_default_branch"),
            patch.object(init_gamebin, "write_sidecar_atomic") as write,
        ):
            summary = init_gamebin.execute_binsync_plans(Path("repo"), [plan], "HZDEV")
        push.assert_called_once_with(repo_path)
        write.assert_not_called()
        self.assertEqual(1, summary["remote_restored"])
        self.assertEqual(1, summary["sidecar_existing"])

    def test_execute_plans_never_syncs_an_existing_valid_remote(self) -> None:
        binary = Path("bin/14175/engine/engine2.dll")
        _, _, repo_path, sidecar_data = init_gamebin.expected_sidecar(binary, "a" * 32, "14175", "HZDEV")
        plan = init_gamebin.BinSyncPlan(
            binary_path=binary,
            binary_md5="a" * 32,
            repo_name="CS2_VibeSignatures_binsync_14175_engine2.dll",
            remote_url=sidecar_data["remote"],
            repo_path=repo_path,
            sidecar_path=Path(f"{binary}.binsync.json"),
            sidecar_data=sidecar_data,
            sidecar_exists=True,
            local_repo_exists=True,
            local_repo_locked=True,
            remote_state=init_gamebin.RemoteState("valid"),
        )
        with (
            patch.object(init_gamebin, "file_md5", return_value="a" * 32),
            patch.object(init_gamebin, "inspect_remote", return_value=init_gamebin.RemoteState("valid")),
            patch.object(init_gamebin, "validate_sidecar", return_value=True),
            patch.object(init_gamebin, "push_local_binsync_history") as push,
            patch.object(init_gamebin, "initialize_minimal_binsync_remote") as initialize,
            patch.object(init_gamebin, "set_remote_default_branch") as set_default,
        ):
            summary = init_gamebin.execute_binsync_plans(Path("repo"), [plan], "HZDEV")
        push.assert_not_called()
        initialize.assert_not_called()
        set_default.assert_not_called()
        self.assertEqual(1, summary["remote_verified"])

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
            patch.object(init_gamebin, "probe_binsync", return_value=(True, "")),
            patch.object(init_gamebin, "prepare_binsync_projects", return_value=binsync_summary()) as binsync,
        ):
            result = init_gamebin.prepare(root, "14168", binsync_mode="enable")
        self.assertEqual("existing local binaries", result["source"])
        download.assert_not_called()
        binsync.assert_called_once_with(root, "14168", config)

    def test_prepare_404_uses_depot_fallback(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[False, True]),
            patch.object(init_gamebin, "download_release_asset", return_value=False),
            patch.object(init_gamebin, "run_depot_fallback") as fallback,
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(init_gamebin, "probe_binsync", return_value=(True, "")),
            patch.object(init_gamebin, "prepare_binsync_projects", return_value=binsync_summary()),
        ):
            result = init_gamebin.prepare(root, "14168", binsync_mode="enable")
        self.assertEqual("Steam depot fallback", result["source"])
        fallback.assert_called_once_with(root, "14168", config)

    def test_prepare_default_skips_binsync_without_probing(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[True, True]),
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(init_gamebin, "probe_binsync") as probe,
            patch.object(init_gamebin, "prepare_binsync_projects") as binsync,
        ):
            result = init_gamebin.prepare(root, "14168")
        self.assertEqual("existing local binaries", result["source"])
        self.assertIsNone(result["binsync"])
        probe.assert_not_called()
        binsync.assert_not_called()

    def test_prepare_enable_fails_when_binsync_unavailable(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        with (
            patch.object(init_gamebin, "load_versions", return_value=["14168"]),
            patch.object(init_gamebin, "check_binaries", side_effect=[True, True]),
            patch.object(init_gamebin, "resolve_analysis_config", return_value=config),
            patch.object(init_gamebin, "probe_binsync", return_value=(False, "gh is not installed")),
            patch.object(init_gamebin, "prepare_binsync_projects") as binsync,
        ):
            with self.assertRaisesRegex(init_gamebin.InitGamebinError, "unavailable"):
                init_gamebin.prepare(root, "14168", binsync_mode="enable")
        binsync.assert_not_called()

    def test_probe_binsync_reports_missing_gh(self) -> None:
        with patch.object(init_gamebin.shutil, "which", return_value=None):
            self.assertEqual(
                (False, "GitHub CLI (gh) is not installed or not on PATH"),
                init_gamebin.probe_binsync(Path("repo")),
            )

    def test_probe_binsync_reports_unauthenticated_gh(self) -> None:
        with patch.object(
            init_gamebin,
            "run_command",
            return_value=completed([], returncode=1, stderr="not logged in"),
        ):
            available, reason = init_gamebin.probe_binsync(Path("repo"))
        self.assertFalse(available)
        self.assertIn("gh is not authenticated to github.com", reason)

    def test_probe_binsync_reports_api_unreachable(self) -> None:
        with patch.object(
            init_gamebin,
            "run_command",
            side_effect=[
                completed([], returncode=0),
                completed([], returncode=1, stderr="Network error"),
            ],
        ):
            available, reason = init_gamebin.probe_binsync(Path("repo"))
        self.assertFalse(available)
        self.assertIn("cannot reach the GitHub API", reason)

    def test_probe_binsync_reports_org_access_denied(self) -> None:
        with patch.object(
            init_gamebin,
            "run_command",
            side_effect=[
                completed([], returncode=0),
                completed([], returncode=0, stdout="HZDEV"),
                completed([], returncode=1, stderr="HTTP 404"),
            ],
        ):
            available, reason = init_gamebin.probe_binsync(Path("repo"))
        self.assertFalse(available)
        self.assertIn("HLND2T organization", reason)

    def test_probe_binsync_reports_org_login_mismatch(self) -> None:
        with patch.object(
            init_gamebin,
            "run_command",
            side_effect=[
                completed([], returncode=0),
                completed([], returncode=0, stdout="HZDEV"),
                completed([], returncode=0, stdout="SomeOtherOrg"),
            ],
        ):
            available, reason = init_gamebin.probe_binsync(Path("repo"))
        self.assertFalse(available)
        self.assertIn("HLND2T organization", reason)

    def test_probe_binsync_reports_available(self) -> None:
        with (
            patch.object(
                init_gamebin.shutil,
                "which",
                return_value="gh",
            ),
            patch.object(
                init_gamebin,
                "run_command",
                return_value=completed([], returncode=0, stdout="HLND2T"),
            ),
        ):
            self.assertEqual((True, ""), init_gamebin.probe_binsync(Path("repo")))

    def test_main_check_binsync_reports_availability(self) -> None:
        output = io.StringIO()
        with (
            patch.object(init_gamebin, "repository_root", return_value=Path("repo")),
            patch.object(init_gamebin, "probe_binsync", return_value=(True, "")),
            patch("sys.stdout", output),
        ):
            self.assertEqual(0, init_gamebin.main(["check-binsync"]))
        self.assertIn("BinSync available", output.getvalue())

        output = io.StringIO()
        with (
            patch.object(init_gamebin, "repository_root", return_value=Path("repo")),
            patch.object(init_gamebin, "probe_binsync", return_value=(False, "gh is not installed")),
            patch("sys.stdout", output),
        ):
            self.assertEqual(1, init_gamebin.main(["check-binsync"]))
        self.assertIn("BinSync unavailable: gh is not installed", output.getvalue())

    def test_main_reports_binsync_skipped(self) -> None:
        result = {
            "gamever": "14169",
            "source": "existing local binaries",
            "copied": 0,
            "skipped": 0,
            "binsync": None,
        }
        output = io.StringIO()
        with (
            patch.object(init_gamebin, "repository_root", return_value=Path("repo")),
            patch.object(init_gamebin, "prepare", return_value=result),
            patch("sys.stdout", output),
        ):
            self.assertEqual(0, init_gamebin.main(["prepare", "14169"]))
        self.assertIn("BinSync recovery: skipped", output.getvalue())

    def test_main_reports_binary_preparation_only(self) -> None:
        result = {
            "gamever": "14169",
            "source": "release archive",
            "copied": 3,
            "skipped": 0,
            "binsync": binsync_summary(),
        }
        output = io.StringIO()
        with (
            patch.object(init_gamebin, "repository_root", return_value=Path("repo")),
            patch.object(init_gamebin, "prepare", return_value=result),
            patch("sys.stdout", output),
        ):
            self.assertEqual(0, init_gamebin.main(["prepare", "14169"]))
        self.assertIn("Selected GAMEVER: 14169", output.getvalue())
        self.assertIn("BinSync recovery: 2 targets", output.getvalue())
        self.assertNotIn("Symbol snapshot:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
