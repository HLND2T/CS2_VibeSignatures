import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import call, patch

import headless_force_push


PROXY_INSTEADOF_ENV = {
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "url.http://127.0.0.1:8080/.insteadOf",
    "GIT_CONFIG_VALUE_0": "https://github.com/",
}


def _run_git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(["git", *arguments], cwd=repo, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _make_local_repo(repo: Path) -> None:
    repo.mkdir(parents=True)
    _run_git(repo, "init")
    (repo / "binary_hash").write_text("a" * 32, encoding="utf-8")
    _run_git(repo, "add", "binary_hash")
    _run_git(
        repo,
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@local",
        "commit",
        "-m",
        "Root commit",
    )


class HeadlessForcePushTests(unittest.TestCase):
    def test_local_only_transport_restores_origin_and_observes_remote_without_writes(self) -> None:
        remote = "https://github.com/HLND2T/CS2_VibeSignatures_binsync_1_server.dll"
        repo = Path("server.dll.bsproj")
        heads = {"refs/heads/binsync/__root__": "a" * 40}

        with (
            patch.object(headless_force_push, "_git", side_effect=[remote, "", "", ""]) as git,
            patch.object(headless_force_push, "_remote_heads", side_effect=[heads, heads]) as remote_heads,
            headless_force_push.local_only_remote(repo, remote),
        ):
            pass

        remote_heads.assert_has_calls([call(remote), call(remote)])
        commands = [call.args[0] for call in git.call_args_list]
        self.assertEqual(["config", "--get", "remote.origin.url"], commands[0])
        self.assertEqual(["clone", "--bare", "--no-tags"], commands[1][:3])
        self.assertEqual(["remote", "set-url", "origin"], commands[2][:3])
        self.assertEqual(remote, commands[3][-1])

    def test_local_only_transport_fails_if_canonical_remote_changes(self) -> None:
        remote = "https://github.com/HLND2T/CS2_VibeSignatures_binsync_1_server.dll"
        before = {"refs/heads/binsync/__root__": "a" * 40}
        after = {"refs/heads/binsync/__root__": "b" * 40}
        with (
            patch.object(headless_force_push, "_git", side_effect=[remote, "", "", ""]),
            patch.object(headless_force_push, "_remote_heads", side_effect=[before, after]),
            self.assertRaisesRegex(SystemExit, "changed remote refs"),
        ):
            with headless_force_push.local_only_remote(Path("server.dll.bsproj"), remote):
                pass

    def test_local_only_transport_reads_raw_origin_despite_insteadof_rewrite(self) -> None:
        remote = "https://github.com/HLND2T/CS2_VibeSignatures_binsync_1_server.dll"
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "server.dll.bsproj"
            _make_local_repo(repo)
            _run_git(repo, "remote", "add", "origin", remote)

            # A system-level insteadOf rewrite (the git cache proxy from issue
            # #927) makes `git remote get-url` return the proxy URL; the sink
            # transport must compare against the raw stored canonical URL. A
            # runner may already define its own proxy host, so assert a rewrite
            # is active without pinning the host that wins the insteadOf match.
            with patch.dict(os.environ, PROXY_INSTEADOF_ENV):
                self.assertNotEqual(remote, _run_git(repo, "remote", "get-url", "origin"))
                with headless_force_push.local_only_remote(repo, remote, bootstrap_local_init=True):
                    pass

            self.assertEqual(remote, _run_git(repo, "config", "--get", "remote.origin.url"))

    def test_direct_push_is_disabled_before_loading_ida_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "server.dll"
            binary.write_bytes(b"binary")
            with (
                patch.object(headless_force_push, "_load_runtime_dependencies") as load,
                self.assertRaisesRegex(SystemExit, "protected bundle publisher"),
            ):
                headless_force_push.main([str(binary), "--push"])
            load.assert_not_called()

    def test_bootstrap_local_only_sink_comes_from_local_repo_without_remote_queries(self) -> None:
        remote = "https://github.com/HLND2T/CS2_VibeSignatures_binsync_1_server.dll"
        repo = Path("server.dll.bsproj").resolve()

        with (
            patch.object(headless_force_push, "_git", side_effect=[remote, "", "", ""]) as git,
            patch.object(headless_force_push, "_remote_heads") as remote_heads,
            headless_force_push.local_only_remote(repo, remote, bootstrap_local_init=True),
        ):
            pass

        remote_heads.assert_not_called()
        commands = [call.args[0] for call in git.call_args_list]
        self.assertEqual(["config", "--get", "remote.origin.url"], commands[0])
        self.assertEqual(["clone", "--bare", "--no-tags", str(repo)], commands[1][:4])
        self.assertEqual(["remote", "set-url", "origin"], commands[2][:3])
        self.assertEqual(remote, commands[3][-1])

    def test_bootstrap_local_init_requires_push_and_local_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "server.dll"
            binary.write_bytes(b"binary")
            with (
                patch.object(headless_force_push, "_load_runtime_dependencies") as load,
                self.assertRaisesRegex(SystemExit, "--bootstrap-local-init requires --push --local-only"),
            ):
                headless_force_push.main([str(binary), "--bootstrap-local-init"])
            load.assert_not_called()

    def _ida_stub(self, *, defined, promoted, names):
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda address: object() if address in defined else None
        idaapi = types.ModuleType("idaapi")

        def add_func(address):
            promoted.append(address)
            defined.add(address)
            return True

        idaapi.add_func = add_func
        idc = types.ModuleType("idc")
        idc.SN_NOWARN = 0x100
        idc.get_name = lambda address: names.get(address, "")
        idc.set_name = lambda address, name, flags=0: names.__setitem__(address, name) or True
        return patch.dict(sys.modules, {"ida_funcs": ida_funcs, "idaapi": idaapi, "idc": idc})

    def test_promotes_bare_code_and_renames_auto_named_symbols(self) -> None:
        defined = {0x1000}
        promoted = []
        names = {0x1000: "sub_1000", 0x2000: "sub_2000"}
        manifest = {
            "functions": [0x1000, 0x2000],
            "globals": [],
            "names": {str(0x1000): "Canonical", str(0x2000): "Other"},
        }
        with self._ida_stub(defined=defined, promoted=promoted, names=names):
            self.assertEqual(2, headless_force_push.apply_manifest_names(manifest))

        self.assertEqual([0x2000], promoted)
        self.assertEqual({0x1000: "Canonical", 0x2000: "Other"}, names)

    def test_leaves_already_canonical_names_untouched(self) -> None:
        names = {0x1000: "CAM_Command_CommandHandler"}
        manifest = {"functions": [0x1000], "globals": [], "names": {str(0x1000): "ShouldNotApply"}}
        with self._ida_stub(defined={0x1000}, promoted=[], names=names):
            self.assertEqual(0, headless_force_push.apply_manifest_names(manifest))

        self.assertEqual({0x1000: "CAM_Command_CommandHandler"}, names)

    def test_skips_addresses_without_a_manifest_name(self) -> None:
        names = {0x1000: "sub_1000"}
        manifest = {"functions": [0x1000], "globals": [], "names": {}}
        with self._ida_stub(defined={0x1000}, promoted=[], names=names):
            self.assertEqual(0, headless_force_push.apply_manifest_names(manifest))

        self.assertEqual({0x1000: "sub_1000"}, names)


if __name__ == "__main__":
    unittest.main()
