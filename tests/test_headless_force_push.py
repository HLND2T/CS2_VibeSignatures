import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import headless_force_push


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
        self.assertEqual(["remote", "get-url", "origin"], commands[0])
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
        self.assertEqual(["remote", "get-url", "origin"], commands[0][:3])
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


if __name__ == "__main__":
    unittest.main()
