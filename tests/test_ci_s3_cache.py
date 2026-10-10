import tempfile
import hashlib
import io
import ntpath
from contextlib import redirect_stderr
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ci_s3_cache as cache


class TestS3Cache(unittest.TestCase):
    def test_shared_namespace_and_identity_scoped_legacy_keys(self):
        self.assertEqual(cache.namespace("owner/repo", "Windows"), cache.namespace("OWNER/REPO", "Linux"))
        key = cache.namespace("owner/repo", "Linux") + "-accepted-14190-" + "a" * 64
        candidates = cache.legacy_keys(key, "owner/repo", "Linux").splitlines()
        self.assertEqual(3, len(candidates))
        for platform, candidate in zip(("windows", "linux", "macos"), candidates):
            self.assertEqual(key.replace("-shared-", f"-{platform}-"), candidate)
        with self.assertRaises(ValueError):
            cache.legacy_keys(key, "another/repo", "Linux")
        with self.assertRaises(ValueError):
            cache.namespace("owner/repo", "FreeBSD")

    def test_endpoint_protocol_and_port(self):
        self.assertEqual(
            {"endpoint": "HZVM", "port": "8333", "insecure": "true"},
            cache.parse_endpoint("http://HZVM:8333"),
        )
        self.assertEqual(
            {"endpoint": "s3.example.com", "port": "443", "insecure": "false"},
            cache.parse_endpoint("https://s3.example.com/"),
        )
        self.assertEqual("80", cache.parse_endpoint("http://HZVM")["port"])

    def test_reject_invalid_endpoints(self):
        for value in (
            "",
            "HZVM:8333",
            "ftp://host",
            "http://user:pass@host",
            "http://host/bucket",
            "http://host?x=y",
            "http://host#fragment",
            "http://host:0",
            "http://host:65536",
            "http://host\n",
            "http://host:",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cache.parse_endpoint(value)

    def test_keys_bind_repository_platform_lock_and_selection(self):
        lock = SimpleNamespace(
            sha256="sha256:" + "a" * 64, document={"download": {"manifests": {"1": "2"}}, "binaries": {}}
        )
        with (
            patch.object(cache, "load_source_binary_lock", return_value=lock),
            patch.object(cache, "configured_binary_paths", return_value=frozenset({"server/server.dll"})),
        ):
            first = cache.cache_layout(Path("."), "14180", "owner/repo", "Windows")
            for key in (first["accepted-key"], first["depot-key"]):
                # tespkg saves with path.join but lists using the original key.
                self.assertTrue(ntpath.normpath(ntpath.join(key, "cache.tzst")).startswith(key + "\\"))
            second = cache.cache_layout(Path("."), "14180", "other/repo", "Windows")
            self.assertNotEqual(first["accepted-key"], second["accepted-key"])
            lock.sha256 = "sha256:" + "b" * 64
            changed = cache.cache_layout(Path("."), "14180", "owner/repo", "Windows")
            self.assertNotEqual(first["accepted-key"], changed["accepted-key"])
            self.assertEqual(first["depot-key"], changed["depot-key"])

    def test_reject_unsafe_names(self):
        for repository in ("../repo", "owner/repo/extra", "owner/repo\n"):
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                cache.namespace(repository, "Windows")

    def test_prepare_clears_only_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / cache.STAGING
            stage.mkdir()
            (stage / "old").write_text("old")
            (root / "keep").write_text("keep")
            cache.prepare_staging(root)
            self.assertFalse((stage / "old").exists())
            self.assertTrue((root / "keep").exists())

    def test_prepare_rejects_link_before_deleting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            outside = root / "outside"
            workspace.mkdir()
            outside.mkdir()
            (outside / "keep").write_text("keep")
            try:
                (workspace / cache.STAGING).symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("Creating directory symlinks is unavailable")
            with self.assertRaises(cache.ReleaseWorkflowError):
                cache.prepare_staging(workspace)
            self.assertTrue((outside / "keep").exists())

    def test_depot_allowlist_missing_and_corrupt_payloads(self):
        data = b"binary"
        lock = SimpleNamespace(
            document={
                "binaries": {
                    "server": {
                        "windows": {
                            "path": "game/bin/server.dll",
                            "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        }
                    }
                }
            }
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(cache, "load_source_binary_lock", return_value=lock),
        ):
            root = Path(temporary)
            self.assertFalse(cache.depot_ready(root, "14180"))
            with self.assertRaisesRegex(ValueError, "incomplete"):
                cache.verify_restored(root, "14180", accepted_hit=False, depot_hit=True)
            target = root / "cs2_depot/14180/game/bin/server.dll"
            target.parent.mkdir(parents=True)
            target.write_bytes(data)
            (target.parent / "credentials.json").write_text("must not enter cache")
            self.assertTrue(cache.depot_ready(root, "14180"))
            cache.verify_restored(root, "14180", accepted_hit=False, depot_hit=True)
            self.assertEqual(data, (root / cache.STORE / "bin/14180/server/server.dll").read_bytes())
            self.assertEqual(
                ["cs2_depot/14180/game/bin/server.dll"], [p for p, _ in cache.depot_files("14180", lock.document)]
            )
            target.write_bytes(b"broken")
            with self.assertRaisesRegex(ValueError, "differs"):
                cache.depot_ready(root, "14180")

    def test_missing_credentials_fail_without_exposing_values(self):
        error = io.StringIO()
        with (
            patch.dict("os.environ", {"S3_ACCESS_KEY_ID": "do-not-log-this-value", "S3_SECRET_ACCESS_KEY": ""}),
            redirect_stderr(error),
        ):
            self.assertEqual(1, cache.main(["endpoint"]))
        self.assertIn("S3_SECRET_ACCESS_KEY is not configured", error.getvalue())
        self.assertNotIn("do-not-log-this-value", error.getvalue())

    def test_verified_accepted_hit_does_not_read_depot(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(cache, "configured_binary_paths", return_value=frozenset({"server/server.dll"})),
            patch.object(cache, "validate_binary_cache_tree") as inventory,
            patch.object(cache, "verify_source_binary_root") as hashes,
            patch.object(cache, "depot_ready", side_effect=AssertionError("depot must stay lazy")),
        ):
            cache.verify_restored(Path(temporary), "14190", accepted_hit=True, depot_hit=False)
            inventory.assert_called_once()
            hashes.assert_called_once()

    def test_selection_paths_bind_generation_and_lease(self):
        identity = "a" * 64
        result = cache.selection_layout("14180", "owner/repo", "Windows", identity + "-100-1", "b" * 32, "100", "1")
        self.assertTrue(result["generation-key"].endswith(identity + "-100-1"))
        self.assertTrue(result["lease-key"].endswith("100-1-" + "b" * 32))
        self.assertNotIn("leases", result["generation-path"])
        for generation in ("../outside", identity + "-bad"):
            with self.assertRaises(ValueError):
                cache.selection_layout("14180", "owner/repo", "Windows", generation, "b" * 32, "100", "1")


if __name__ == "__main__":
    unittest.main()
