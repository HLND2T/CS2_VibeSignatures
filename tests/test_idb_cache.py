import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import idb_cache
import idb_cache_leases as leases
from idb_cache_leases import LeaseOwner


class TestIdbCache(unittest.TestCase):
    owner = LeaseOwner("HLND2T/CS2_VibeSignatures", "100", "1")

    def _configured_binaries(self, root: Path, gamever: str, _config_path: Path):
        return [
            ("server", "windows", Path(root) / "bin" / gamever / "server" / "server.dll"),
            ("engine", "linux", Path(root) / "bin" / gamever / "engine" / "libengine2.so"),
        ]

    def _write_source(self, root: Path, gamever: str, *, marker: bytes = b"v1") -> None:
        for relative, prefix in (
            ("server/server.dll", b"server-"),
            ("engine/libengine2.so", b"engine-"),
        ):
            binary = root / "bin" / gamever / relative
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(prefix + marker)
            Path(f"{binary}.i64").write_bytes(b"idb-" + prefix + marker)

    def _patch_config(self):
        return patch.multiple(
            idb_cache,
            resolve_analysis_config=lambda gamever, repo_root: Path(repo_root) / "configs" / f"{gamever}.yaml",
            iter_configured_binaries=self._configured_binaries,
        )

    def test_write_ready_skips_unchanged_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            persisted_root = Path(temp_dir)
            gamever = "14180"
            payload = {"schema_version": 1, "gamever": gamever, "generation": "generation"}
            ready_path = persisted_root / "idb-cache-v2" / gamever / "READY.json"
            ready_path.parent.mkdir(parents=True)
            ready_path.write_bytes(idb_cache.canonical_json_bytes(payload))

            with patch.object(idb_cache, "write_canonical_json") as write:
                idb_cache._write_ready(persisted_root, gamever, payload)

            write.assert_not_called()

    def test_write_ready_replaces_changed_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            persisted_root = Path(temp_dir)
            gamever = "14180"
            payload = {"schema_version": 1, "gamever": gamever, "generation": "new-generation"}
            ready_path = persisted_root / "idb-cache-v2" / gamever / "READY.json"
            ready_path.parent.mkdir(parents=True)
            ready_path.write_bytes(idb_cache.canonical_json_bytes({"generation": "old-generation"}))

            with patch.object(idb_cache, "write_canonical_json") as write:
                idb_cache._write_ready(persisted_root, gamever, payload)

            write.assert_called_once_with(ready_path, payload)

    def test_publish_probe_and_restore_verified_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            destination = root / "destination"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="100-1",
                )
                probed = idb_cache.probe_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                )
                restored = idb_cache.restore_cache(
                    owner=self.owner,
                    repo_root=destination,
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    lease_id=published["lease_id"],
                    lease_sha256=published["lease_sha256"],
                    ida_version="9.2",
                )

            self.assertTrue(probed["cache_hit"])
            self.assertEqual(published["generation"], probed["generation"])
            self.assertEqual(published["generation"], restored["generation"])
            self.assertEqual(
                b"server-v1",
                (destination / "bin" / gamever / "server" / "server.dll").read_bytes(),
            )
            self.assertEqual(
                b"idb-server-v1",
                (destination / "bin" / gamever / "server" / "server.dll.i64").read_bytes(),
            )

    def test_publish_requires_every_configured_i64(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            gamever = "14180"
            self._write_source(source, gamever)
            (source / "bin" / gamever / "engine" / "libengine2.so.i64").unlink()

            with self._patch_config(), self.assertRaisesRegex(idb_cache.IdbCacheError, "warm IDB is missing"):
                idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=root / "persisted",
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="101-1",
                )

    def test_publish_preserves_primary_failure_when_incoming_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            gamever = "14180"
            self._write_source(source, gamever)
            (source / "bin" / gamever / "engine" / "libengine2.so.i64").unlink()
            stderr = io.StringIO()

            with (
                self._patch_config(),
                patch.object(idb_cache, "remove_tree", side_effect=OSError("cleanup denied")),
                redirect_stderr(stderr),
                self.assertRaisesRegex(idb_cache.IdbCacheError, "warm IDB is missing"),
            ):
                idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=root / "persisted",
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="101-2",
                )

            self.assertIn("failed to remove incomplete cache publication", stderr.getvalue())
            self.assertIn("cleanup denied", stderr.getvalue())

    def test_restore_rejects_tampered_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="102-1",
                )

            payload = (
                persisted
                / "idb-cache-v2"
                / gamever
                / "generations"
                / published["generation"]
                / "payload"
                / "server"
                / "server.dll.i64"
            )
            payload.write_bytes(b"tampered")

            with self.assertRaisesRegex(idb_cache.IdbCacheError, "inventory"):
                idb_cache.restore_cache(
                    owner=self.owner,
                    repo_root=root / "destination",
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    lease_id=published["lease_id"],
                    lease_sha256=published["lease_sha256"],
                    ida_version="9.2",
                )

    def test_restore_rejects_manifest_identity_that_disagrees_with_cache_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="102-2",
                )
            manifest_path = (
                persisted / "idb-cache-v2" / gamever / "generations" / published["generation"] / "manifest.json"
            )
            manifest = idb_cache.load_json_object(manifest_path)
            manifest["binaries"][0]["module"] = "tampered"
            idb_cache.write_canonical_json(manifest_path, manifest)

            with self.assertRaisesRegex(idb_cache.IdbCacheError, "manifest digest"):
                idb_cache.restore_cache(
                    owner=self.owner,
                    repo_root=root / "destination",
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    lease_id=published["lease_id"],
                    lease_sha256=published["lease_sha256"],
                    ida_version="9.2",
                )

    def test_explicit_generation_is_stable_after_ready_moves(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            destination = root / "destination"
            gamever = "14180"
            self._write_source(source, gamever, marker=b"v1")

            with self._patch_config():
                first = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="103-1",
                )
                self._write_source(source, gamever, marker=b"v2")
                second = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="104-1",
                )
                idb_cache.restore_cache(
                    owner=self.owner,
                    repo_root=destination,
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=first["generation"],
                    expected_cache_key=first["cache_key"],
                    lease_id=first["lease_id"],
                    lease_sha256=first["lease_sha256"],
                    ida_version="9.2",
                )

            self.assertNotEqual(first["cache_key"], second["cache_key"])
            self.assertEqual(
                b"server-v1",
                (destination / "bin" / gamever / "server" / "server.dll").read_bytes(),
            )

    def test_restore_rejects_consumer_ida_version_mismatch_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            destination = root / "destination"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="105-1",
                )
                with self.assertRaisesRegex(idb_cache.IdbCacheError, "IDA version mismatch"):
                    idb_cache.restore_cache(
                        owner=self.owner,
                        repo_root=destination,
                        persisted_root=persisted,
                        gamever=gamever,
                        generation=published["generation"],
                        expected_cache_key=published["cache_key"],
                        lease_id=published["lease_id"],
                        lease_sha256=published["lease_sha256"],
                        ida_version="9.1",
                    )

            self.assertFalse((destination / "bin").exists())

    def test_restore_rejects_reparse_component_on_target_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            destination = root / "destination"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="106-1",
                )

            # Create a junction at destination/bin/<gamever> pointing inside the
            # destination root so contained_path still accepts it but the restore
            # reparse-component check must reject it.
            bin_root = destination / "bin"
            bin_root.mkdir(parents=True, exist_ok=True)
            link = bin_root / gamever
            link_target = destination / "bin" / f"{gamever}-link-target"
            link_target.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                result = os.system(f'cmd /c mklink /j "{link}" "{link_target}"')
                if result != 0:
                    self.skipTest("unable to create a junction on this host")
            else:
                try:
                    link.symlink_to(link_target, target_is_directory=True)
                except OSError as exc:
                    self.skipTest(f"unable to create a symlink on this host: {exc}")

            with self.assertRaisesRegex(idb_cache.IdbCacheError, "reparse"):
                idb_cache.restore_cache(
                    owner=self.owner,
                    repo_root=destination,
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    lease_id=published["lease_id"],
                    lease_sha256=published["lease_sha256"],
                    ida_version="9.2",
                )

    def test_prune_removes_only_old_unprotected_generations_and_incoming(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            gamever = "14180"
            published = []
            with self._patch_config():
                for index in range(4):
                    self._write_source(source, gamever, marker=f"v{index}".encode())
                    published.append(
                        idb_cache.publish_cache(
                            owner=self.owner,
                            repo_root=source,
                            persisted_root=persisted,
                            gamever=gamever,
                            ida_version="9.2",
                            generation_suffix=f"20{index}-1",
                        )
                    )
                for item in published:
                    idb_cache.restore_cache(
                        owner=self.owner,
                        repo_root=root / "consumer",
                        persisted_root=persisted,
                        gamever=gamever,
                        generation=item["generation"],
                        expected_cache_key=item["cache_key"],
                        ida_version="9.2",
                        lease_id=item["lease_id"],
                        lease_sha256=item["lease_sha256"],
                    )
            generations_root = persisted / "idb-cache-v2" / gamever / "generations"
            now = time.time()
            for index, generation in enumerate(published):
                path = generations_root / generation["generation"]
                age = (len(published) - index + 1) * 3600
                os.utime(path, (now - age, now - age))
            recent_incoming = generations_root / ".incoming-recent"
            stale_incoming = generations_root / ".incoming-stale"
            recent_incoming.mkdir()
            stale_incoming.mkdir()
            os.utime(recent_incoming, (now - 1800, now - 1800))
            os.utime(stale_incoming, (now - 7200, now - 7200))

            result = idb_cache.prune_cache(
                persisted_root=persisted,
                gamever=gamever,
                keep_generations=1,
                generation_min_age_hours=1,
                incoming_max_age_hours=1,
                now=now,
            )

            ready_generation = published[-1]["generation"]
            self.assertTrue((generations_root / ready_generation).is_dir())
            self.assertEqual(3, len(result["removed_generations"]))
            self.assertEqual([".incoming-stale"], result["removed_incoming"])
            self.assertTrue(recent_incoming.is_dir())

    def test_publish_builds_payload_inventory_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            gamever = "14180"
            self._write_source(source, gamever)

            with (
                self._patch_config(),
                patch.object(idb_cache, "file_inventory", wraps=idb_cache.file_inventory) as inventory,
            ):
                idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=root / "persisted",
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="106-1",
                )

            inventory.assert_called_once()

    def test_selected_old_generation_survives_other_warmups_until_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, self._patch_config():
            root = Path(temp_dir)
            source, persisted = root / "source", root / "persisted"
            gamever = "14180"
            generations = []
            for index in range(4):
                self._write_source(source, gamever, marker=f"v{index}".encode())
                published = idb_cache.publish_cache(
                    owner=self.owner,
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix=f"30{index}-1",
                )
                idb_cache.restore_cache(
                    owner=self.owner,
                    repo_root=root / "seed-consumer",
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    lease_id=published["lease_id"],
                    lease_sha256=published["lease_sha256"],
                    ida_version="9.2",
                )
                generations.append(published)
            cache_root = idb_cache._cache_root(persisted, gamever)
            now = time.time()
            for index, published in enumerate(generations):
                path = cache_root / "generations" / published["generation"]
                timestamp = now - (10 - index) * 24 * 3600
                os.utime(path, (timestamp, timestamp))
            self._write_source(source, gamever, marker=b"v0")
            selected = idb_cache.probe_cache(
                owner=self.owner,
                repo_root=source,
                persisted_root=persisted,
                gamever=gamever,
                ida_version="9.2",
            )
            # B prunes before probing; READY still protects A at this point.
            idb_cache.prune_cache(persisted_root=persisted, gamever=gamever, now=now)
            self._write_source(source, gamever, marker=b"v3")
            idb_cache.probe_cache(
                owner=self.owner,
                repo_root=source,
                persisted_root=persisted,
                gamever=gamever,
                ida_version="9.2",
            )
            # C can now prune A unless selection protection survives across jobs.
            idb_cache.prune_cache(persisted_root=persisted, gamever=gamever, now=now)
            idb_cache.restore_cache(
                owner=self.owner,
                repo_root=root / "consumer-a",
                persisted_root=persisted,
                gamever=gamever,
                generation=selected["generation"],
                expected_cache_key=selected["cache_key"],
                lease_id=selected["lease_id"],
                lease_sha256=selected["lease_sha256"],
                ida_version="9.2",
            )
            self.assertEqual(
                b"idb-server-v0",
                (root / "consumer-a/bin/14180/server/server.dll.i64").read_bytes(),
            )


class TestIdbCacheLeases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "producer"
        self.persisted = self.root / "persisted"
        self.gamever = "14180"
        self.owner = LeaseOwner("HLND2T/CS2_VibeSignatures", "100", "1")
        self.fixture = TestIdbCache()
        config = self.fixture._patch_config()
        config.start()
        self.addCleanup(config.stop)
        self.fixture._write_source(self.source, self.gamever)
        self.sequence = 0

    def publish(self, marker=b"v1", owner=None):
        self.sequence += 1
        self.fixture._write_source(self.source, self.gamever, marker=marker)
        return idb_cache.publish_cache(
            repo_root=self.source,
            persisted_root=self.persisted,
            gamever=self.gamever,
            ida_version="9.2",
            generation_suffix=f"{self.sequence}-1",
            owner=owner or self.owner,
        )

    def probe(self, owner=None):
        return idb_cache.probe_cache(
            repo_root=self.source,
            persisted_root=self.persisted,
            gamever=self.gamever,
            ida_version="9.2",
            owner=owner or self.owner,
        )

    def restore(self, selection, **overrides):
        arguments = {
            "repo_root": self.root / "consumer",
            "persisted_root": self.persisted,
            "gamever": self.gamever,
            "ida_version": "9.2",
            "generation": selection["generation"],
            "expected_cache_key": selection["cache_key"],
            "lease_id": selection["lease_id"],
            "lease_sha256": selection["lease_sha256"],
            "owner": self.owner,
        }
        return idb_cache.restore_cache(**{**arguments, **overrides})

    def lease_path(self, selection):
        return leases.lease_path(self.persisted, self.gamever, selection["lease_id"])

    def generation_path(self, selection):
        return leases.cache_root(self.persisted, self.gamever) / "generations" / selection["generation"]

    def make_prunable(self, selection):
        timestamp = time.time() - 10 * 24 * 3600
        os.utime(self.generation_path(selection), (timestamp, timestamp))
        # Three newer generations and a different READY remove all retention-based protection.
        for index in range(3):
            self.publish(marker=f"new-{index}".encode())

    def test_multiple_runs_and_attempts_protect_independently(self):
        first = self.publish()
        other_owner = LeaseOwner(self.owner.repository, "200", "2")
        second = self.probe(owner=other_owner)
        self.assertNotEqual(first["lease_id"], second["lease_id"])
        self.make_prunable(first)
        self.restore(first)
        result = idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
        self.assertNotIn(first["generation"], result["removed_generations"])
        self.restore(second, owner=other_owner, repo_root=self.root / "second-consumer")
        result = idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
        self.assertIn(first["generation"], result["removed_generations"])

    def test_partial_copy_failure_keeps_lease_until_full_retry_succeeds(self):
        selection = self.publish()
        self.make_prunable(selection)
        original_copy = idb_cache._atomic_copy
        copies = []

        def fail_second_binary(source, target):
            copies.append(source)
            if len(copies) == 3:
                raise OSError("injected second binary failure")
            original_copy(source, target)

        with patch.object(idb_cache, "_atomic_copy", side_effect=fail_second_binary):
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "second binary failure"):
                self.restore(selection)
        self.assertEqual("active", leases.load_json_object(self.lease_path(selection))["state"])
        idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
        self.assertTrue(self.generation_path(selection).is_dir())
        self.restore(selection)
        self.assertEqual("released", leases.load_json_object(self.lease_path(selection))["state"])

    def test_released_missing_and_expired_leases_fail_before_copy(self):
        released = self.publish()
        self.restore(released)
        missing = self.publish()
        self.lease_path(missing).unlink()
        expired = self.publish()
        expiration = leases.load_json_object(self.lease_path(expired))["expires_at"]
        with patch.object(idb_cache, "_atomic_copy") as copy:
            for selection, message in ((released, "released"), (missing, "unable to read JSON")):
                with self.subTest(message=message), self.assertRaisesRegex(idb_cache.IdbCacheError, message):
                    self.restore(selection)
            with patch.object(leases.time, "time", return_value=expiration):
                with self.assertRaisesRegex(idb_cache.IdbCacheError, "expired"):
                    self.restore(expired)
            copy.assert_not_called()

    def test_wrong_owner_selection_and_digest_fail_before_copy(self):
        selection = self.publish()
        cases = (
            {"owner": LeaseOwner("another/repository", "100", "1")},
            {"owner": LeaseOwner(self.owner.repository, "200", "1")},
            {"owner": LeaseOwner(self.owner.repository, "100", "2")},
            {"generation": "0" * 64 + "-1-1"},
            {"expected_cache_key": "0" * 64},
            {"lease_sha256": "0" * 64},
            {"lease_id": "../escape"},
            {"lease_id": ""},
            {"lease_id": "a/../" + selection["lease_id"]},
        )
        with patch.object(idb_cache, "_atomic_copy") as copy:
            for arguments in cases:
                with self.subTest(arguments=arguments), self.assertRaises(idb_cache.IdbCacheError):
                    self.restore(selection, **arguments)
            copy.assert_not_called()
        self.assertEqual("active", leases.load_json_object(self.lease_path(selection))["state"])

    def test_expired_or_cancelled_producer_is_reclaimed_after_clock_grace(self):
        selection = self.publish()
        self.make_prunable(selection)
        expiration = leases.load_json_object(self.lease_path(selection))["expires_at"]
        result = idb_cache.prune_cache(
            persisted_root=self.persisted,
            gamever=self.gamever,
            now=expiration + leases.CLOCK_SKEW_SECONDS - 1,
        )
        self.assertNotIn(selection["generation"], result["removed_generations"])
        result = idb_cache.prune_cache(
            persisted_root=self.persisted,
            gamever=self.gamever,
            now=expiration + leases.CLOCK_SKEW_SECONDS,
        )
        self.assertIn(selection["generation"], result["removed_generations"])
        self.assertFalse(self.lease_path(selection).exists())

    def test_corrupt_lease_blocks_pruning_before_any_generation_deletion(self):
        selection = self.publish()
        self.make_prunable(selection)
        self.lease_path(selection).write_text('{"broken":', encoding="utf-8")
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "unable to read JSON"):
            idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
        self.assertTrue(self.generation_path(selection).is_dir())
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "unable to read JSON"):
            self.restore(selection)

    def test_invalid_lease_metadata_fails_closed(self):
        selection = self.publish()
        original = leases.load_json_object(self.lease_path(selection))
        cases = (
            {"schema_version": 2},
            {"schema_version": True},
            {"lease_id": "0" * 32},
            {"gamever": "99999"},
            {"state": "unknown"},
            {"owner": []},
            {"owner": {**original["owner"], "run_attempt": "0"}},
            {"generation": "../../escape"},
            {"manifest_sha256": "bad"},
            {"cache_key": "0" * 64},
            {"created_at": True},
            {"expires_at": float("nan")},
            {"expires_at": original["expires_at"] + 1},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                leases.write_canonical_json(self.lease_path(selection), {**original, **changes})
                with self.assertRaises(idb_cache.IdbCacheError):
                    self.restore(selection)
                with self.assertRaises(idb_cache.IdbCacheError):
                    idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)

    def test_lease_read_error_blocks_prune(self):
        selection = self.publish()
        self.make_prunable(selection)
        original = leases.load_json_object

        def read(path):
            if Path(path).resolve() == self.lease_path(selection).resolve():
                raise OSError("lease read denied")
            return original(path)

        with patch.object(leases, "load_json_object", side_effect=read):
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "lease read denied"):
                idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
        self.assertTrue(self.generation_path(selection).is_dir())

    def test_failed_lease_write_returns_no_selection_and_leaves_no_partial_lease(self):
        self.publish()
        before = set((leases.cache_root(self.persisted, self.gamever) / "leases").iterdir())
        with patch.object(leases, "write_canonical_json", side_effect=OSError("lease write denied")):
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "lease write denied"):
                self.probe()
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "lease write denied"):
                self.publish(marker=b"v2")
        self.assertEqual(before, set((leases.cache_root(self.persisted, self.gamever) / "leases").iterdir()))

    def test_release_write_failure_keeps_protection(self):
        selection = self.publish()
        with patch.object(leases, "write_canonical_json", side_effect=OSError("release write denied")):
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "release write denied"):
                self.restore(selection)
        self.assertEqual("active", leases.load_json_object(self.lease_path(selection))["state"])
        self.restore(selection)

    def test_lease_directory_enumeration_failure_blocks_pruning(self):
        selection = self.publish()
        self.make_prunable(selection)
        root = self.lease_path(selection).parent
        original = Path.iterdir

        def unreadable(path):
            if path == root:
                raise PermissionError("lease enumeration denied")
            return original(path)

        with patch.object(Path, "iterdir", unreadable):
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "lease enumeration denied"):
                idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
        self.assertTrue(self.generation_path(selection).is_dir())

    def test_lease_root_replaced_by_file_blocks_pruning(self):
        selection = self.publish()
        self.make_prunable(selection)
        root = self.lease_path(selection).parent
        root.rename(root.with_name("saved-leases"))
        root.write_text("damaged lease directory", encoding="utf-8")
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "lease root is not a directory"):
            idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
        self.assertTrue(self.generation_path(selection).is_dir())

    def test_actual_atomic_lease_write_failure_emits_no_cli_output(self):
        self.publish()
        root = leases.cache_root(self.persisted, self.gamever) / "leases"
        before = set(root.iterdir())
        output = self.root / "github-output"
        with (
            patch("release_workflow_lib.hashing.os.replace", side_effect=OSError("atomic lease failure")),
            redirect_stderr(io.StringIO()),
        ):
            result = idb_cache.main(
                [
                    "probe",
                    "--persisted-root",
                    str(self.persisted),
                    "--repo-root",
                    str(self.source),
                    "--gamever",
                    self.gamever,
                    "--ida-version",
                    "9.2",
                    "--repository",
                    self.owner.repository,
                    "--run-id",
                    self.owner.run_id,
                    "--run-attempt",
                    self.owner.run_attempt,
                    "--github-output",
                    str(output),
                ]
            )
        self.assertEqual(1, result)
        self.assertFalse(output.exists())
        self.assertEqual(before, set(root.iterdir()))

    def test_clock_skew_beyond_grace_fails_closed(self):
        selection = self.publish()
        created = leases.load_json_object(self.lease_path(selection))["created_at"]
        now = created - leases.CLOCK_SKEW_SECONDS - 1
        with patch.object(leases.time, "time", return_value=now):
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "clock differs"):
                self.restore(selection)
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "creation time is in the future"):
            idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever, now=now)

    def test_lease_and_lock_directory_reparse_points_are_rejected(self):
        selection = self.publish()
        paths = (
            self.lease_path(selection).parent,
            self.persisted / leases.CACHE_NAMESPACE / ".locks",
        )
        for root in paths:
            with self.subTest(root=root.name):
                target = root.with_name(f"{root.name}-redirected")
                root.rename(target)
                if os.name == "nt":
                    subprocess.run(
                        ["cmd", "/c", "mklink", "/j", str(root), str(target)],
                        check=True,
                        capture_output=True,
                    )
                else:
                    root.symlink_to(target, target_is_directory=True)
                try:
                    with self.assertRaisesRegex(idb_cache.IdbCacheError, "reparse"):
                        self.restore(selection)
                    with self.assertRaisesRegex(idb_cache.IdbCacheError, "reparse"):
                        idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever)
                finally:
                    if os.name == "nt":
                        root.rmdir()
                    else:
                        root.unlink()
                    target.rename(root)

    def test_legacy_namespace_is_neither_reused_nor_pruned(self):
        selection = self.publish()
        current = leases.cache_root(self.persisted, self.gamever)
        legacy = self.persisted / "idb-cache" / self.gamever
        legacy.parent.mkdir(parents=True)
        current.rename(legacy)
        self.assertFalse(self.probe()["cache_hit"])
        idb_cache.prune_cache(persisted_root=self.persisted, gamever=self.gamever, generation_min_age_hours=0)
        self.assertTrue((legacy / "generations" / selection["generation"]).is_dir())

    def test_cross_process_lock_covers_restore_copy_and_releases_after_failure(self):
        selection = self.publish()
        project = Path(idb_cache.__file__).parent
        child = (
            "import sys; from pathlib import Path; from idb_cache_leases import cache_lock; "
            "from release_workflow_lib.errors import ReleaseWorkflowError\n"
            "try:\n"
            "    with cache_lock(Path(sys.argv[1]), sys.argv[2], timeout=0): print('acquired')\n"
            "except ReleaseWorkflowError: print('blocked')\n"
        )

        def lock_result():
            result = subprocess.run(
                [sys.executable, "-c", child, str(self.persisted), self.gamever],
                cwd=project,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            return result.stdout.strip()

        def fail_copy(_source, _target):
            self.assertEqual("blocked", lock_result())
            raise OSError("copy failed")

        with patch.object(idb_cache, "_atomic_copy", side_effect=fail_copy):
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "copy failed"):
                self.restore(selection)
        self.assertEqual("acquired", lock_result())

    def test_cli_selection_restores_in_another_process_and_workspace(self):
        project = Path(idb_cache.__file__).parent
        child = (
            "import sys, runpy; sys.path.insert(0, sys.argv.pop(1)); import idb_cache; "
            "fixture = runpy.run_path(sys.argv.pop(1))['TestIdbCache']()\n"
            "with fixture._patch_config(): raise SystemExit(idb_cache.main(sys.argv[1:]))\n"
        )

        def cli(command, *extra):
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    child,
                    str(project),
                    str(Path(__file__).resolve()),
                    command,
                    "--persisted-root",
                    str(self.persisted),
                    "--gamever",
                    self.gamever,
                    "--repository",
                    self.owner.repository,
                    "--run-id",
                    self.owner.run_id,
                    "--run-attempt",
                    self.owner.run_attempt,
                    "--ida-version",
                    "9.2",
                    *extra,
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            return json.loads(result.stdout)

        published = cli("publish", "--repo-root", str(self.source), "--generation-suffix", "100-1")
        consumer = self.root / "independent-consumer"
        restored = cli(
            "restore",
            "--repo-root",
            str(consumer),
            "--generation",
            published["generation"],
            "--cache-key",
            published["cache_key"],
            "--lease-id",
            published["lease_id"],
            "--lease-sha256",
            published["lease_sha256"],
        )
        self.assertEqual(published["generation"], restored["generation"])
        self.assertEqual(b"idb-engine-v1", (consumer / "bin/14180/engine/libengine2.so.i64").read_bytes())


if __name__ == "__main__":
    unittest.main()
