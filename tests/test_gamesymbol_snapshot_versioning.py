import contextlib
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml

import analysis_output_contract
from gamesymbol_snapshot_lib.codec import (
    LEGACY_SCHEMA_VERSION,
    SCHEMA_2_VERSION,
    SCHEMA_3_VERSION,
    SCHEMA_4_VERSION,
    SCHEMA_VERSION,
    build_snapshot_document,
    canonical_snapshot_bytes,
    parse_snapshot_bytes,
    snapshot_analysis_output_contract_version,
    snapshot_config_digest_version,
)
from gamesymbol_snapshot_lib.config import (
    V1_ADDITIVE_FIELDS,
    V1_LEGACY_SKILL_FIELDS,
    V2_DOMAIN_SEPARATOR,
    V2_SKILL_FIELDS,
    load_contract,
    load_unversioned_schema1_contract,
)
from gamesymbol_snapshot_lib.errors import SnapshotMismatchError, SnapshotSchemaError, SnapshotUntrustedError
from gamesymbol_snapshot_lib.operations import check_snapshot_contract, migrate_snapshot
from gamesymbol_snapshot_lib.snapshot_cli import main as snapshot_main
from tests.gamesymbol_snapshot_test_support import module, skill, write_binary, write_config


class VersioningFixture:
    gamever = "14199"

    def __init__(self, root: Path, *, optional_input=None) -> None:
        self.root = root
        self.config = root / "config.yaml"
        self.bindir = root / "bin"
        self.snapshot = root / "snapshot.yaml"
        extra = {} if optional_input is None else {"optional_input": optional_input}
        write_config(
            self.config,
            [module("server", [skill("find-a", ["A.{platform}.yaml"], **extra)], linux=False)],
        )

    def write_snapshot(
        self,
        digest_version: int,
        *,
        config_sha256: str | None = None,
        schema_version: int | None = None,
    ) -> bytes:
        contract = load_contract(self.config, self.gamever, self.bindir, digest_version)
        schema_version = schema_version or (LEGACY_SCHEMA_VERSION if digest_version == 1 else SCHEMA_VERSION)
        binary_metadata = {
            "path": "game/bin/win64/server.dll",
            "sha256": "1" * 64,
            "md5": "2" * 32,
        }
        if schema_version == SCHEMA_VERSION:
            binary_metadata.update({"crc32": "3" * 8, "crc64": "4" * 16, "size": 123})
        document = build_snapshot_document(
            self.gamever,
            config_sha256 or contract.config_sha256,
            {"server/A.windows.yaml": {"func_name": "A", "func_rva": "0x10"}},
            schema_version=schema_version,
            config_digest_version=digest_version,
            last_publish_time="2026-01-02T03:04:05Z" if schema_version in {SCHEMA_4_VERSION, SCHEMA_VERSION} else None,
            binaries={"server": {"windows": binary_metadata}}
            if schema_version in {SCHEMA_4_VERSION, SCHEMA_VERSION}
            else None,
        )
        data = canonical_snapshot_bytes(document)
        self.snapshot.write_bytes(data)
        return data

    def write_binary(self) -> None:
        write_binary(self.bindir / self.gamever / "server" / "server.dll", b"server-binary")


class TestConfigDigestVersioning(unittest.TestCase):
    def test_frozen_field_sets_and_domain_separator(self) -> None:
        self.assertEqual(
            (
                "name",
                "platform",
                "expected_output",
                "expected_output_windows",
                "expected_output_linux",
                "optional_output",
                "expected_input",
                "expected_input_windows",
                "expected_input_linux",
                "prerequisite",
                "skip_if_exists",
            ),
            V1_LEGACY_SKILL_FIELDS,
        )
        self.assertEqual(
            ("optional_input", "optional_input_windows", "optional_input_linux"),
            V1_ADDITIVE_FIELDS,
        )
        self.assertEqual(
            (
                "name",
                "platform",
                "expected_output",
                "expected_output_windows",
                "expected_output_linux",
                "optional_output",
                "expected_input",
                "expected_input_windows",
                "expected_input_linux",
                "optional_input",
                "optional_input_windows",
                "optional_input_linux",
                "prerequisite",
                "skip_if_exists",
            ),
            V2_SKILL_FIELDS,
        )
        self.assertEqual(b"gamesymbol-config-contract:v2\n", V2_DOMAIN_SEPARATOR)

    def test_hard_coded_minimal_v1_and_v2_digests(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))

            v1 = load_contract(fixture.config, fixture.gamever, fixture.bindir, 1)
            v2 = load_contract(fixture.config, fixture.gamever, fixture.bindir, 2)

        self.assertEqual("sha256:783380997380347b135207a375957a92853f31edbf6de0847b454546e79c9d9d", v1.config_sha256)
        self.assertEqual("sha256:975143dae3789132fc0f9dee359721f60af380363f6deb5dcd0ab87a3d33ab9a", v2.config_sha256)

    def test_v1_missing_and_empty_optional_input_match_but_nonempty_changes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing = VersioningFixture(root / "missing")
            empty = VersioningFixture(root / "empty", optional_input=[])
            nonempty = VersioningFixture(root / "nonempty", optional_input=["Optional.{platform}.yaml"])

            missing_digest = load_contract(missing.config, missing.gamever, missing.bindir, 1).config_sha256
            empty_digest = load_contract(empty.config, empty.gamever, empty.bindir, 1).config_sha256
            nonempty_digest = load_contract(nonempty.config, nonempty.gamever, nonempty.bindir, 1).config_sha256

        self.assertEqual(missing_digest, empty_digest)
        self.assertNotEqual(missing_digest, nonempty_digest)

    def test_checked_in_v1_regression_fixture_keeps_digest(self) -> None:
        config = Path("tests/fixtures/config_digest_v1_regression.yaml")
        digest = load_contract(config, "fixture", "bin", 1).config_sha256

        self.assertEqual("sha256:b2b853cf7045d34f20d10641729d7586d7ed840434423d5f10f6c2d6cf737b73", digest)


class TestSnapshotSchemaVersioning(unittest.TestCase):
    def test_schema_1_bytes_remain_stable_and_imply_digest_v1(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            raw = fixture.write_snapshot(1)
            document = parse_snapshot_bytes(raw, fixture.gamever)

        self.assertEqual(1, snapshot_config_digest_version(document))
        self.assertNotIn("config_digest_version", document)
        self.assertEqual(raw, canonical_snapshot_bytes(document))

    def test_schema_2_requires_supported_explicit_digest_version(self) -> None:
        base = {
            "schema_version": 2,
            "game_version": "1",
            "config_sha256": "sha256:" + "0" * 64,
            "file_count": 0,
            "files": {},
        }
        with self.assertRaisesRegex(SnapshotSchemaError, "exactly"):
            parse_snapshot_bytes(yaml.safe_dump(base).encode())
        base["config_digest_version"] = 999
        with self.assertRaisesRegex(SnapshotSchemaError, "config_digest_version"):
            parse_snapshot_bytes(yaml.safe_dump(base).encode())

    def test_schema_2_maps_to_analysis_output_contract_version_1(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            document = parse_snapshot_bytes(
                fixture.write_snapshot(2, schema_version=SCHEMA_2_VERSION),
                fixture.gamever,
            )

        self.assertEqual(SCHEMA_2_VERSION, document["schema_version"])
        self.assertEqual(1, snapshot_analysis_output_contract_version(document))
        self.assertNotIn("analysis_output_contract_version", document)

    def test_schema_3_requires_positive_analysis_output_contract_version(self) -> None:
        base = {
            "schema_version": SCHEMA_3_VERSION,
            "config_digest_version": 2,
            "game_version": "1",
            "config_sha256": "sha256:" + "0" * 64,
            "file_count": 0,
            "files": {},
        }
        with self.assertRaisesRegex(SnapshotSchemaError, "exactly"):
            parse_snapshot_bytes(yaml.safe_dump(base).encode())
        base["analysis_output_contract_version"] = 0
        with self.assertRaisesRegex(SnapshotSchemaError, "analysis_output_contract_version"):
            parse_snapshot_bytes(yaml.safe_dump(base).encode())

    def test_schema_4_remains_readable_with_legacy_publish_metadata(self) -> None:
        base = {
            "schema_version": SCHEMA_4_VERSION,
            "last_publish_time": "2026-01-02T03:04:05Z",
            "binaries": {
                "server": {
                    "windows": {
                        "path": "game/bin/win64/server.dll",
                        "sha256": "1" * 64,
                        "md5": "2" * 32,
                    }
                }
            },
            "analysis_output_contract_version": 1,
            "config_digest_version": 2,
            "game_version": "1",
            "config_sha256": "sha256:" + "0" * 64,
            "file_count": 0,
            "files": {},
        }
        parsed = parse_snapshot_bytes(canonical_snapshot_bytes(base))
        self.assertEqual(base, parsed)

        invalid_cases = (
            ("last_publish_time", "2026-01-02T03:04:05+00:00"),
            ("last_publish_time", "2026-02-30T03:04:05Z"),
            ("sha256", "A" * 64),
            ("sha256", "1" * 63),
            ("md5", "2" * 31),
        )
        for field, value in invalid_cases:
            with self.subTest(field=field, value=value):
                candidate = yaml.safe_load(yaml.safe_dump(base))
                if field == "last_publish_time":
                    candidate[field] = value
                else:
                    candidate["binaries"]["server"]["windows"][field] = value
                with self.assertRaises(SnapshotSchemaError):
                    parse_snapshot_bytes(yaml.safe_dump(candidate).encode())

    def test_schema_5_requires_exact_valid_binary_integrity_metadata(self) -> None:
        base = {
            "schema_version": SCHEMA_VERSION,
            "last_publish_time": "2026-01-02T03:04:05Z",
            "binaries": {
                "server": {
                    "windows": {
                        "path": "game/bin/win64/server.dll",
                        "sha256": "1" * 64,
                        "md5": "2" * 32,
                        "crc32": "3" * 8,
                        "crc64": "4" * 16,
                        "size": 123,
                    }
                }
            },
            "analysis_output_contract_version": 1,
            "config_digest_version": 2,
            "game_version": "1",
            "config_sha256": "sha256:" + "0" * 64,
            "file_count": 0,
            "files": {},
        }
        self.assertEqual(base, parse_snapshot_bytes(canonical_snapshot_bytes(base)))

        invalid_cases = (("crc32", "A" * 8), ("crc64", "4" * 15), ("size", -1), ("size", True))
        for field, value in invalid_cases:
            with self.subTest(field=field, value=value):
                candidate = yaml.safe_load(yaml.safe_dump(base))
                candidate["binaries"]["server"]["windows"][field] = value
                with self.assertRaises(SnapshotSchemaError):
                    parse_snapshot_bytes(yaml.safe_dump(candidate).encode())

    def test_contract_probe_accepts_v1_through_v5_without_mutating_bin(self) -> None:
        cases = (
            (1, LEGACY_SCHEMA_VERSION),
            (2, SCHEMA_2_VERSION),
            (2, SCHEMA_3_VERSION),
            (2, SCHEMA_4_VERSION),
            (2, SCHEMA_VERSION),
        )
        for digest_version, schema_version in cases:
            with (
                self.subTest(digest_version=digest_version, schema_version=schema_version),
                TemporaryDirectory() as temp_dir,
            ):
                fixture = VersioningFixture(Path(temp_dir))
                fixture.write_snapshot(digest_version, schema_version=schema_version)

                context = check_snapshot_contract(
                    fixture.gamever,
                    fixture.bindir,
                    fixture.config,
                    fixture.snapshot,
                )

                self.assertEqual(digest_version, context.contract.config_digest_version)
                self.assertEqual(1, context.contract.analysis_output_contract_version)
                self.assertFalse(fixture.bindir.exists())

    def test_contract_probe_returns_structured_untrusted_result(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            fixture.write_snapshot(2, config_sha256="sha256:" + "f" * 64)
            stdout = io.StringIO()
            args = [
                "check-contract",
                "-gamever",
                fixture.gamever,
                "-bindir",
                str(fixture.bindir),
                "-configyaml",
                str(fixture.config),
                "-snapshot",
                str(fixture.snapshot),
                "-json",
            ]

            with contextlib.redirect_stdout(stdout):
                exit_code = snapshot_main(args)

        self.assertEqual(3, exit_code)
        self.assertIn('"reason": "config_digest_mismatch"', stdout.getvalue())
        self.assertFalse(fixture.bindir.exists())

    def test_contract_probe_rejects_analyzer_output_contract_version_mismatch(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            fixture.write_snapshot(2, schema_version=SCHEMA_2_VERSION)
            with patch.object(analysis_output_contract, "ANALYSIS_OUTPUT_CONTRACT_VERSION", 2):
                with self.assertRaisesRegex(SnapshotUntrustedError, "analysis output contract version mismatch"):
                    check_snapshot_contract(
                        fixture.gamever,
                        fixture.bindir,
                        fixture.config,
                        fixture.snapshot,
                    )

    def test_migration_changes_only_metadata_and_is_atomic(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            source = parse_snapshot_bytes(fixture.write_snapshot(1))
            fixture.write_binary()

            migrated_raw = migrate_snapshot(
                fixture.gamever,
                fixture.bindir,
                fixture.config,
                fixture.snapshot,
            )
            migrated = parse_snapshot_bytes(migrated_raw)

            self.assertEqual(5, migrated["schema_version"])
            self.assertEqual(2, migrated["config_digest_version"])
            self.assertEqual(1, migrated["analysis_output_contract_version"])
            self.assertEqual(source["game_version"], migrated["game_version"])
            self.assertEqual(source["file_count"], migrated["file_count"])
            self.assertEqual(source["files"], migrated["files"])
            self.assertEqual(migrated_raw, fixture.snapshot.read_bytes())
            self.assertIn("last_publish_time", migrated)
            self.assertIn("binaries", migrated)
            with self.assertRaisesRegex(SnapshotMismatchError, "schema 1, 2, 3, or 4 source"):
                migrate_snapshot(fixture.gamever, fixture.bindir, fixture.config, fixture.snapshot)

    def test_migration_accepts_known_unversioned_schema_1_transition_digest(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            transitional = load_unversioned_schema1_contract(
                fixture.config,
                fixture.gamever,
                fixture.bindir,
            )
            source = build_snapshot_document(
                fixture.gamever,
                transitional.config_sha256,
                {"server/A.windows.yaml": {"func_name": "A"}},
                schema_version=1,
                config_digest_version=1,
            )
            fixture.snapshot.write_bytes(canonical_snapshot_bytes(source))
            fixture.write_binary()

            migrated = parse_snapshot_bytes(
                migrate_snapshot(fixture.gamever, fixture.bindir, fixture.config, fixture.snapshot)
            )

        self.assertEqual(5, migrated["schema_version"])
        self.assertEqual(source["files"], migrated["files"])

    def test_migration_upgrades_schema_2_to_schema_5(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            source = parse_snapshot_bytes(fixture.write_snapshot(2, schema_version=SCHEMA_2_VERSION))
            fixture.write_binary()

            migrated = parse_snapshot_bytes(
                migrate_snapshot(fixture.gamever, fixture.bindir, fixture.config, fixture.snapshot)
            )

        self.assertEqual(5, migrated["schema_version"])
        self.assertEqual(1, migrated["analysis_output_contract_version"])
        self.assertEqual(source["files"], migrated["files"])

    def test_migration_upgrades_schema_3_with_explicit_historical_time(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            source = parse_snapshot_bytes(fixture.write_snapshot(2, schema_version=SCHEMA_3_VERSION))
            fixture.write_binary()

            migrated = parse_snapshot_bytes(
                migrate_snapshot(
                    fixture.gamever,
                    fixture.bindir,
                    fixture.config,
                    fixture.snapshot,
                    last_publish_time="2025-12-31T23:59:58Z",
                )
            )

        self.assertEqual(5, migrated["schema_version"])
        self.assertEqual("2025-12-31T23:59:58Z", migrated["last_publish_time"])
        self.assertEqual(source["files"], migrated["files"])

    def test_migration_upgrades_schema_4_and_preserves_its_publish_time(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fixture = VersioningFixture(Path(temp_dir))
            source = parse_snapshot_bytes(fixture.write_snapshot(2, schema_version=SCHEMA_4_VERSION))
            fixture.write_binary()

            migrated = parse_snapshot_bytes(
                migrate_snapshot(fixture.gamever, fixture.bindir, fixture.config, fixture.snapshot)
            )

        self.assertEqual(SCHEMA_VERSION, migrated["schema_version"])
        self.assertEqual(source["last_publish_time"], migrated["last_publish_time"])
        self.assertEqual(source["files"], migrated["files"])
        self.assertEqual("c46b11c1", migrated["binaries"]["server"]["windows"]["crc32"])
        self.assertEqual("0485ac38eb282c87", migrated["binaries"]["server"]["windows"]["crc64"])
        self.assertEqual(13, migrated["binaries"]["server"]["windows"]["size"])


if __name__ == "__main__":
    unittest.main()
