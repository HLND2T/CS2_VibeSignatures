from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pages_release_input as pri
from release_bundle import _create_archive, _release_rebuild_digest
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    file_inventory,
    inventory_sha256,
    load_json_object,
    sha256_bytes,
)


SOURCE_A = "1" * 40
SOURCE_B = "2" * 40
DIGEST = "sha256:" + "3" * 64


class FakeReleaseClient:
    def __init__(self, releases: list[dict], blobs: dict[int, bytes], tag_targets: dict[str, str]):
        self.releases = releases
        self.blobs = blobs
        self.tag_targets = tag_targets

    def list_releases(self) -> list[dict]:
        return self.releases

    def tag_target(self, tag: str) -> str:
        return self.tag_targets[tag]

    def download_asset(self, asset: dict, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.blobs[asset["id"]])


class FakeExtractor:
    def __init__(self, payloads: dict[str, bytes], *, tamper: bool = False):
        self.payloads = payloads
        self.tamper = tamper

    def extract_gamedata(
        self,
        _archive: Path,
        destination: Path,
        game_version: str,
        _expected: list[dict],
    ) -> None:
        payload = self.payloads[game_version]
        if self.tamper:
            payload += b"tampered"
        target = destination / "gamedata" / game_version / "Plugin" / "data.jsonc"
        target.parent.mkdir(parents=True)
        target.write_bytes(payload)


def _asset_record(path: str, raw: bytes) -> dict:
    return {
        "path": path,
        "name": Path(path).name,
        "size": len(raw),
        "sha256": sha256_bytes(raw),
    }


def _release_fixture(
    release_id: int, game_version: str, source_sha: str, asset_id_start: int
) -> tuple[dict, dict[int, bytes], bytes]:
    snapshot = f"snapshot-{game_version}\n".encode()
    metadata = f"metadata-{game_version}\n".encode()
    gamedata = f'{{"gamever":"{game_version}"}}\n'.encode()
    gamedata_archive = f"archive-{game_version}".encode()
    gamebin_archive = f"gamebin-{game_version}".encode()
    gamedata_files = [
        {
            "path": f"gamedata/{game_version}/Plugin/data.jsonc",
            "size": len(gamedata),
            "sha256": sha256_bytes(gamedata),
        }
    ]
    gamebin_files = [
        {
            "path": f"bin/{game_version}/server/server.dll",
            "size": 1,
            "sha256": "4" * 64,
        }
    ]
    public_assets = [
        _asset_record(f"gamesymbols/{game_version}.yaml", snapshot),
        _asset_record(f"gamesymbols/{game_version}.metadata.yaml", metadata),
        _asset_record(f"archives/gamedata-{game_version}.7z", gamedata_archive),
        _asset_record(f"archives/gamebin-{game_version}.7z", gamebin_archive),
    ]
    full_rebuild = {
        "schema_version": 1,
        "source_sha": source_sha,
        "game_version": game_version,
        "binary_lock_sha256": DIGEST,
        "artifact_inventory_sha256": DIGEST,
    }
    full_rebuild["verification_sha256"] = _release_rebuild_digest("rebuild-verification", full_rebuild)
    manifest = {
        "schema_version": 2,
        "repository": pri.ALLOWED_REPOSITORY,
        "release_version": game_version,
        "game_version": game_version,
        "build_id": source_sha,
        "actions_artifact_name": f"release-{game_version}",
        "source_sha": source_sha,
        "source_subject": f"Release {game_version}",
        "download_sha256": DIGEST,
        "config_sha256": DIGEST,
        "sdk_gitlink_sha": "5" * 40,
        "cpp_sdk": {"ref": "source-gitlink", "sha": "5" * 40},
        "sdk_files": [{"path": "README.md", "size": 1, "sha256": "6" * 64}],
        "sdk_inventory_sha256": "7" * 64,
        "binary_lock_sha256": DIGEST,
        "binary_inventory": {},
        "binary_inventory_sha256": DIGEST,
        "artifact_inventory_sha256": DIGEST,
        "producer_contract": {"files": [], "digest": DIGEST},
        "ida_runtime_identity": "IDA-9.2",
        "warm_idb_generation": "generation",
        "warm_idb_cache_key": "cache-key",
        "full_rebuild": full_rebuild,
        "snapshot": {
            "path": f"gamesymbols/{game_version}.yaml",
            "sha256": sha256_bytes(snapshot),
            "file_count": 1,
        },
        "metadata": {
            "path": f"gamesymbols/{game_version}.metadata.yaml",
            "sha256": sha256_bytes(metadata),
        },
        "gamedata": {
            "path": f"gamedata/{game_version}",
            "files": gamedata_files,
            "manifest_sha256": DIGEST,
            "generator_contract_sha256": DIGEST,
        },
        "cpp_validation_sha256": "8" * 64,
        "binsync": {
            "candidate_publication_digest": DIGEST,
            "repositories": [],
            "target_state_digest": DIGEST,
        },
        "archives": {
            f"archives/gamedata-{game_version}.7z": {
                "files": gamedata_files,
                "inventory_sha256": inventory_sha256(gamedata_files),
            },
            f"archives/gamebin-{game_version}.7z": {
                "files": gamebin_files,
                "inventory_sha256": inventory_sha256(gamebin_files),
            },
        },
        "public_assets": public_assets,
    }
    manifest_name = f"release-manifest-{game_version}.json"
    checksum_name = f"SHA256SUMS-{game_version}.txt"
    manifest_bytes = canonical_json_bytes(manifest)
    checksum_bytes = "".join(
        f"{item['sha256']}  {item['path']}\n"
        for item in sorted(
            [
                *public_assets,
                {
                    "path": manifest_name,
                    "name": manifest_name,
                    "size": len(manifest_bytes),
                    "sha256": sha256_bytes(manifest_bytes),
                },
            ],
            key=lambda item: item["path"],
        )
    ).encode()
    named_blobs = {
        f"{game_version}.yaml": snapshot,
        f"{game_version}.metadata.yaml": metadata,
        f"gamedata-{game_version}.7z": gamedata_archive,
        f"gamebin-{game_version}.7z": gamebin_archive,
        manifest_name: manifest_bytes,
        checksum_name: checksum_bytes,
    }
    blobs = {}
    assets = []
    for offset, (name, raw) in enumerate(named_blobs.items()):
        asset_id = asset_id_start + offset
        blobs[asset_id] = raw
        assets.append({"id": asset_id, "name": name, "size": len(raw)})
    release = {
        "id": release_id,
        "tag_name": game_version,
        "target_commitish": source_sha,
        "draft": False,
        "prerelease": False,
        "assets": assets,
    }
    return release, blobs, gamedata


class PagesReleaseInputTests(unittest.TestCase):
    def _stage(
        self,
        root: Path,
        releases: list[dict],
        blobs: dict[int, bytes],
        payloads: dict[str, bytes],
        *,
        trigger: dict,
        manifest_digest: str,
        extractor: FakeExtractor | None = None,
        tag_targets: dict[str, str] | None = None,
    ) -> dict:
        return pri.stage_pages_release_inputs(
            repository=pri.ALLOWED_REPOSITORY,
            triggering_release_id=trigger["id"],
            triggering_tag=trigger["tag_name"],
            triggering_source_sha=trigger["target_commitish"],
            triggering_manifest_sha256=manifest_digest,
            output_root=root / "input",
            receipt_path=root / "receipt.json",
            client=FakeReleaseClient(
                releases,
                blobs,
                tag_targets
                or {release["tag_name"]: release["target_commitish"] for release in releases if "tag_name" in release},
            ),
            extractor=extractor or FakeExtractor(payloads),
        )

    def test_stages_every_compatible_published_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, first_blobs, first_gamedata = _release_fixture(101, "14177", SOURCE_A, 1000)
            second, second_blobs, second_gamedata = _release_fixture(102, "14178", SOURCE_B, 2000)
            legacy = {
                "id": 99,
                "tag_name": "14176",
                "target_commitish": "9" * 40,
                "draft": False,
                "prerelease": False,
                "assets": [],
            }
            blobs = {**first_blobs, **second_blobs}
            manifest_name = "release-manifest-14178.json"
            manifest_asset = next(asset for asset in second["assets"] if asset["name"] == manifest_name)

            receipt = self._stage(
                root,
                [second, legacy, first],
                blobs,
                {"14177": first_gamedata, "14178": second_gamedata},
                trigger=second,
                manifest_digest=sha256_bytes(blobs[manifest_asset["id"]]),
            )

            self.assertEqual(["14177", "14178"], [item["game_version"] for item in receipt["releases"]])
            self.assertEqual(
                second_gamedata,
                (root / "input" / "gamedata" / "14178" / "Plugin" / "data.jsonc").read_bytes(),
            )
            self.assertTrue((root / "input" / "gamesymbols" / "14177.yaml").is_file())
            self.assertEqual(receipt, load_json_object(root / "receipt.json"))

    def test_rejects_trigger_identity_checksum_and_unexpected_assets(self) -> None:
        mutations = ("manifest", "checksum", "unexpected")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                release, blobs, gamedata = _release_fixture(201, "14179", SOURCE_A, 3000)
                manifest_asset = next(
                    asset for asset in release["assets"] if asset["name"].startswith("release-manifest-")
                )
                checksum_asset = next(asset for asset in release["assets"] if asset["name"].startswith("SHA256SUMS-"))
                manifest_digest = sha256_bytes(blobs[manifest_asset["id"]])
                if mutation == "manifest":
                    manifest_digest = "0" * 64
                elif mutation == "checksum":
                    blobs[checksum_asset["id"]] = b"0" * checksum_asset["size"]
                else:
                    release["assets"].append({"id": 3999, "name": "unexpected.txt", "size": 1})
                    blobs[3999] = b"x"

                with self.assertRaises(pri.PagesReleaseInputError):
                    self._stage(
                        root,
                        [release],
                        blobs,
                        {"14179": gamedata},
                        trigger=release,
                        manifest_digest=manifest_digest,
                    )
                self.assertFalse((root / "input").exists())

    def test_rejects_tag_target_and_extracted_gamedata_drift(self) -> None:
        for mutation in ("tag", "gamedata"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                release, blobs, gamedata = _release_fixture(301, "14180", SOURCE_B, 4000)
                manifest_asset = next(
                    asset for asset in release["assets"] if asset["name"].startswith("release-manifest-")
                )
                kwargs = {}
                extractor = FakeExtractor({"14180": gamedata})
                if mutation == "tag":
                    kwargs["tag_targets"] = {"14180": SOURCE_A}
                else:
                    extractor = FakeExtractor({"14180": gamedata}, tamper=True)

                with self.assertRaises(pri.PagesReleaseInputError):
                    self._stage(
                        root,
                        [release],
                        blobs,
                        {"14180": gamedata},
                        trigger=release,
                        manifest_digest=sha256_bytes(blobs[manifest_asset["id"]]),
                        extractor=extractor,
                        **kwargs,
                    )

    def test_seven_zip_listing_rejects_traversal_and_links(self) -> None:
        with self.assertRaises(pri.PagesReleaseInputError):
            pri.SevenZipGamedataExtractor._listed_files("Path = ../escape.txt\nSize = 1\nFolder = -\n\n")
        with self.assertRaises(pri.PagesReleaseInputError):
            pri.SevenZipGamedataExtractor._listed_files(
                "Path = gamedata/14180/link\nSize = 1\nFolder = -\nSymbolic Link = target\n\n"
            )

    def test_seven_zip_extractor_preflights_and_extracts_only_gamedata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            gamedata = source / "gamedata" / "14181" / "Plugin" / "data.jsonc"
            unrelated = source / "bin_artifacts" / "14181" / "server" / "Symbol.yaml"
            gamedata.parent.mkdir(parents=True)
            unrelated.parent.mkdir(parents=True)
            gamedata.write_text('{"value":1}\n', encoding="utf-8", newline="\n")
            unrelated.write_text("func_name: Symbol\n", encoding="utf-8", newline="\n")
            archive = root / "gamedata-14181.7z"
            _create_archive(source, archive)

            extracted = root / "extracted"
            expected = file_inventory(source)
            pri.SevenZipGamedataExtractor().extract_gamedata(archive, extracted, "14181", expected)

            self.assertEqual(
                [item for item in expected if item["path"].startswith("gamedata/14181/")],
                file_inventory(extracted),
            )


if __name__ == "__main__":
    unittest.main()
