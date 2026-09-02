import tempfile
import unittest
from pathlib import Path

from gamedata_candidate import (
    GamedataCandidateError,
    build_candidate,
    compare_gamedata_inventory,
    guard_candidate,
)
from gamedata_contract import GamedataContractError, discover_generator_modules
from gamesymbol_snapshot_lib.codec import build_snapshot_document, canonical_snapshot_bytes
from gamesymbol_snapshot_lib.config import load_contract


GENERATOR_SOURCE = """
from pathlib import Path

MODULE_NAME = "Fixture"
MODULE_ENABLED = True
OUTPUT_PATHS = ("payload/final.json",)
DOWNLOAD_SOURCES = ()


def update(yaml_data, func_lib_map, platforms, output_dir, alias_to_name_map, debug=False):
    path = Path(output_dir) / OUTPUT_PATHS[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"ok": true}\\n', encoding="utf-8")
    return 1, 0, [], []
"""


class GamedataCandidateFixture:
    gamever = "14170"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.config = root / "configs" / f"{self.gamever}.yaml"
        self.snapshot = root / "candidate.yaml"
        self.modules = root / "gamedata-generators"
        self.candidate_root = root / "candidate-root"
        self.session = root / "candidate-root" / "session.json"
        self.config.parent.mkdir(parents=True)
        self.config.write_text("modules: []\n", encoding="utf-8")
        contract = load_contract(self.config, self.gamever, root / "bin")
        document = build_snapshot_document(
            self.gamever,
            contract.config_sha256,
            {},
            last_publish_time="2026-01-02T03:04:05Z",
            binaries={},
        )
        self.snapshot.write_bytes(canonical_snapshot_bytes(document))
        generator = self.modules / "fixture"
        generator.mkdir(parents=True)
        (generator / "gamedata.py").write_text(GENERATOR_SOURCE, encoding="utf-8")

    def build(self) -> dict:
        return build_candidate(
            gamever=self.gamever,
            build_id="123-1",
            snapshot=self.snapshot,
            analysis_config=self.config,
            modules_dir=self.modules,
            candidate_root=self.candidate_root,
            session_path=self.session,
        )


class TestGamedataCandidate(unittest.TestCase):
    def test_inventory_comparison_is_order_independent_and_reports_path_level_diff(self) -> None:
        candidate_files = [
            {"path": "gamedata/14170/a.txt", "size": 1, "sha256": "a" * 64},
            {"path": "gamedata/14170/b.txt", "size": 2, "sha256": "b" * 64},
        ]
        expected_files = [
            {"path": "gamedata/14170/c.txt", "size": 3, "sha256": "c" * 64},
            {"path": "gamedata/14170/b.txt", "size": 2, "sha256": "d" * 64},
        ]

        diff = compare_gamedata_inventory(
            session={"gamever": "14170", "files": list(reversed(candidate_files))},
            expected_files=list(reversed(expected_files)),
        )

        self.assertEqual(("gamedata/14170/c.txt",), diff.added)
        self.assertEqual(("gamedata/14170/a.txt",), diff.missing)
        self.assertEqual(("gamedata/14170/b.txt",), tuple(item.path for item in diff.modified))
        self.assertFalse(diff.matches)
        self.assertTrue(
            compare_gamedata_inventory(
                session={"gamever": "14170", "files": candidate_files},
                expected_files=list(reversed(candidate_files)),
            ).matches
        )

    def test_inventory_comparison_rejects_duplicate_case_colliding_and_unsafe_paths(self) -> None:
        candidate = {"gamever": "14170", "files": [{"path": "gamedata/14170/a.txt", "size": 1, "sha256": "a" * 64}]}
        invalid_expected = (
            (
                "duplicate",
                [
                    {"path": "gamedata/14170/a.txt", "size": 1, "sha256": "a" * 64},
                    {"path": "gamedata/14170/a.txt", "size": 1, "sha256": "a" * 64},
                ],
            ),
            (
                "case-insensitive path collision",
                [
                    {"path": "gamedata/14170/A.txt", "size": 1, "sha256": "a" * 64},
                    {"path": "gamedata/14170/a.txt", "size": 1, "sha256": "a" * 64},
                ],
            ),
            ("unsafe relative path", [{"path": "gamedata/14170/../a.txt", "size": 1, "sha256": "a" * 64}]),
            ("unsafe relative path", [{"path": "gamedata/14170//a.txt", "size": 1, "sha256": "a" * 64}]),
        )

        for expected_error, files in invalid_expected:
            with self.subTest(expected_error=expected_error):
                with self.assertRaisesRegex(GamedataCandidateError, expected_error):
                    compare_gamedata_inventory(session=candidate, expected_files=files)

    def test_guard_rejects_candidate_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = GamedataCandidateFixture(Path(tmp))
            fixture.build()
            output = fixture.candidate_root / "gamedata" / fixture.gamever / "fixture" / "payload" / "final.json"
            output.write_text("tampered\n", encoding="utf-8")

            with self.assertRaisesRegex(GamedataCandidateError, "bytes changed"):
                guard_candidate(fixture.session)

    def test_contract_rejects_forbidden_and_undeclared_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            modules = Path(tmp) / "gamedata-generators"
            generator = modules / "fixture"
            generator.mkdir(parents=True)
            (generator / "gamedata.py").write_text(
                'MODULE_NAME="Fixture"\nOUTPUT_PATHS=("config.yaml",)\nDOWNLOAD_SOURCES=()\nupdate=lambda *_args: None\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(GamedataContractError, "forbidden extension"):
                discover_generator_modules(modules)

    def test_contract_validates_generator_api_v2_context_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            modules = Path(tmp) / "gamedata-generators"
            generator = modules / "fixture"
            generator.mkdir(parents=True)
            (generator / "gamedata.py").write_text(
                'MODULE_NAME="Fixture"\n'
                "GENERATOR_API_VERSION=2\n"
                'OUTPUT_PATHS=("payload.txt",)\n'
                "DOWNLOAD_SOURCES=()\n"
                "def update(*_args):\n    return 0, 0, [], []\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(GamedataContractError, "must accept a context keyword argument"):
                discover_generator_modules(modules)

            (generator / "gamedata.py").write_text(
                'MODULE_NAME="Fixture"\n'
                "GENERATOR_API_VERSION=3\n"
                'OUTPUT_PATHS=("payload.txt",)\n'
                "DOWNLOAD_SOURCES=()\n"
                "def update(*_args, context):\n    return 0, 0, [], []\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(GamedataContractError, "unsupported GENERATOR_API_VERSION"):
                discover_generator_modules(modules)


if __name__ == "__main__":
    unittest.main()
