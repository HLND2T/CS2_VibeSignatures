import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gamedata_candidate import (
    GamedataCandidateError,
    build_candidate,
    compare_gamedata_inventory,
    git_revision_gamedata_inventory,
    guard_candidate,
    main,
    publish_candidate,
    verify_tracked_gamedata,
)
from gamedata_contract import GamedataContractError, discover_generator_modules
from gamesymbol_snapshot_lib.codec import build_snapshot_document, canonical_snapshot_bytes
from gamesymbol_snapshot_lib.config import load_contract
from release_workflow_lib.hashing import sha256_bytes


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

    def init_repo(self) -> Path:
        repo = self.root / "repo"
        repo.mkdir()
        self.git(repo, "init", "-b", "main")
        self.git(repo, "config", "user.email", "tests@example.com")
        self.git(repo, "config", "user.name", "Tests")
        return repo

    def publish_and_commit(self, repo: Path) -> Path:
        publish_candidate(
            session_path=self.session,
            output_dir=repo / "gamedata" / self.gamever,
        )
        self.git(repo, "add", "gamedata")
        self.git(repo, "commit", "-m", "tracked gamedata")
        return repo / "gamedata" / self.gamever / "fixture" / "payload" / "final.json"

    @staticmethod
    def git(repo: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def verify_tracked(
        self,
        repo: Path,
        *,
        gamever: str | None = None,
        candidate: Path | None = None,
        analysis_config: Path | None = None,
    ) -> dict:
        return verify_tracked_gamedata(
            session_path=self.session,
            repo_root=repo,
            revision="HEAD",
            gamever=gamever or self.gamever,
            candidate=candidate or self.snapshot,
            analysis_config=analysis_config or self.config,
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

    def test_build_guard_and_publish_keep_versions_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = GamedataCandidateFixture(Path(tmp))
            session = fixture.build()
            workspace = fixture.root / "workspace"
            historical = workspace / "gamedata" / "14168" / "keep.json"
            historical.parent.mkdir(parents=True)
            historical.write_text("keep\n", encoding="utf-8")

            guard_candidate(fixture.session)
            publish_candidate(
                session_path=fixture.session,
                output_dir=workspace / "gamedata" / fixture.gamever,
            )

            self.assertEqual("gamedata/14170", session["gamedata_path"])
            self.assertEqual("keep\n", historical.read_text(encoding="utf-8"))
            self.assertEqual(
                '{"ok": true}\n',
                (workspace / "gamedata" / fixture.gamever / "fixture" / "payload" / "final.json").read_text(
                    encoding="utf-8"
                ),
            )
            published = workspace / "gamedata" / fixture.gamever / "fixture" / "payload" / "final.json"
            self.assertNotIn(b"\r", published.read_bytes())

    def test_guard_rejects_candidate_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = GamedataCandidateFixture(Path(tmp))
            fixture.build()
            output = fixture.candidate_root / "gamedata" / fixture.gamever / "fixture" / "payload" / "final.json"
            output.write_text("tampered\n", encoding="utf-8")

            with self.assertRaisesRegex(GamedataCandidateError, "bytes changed"):
                guard_candidate(fixture.session)

    def test_verify_tracked_reads_explicit_revision_instead_of_working_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = GamedataCandidateFixture(Path(tmp))
            fixture.build()
            repo = fixture.init_repo()
            tracked = fixture.publish_and_commit(repo)
            tracked.write_text("mutable working tree\n", encoding="utf-8")

            result = fixture.verify_tracked(repo)

            self.assertEqual("gamedata/14170", result["gamedata_path"])
            self.assertEqual(
                0,
                main(
                    [
                        "verify-tracked",
                        "-session",
                        str(fixture.session),
                        "-gamever",
                        fixture.gamever,
                        "-candidate",
                        str(fixture.snapshot),
                        "-configyaml",
                        str(fixture.config),
                        "-repo-root",
                        str(repo),
                        "-revision",
                        "HEAD",
                    ]
                ),
            )

    def test_verify_tracked_reports_added_missing_and_modified_paths(self) -> None:
        cases = ("added", "missing", "modified-size", "modified-sha256")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                fixture = GamedataCandidateFixture(Path(tmp))
                fixture.build()
                repo = fixture.init_repo()
                tracked = fixture.publish_and_commit(repo)
                if case == "added":
                    added = tracked.with_name("unexpected.txt")
                    added.write_text("unexpected\n", encoding="utf-8")
                    expected_error = "Added in PR head"
                elif case == "missing":
                    tracked.unlink()
                    tracked.with_name("unexpected.txt").write_text("unexpected\n", encoding="utf-8")
                    expected_error = "Missing from PR head"
                elif case == "modified-size":
                    tracked.write_text("different length\n", encoding="utf-8")
                    expected_error = "Modified"
                else:
                    original = tracked.read_bytes()
                    tracked.write_bytes(b"x" * len(original))
                    expected_error = "Modified"
                fixture.git(repo, "add", "-A", "gamedata")
                fixture.git(repo, "commit", "-m", case)

                with self.assertRaisesRegex(GamedataCandidateError, expected_error):
                    fixture.verify_tracked(repo)

    def test_verify_tracked_rejects_session_identity_drift(self) -> None:
        cases = ("gamever", "invalid-gamever", "candidate", "head-config", "session-candidate", "generator")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                fixture = GamedataCandidateFixture(Path(tmp))
                fixture.build()
                repo = fixture.init_repo()
                fixture.publish_and_commit(repo)
                gamever = fixture.gamever
                candidate = fixture.snapshot
                analysis_config = fixture.config
                expected_error = "release candidate"
                if case == "gamever":
                    gamever = "14171"
                elif case == "invalid-gamever":
                    gamever = "../14170"
                    expected_error = "invalid GAMEVER"
                elif case == "candidate":
                    candidate = fixture.root / "other-candidate.yaml"
                    candidate.write_bytes(fixture.snapshot.read_bytes() + b"\n")
                elif case == "head-config":
                    analysis_config = fixture.root / "other-config.yaml"
                    analysis_config.write_text("modules: [changed]\n", encoding="utf-8")
                    expected_error = "does not match the analysis config"
                elif case == "session-candidate":
                    fixture.snapshot.write_bytes(fixture.snapshot.read_bytes() + b"\n")
                    expected_error = "symbol candidate changed"
                else:
                    generator = fixture.modules / "fixture" / "gamedata.py"
                    generator.write_text(generator.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
                    expected_error = "generator contract changed"

                with self.assertRaisesRegex(GamedataCandidateError, expected_error):
                    fixture.verify_tracked(
                        repo,
                        gamever=gamever,
                        candidate=candidate,
                        analysis_config=analysis_config,
                    )

    def test_git_revision_inventory_rejects_unsupported_modes_and_unsafe_paths(self) -> None:
        object_id = b"a" * 40
        cases = {
            "unsupported Git tree entry": b"120000 blob " + object_id + b"\tgamedata/14170/link\0",
            "non-blob Git tree entry": b"160000 commit " + object_id + b"\tgamedata/14170/submodule\0",
            "non-empty POSIX relative path": b"100644 blob " + object_id + b"\tgamedata/14170/bad\\name.txt\0",
            "unsafe relative path": b"100644 blob " + object_id + b"\tgamedata/14170/../escape.txt\0",
            "outside exact root": b"100644 blob " + object_id + b"\t/gamedata/14170/file.txt\0",
            "case-insensitive path collision": (
                b"100644 blob " + object_id + b"\tgamedata/14170/A.txt\0"
                b"100644 blob " + object_id + b"\tgamedata/14170/a.txt\0"
            ),
        }
        commit = b"1" * 40 + b"\n"

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for expected_error, tree in cases.items():
                with self.subTest(expected_error=expected_error):
                    with patch("gamedata_candidate._git_bytes", side_effect=[commit, commit, tree]):
                        with self.assertRaisesRegex(GamedataCandidateError, expected_error):
                            git_revision_gamedata_inventory(repo, "HEAD", "14170")

    def test_git_revision_inventory_requires_root_and_hashes_raw_blob_bytes(self) -> None:
        commit = b"1" * 40 + b"\n"
        object_id = b"a" * 40
        tree = b"100644 blob " + object_id + b"\tgamedata/14170/file.txt\0"
        blob = b"line one\r\nline two\r\n"

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            with patch("gamedata_candidate._git_bytes", side_effect=[commit, commit, b""]):
                with self.assertRaisesRegex(GamedataCandidateError, "missing or empty"):
                    git_revision_gamedata_inventory(repo, "HEAD", "14170")
            with patch("gamedata_candidate._git_bytes", side_effect=[commit, commit, tree, blob]):
                inventory = git_revision_gamedata_inventory(repo, "HEAD", "14170")

        self.assertEqual(
            [{"path": "gamedata/14170/file.txt", "size": len(blob), "sha256": sha256_bytes(blob)}],
            inventory,
        )

    def test_git_revision_inventory_requires_current_checkout_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = GamedataCandidateFixture(Path(tmp))
            fixture.build()
            repo = fixture.init_repo()
            fixture.publish_and_commit(repo)
            previous = fixture.git(repo, "rev-parse", "HEAD")
            marker = repo / "marker.txt"
            marker.write_text("advance checkout\n", encoding="utf-8")
            fixture.git(repo, "add", "marker.txt")
            fixture.git(repo, "commit", "-m", "advance checkout")

            with self.assertRaisesRegex(GamedataCandidateError, "explicit HEAD or a full commit SHA"):
                git_revision_gamedata_inventory(repo, "main", fixture.gamever)
            with self.assertRaisesRegex(GamedataCandidateError, "does not match the current checkout"):
                git_revision_gamedata_inventory(repo, previous, fixture.gamever)

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
