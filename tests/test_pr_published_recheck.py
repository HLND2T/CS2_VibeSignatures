import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import gamedata_contract
from pr_published_recheck import (
    BOT_EMAIL,
    BOT_NAME,
    DispatchContext,
    PublishedRecheckError,
    PublicationProvenance,
    canonical_commit_message,
    classify_pull_request_publication,
    validate_dispatch_inputs,
    verify_dispatch,
    verify_dispatch_stable,
    verify_existing_publication,
    verify_published_commit,
    verify_worktree_publication,
)


def _git(repo: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **(env or {})},
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


class PublishedRecheckFixture:
    def __init__(self, root: Path):
        self.root = root
        _git(root, "init")
        _git(root, "config", "core.autocrlf", "false")
        _git(root, "config", "user.name", "Developer")
        _git(root, "config", "user.email", "developer@example.com")
        (root / "gamesymbols").mkdir()
        (root / "gamedata/14176/module").mkdir(parents=True)
        (root / "gamesymbols/14176.yaml").write_text("snapshot: base\n", encoding="utf-8")
        (root / "gamedata/14176/module/data.txt").write_text("base\n", encoding="utf-8")
        _git(root, "add", "--", "gamesymbols/14176.yaml", "gamedata/14176")
        _git(root, "commit", "-m", "feat: source change")
        self.validated_head_sha = _git(root, "rev-parse", "HEAD")
        self.validated_base_sha = "b" * 40

    def publish(
        self,
        *,
        extra_path: bool = False,
        bot_identity: bool = True,
        message: str | None = None,
        declared_snapshot_sha256: str | None = None,
        declared_gamedata_manifest_sha256: str | None = None,
    ) -> None:
        (self.root / "gamesymbols/14176.yaml").write_text("snapshot: published\n", encoding="utf-8")
        (self.root / "gamedata/14176/module/data.txt").write_text("published\n", encoding="utf-8")
        paths = ["gamesymbols/14176.yaml", "gamedata/14176"]
        if extra_path:
            (self.root / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
            paths.append("unexpected.txt")
        _git(self.root, "add", "--", *paths)
        snapshot_sha256 = self._sha256(self.root / "gamesymbols/14176.yaml")
        gamedata_manifest_sha256 = self._manifest_sha256()
        declared_snapshot_sha256 = declared_snapshot_sha256 or snapshot_sha256
        declared_gamedata_manifest_sha256 = declared_gamedata_manifest_sha256 or gamedata_manifest_sha256
        placeholder = PublicationProvenance(
            expected_head_sha="a" * 40,
            validated_head_sha=self.validated_head_sha,
            validated_base_sha=self.validated_base_sha,
            gamever="14176",
            snapshot_sha256=declared_snapshot_sha256,
            gamedata_manifest_sha256=declared_gamedata_manifest_sha256,
        )
        commit_env = {
            "GIT_AUTHOR_NAME": BOT_NAME if bot_identity else "Impostor",
            "GIT_AUTHOR_EMAIL": BOT_EMAIL if bot_identity else "impostor@example.com",
            "GIT_COMMITTER_NAME": BOT_NAME if bot_identity else "Impostor",
            "GIT_COMMITTER_EMAIL": BOT_EMAIL if bot_identity else "impostor@example.com",
        }
        message_path = self.root / "commit-message.txt"
        message_path.write_text(message or canonical_commit_message(placeholder), encoding="utf-8")
        _git(self.root, "commit", "-F", str(message_path), env=commit_env)
        message_path.unlink()
        self.expected_head_sha = _git(self.root, "rev-parse", "HEAD")
        self.provenance = PublicationProvenance(
            expected_head_sha=self.expected_head_sha,
            validated_head_sha=self.validated_head_sha,
            validated_base_sha=self.validated_base_sha,
            gamever="14176",
            snapshot_sha256=declared_snapshot_sha256,
            gamedata_manifest_sha256=declared_gamedata_manifest_sha256,
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        import hashlib

        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _manifest_sha256(self) -> str:
        import hashlib
        import json

        path = self.root / "gamedata/14176/module/data.txt"
        data = path.read_bytes()
        inventory = [
            {
                "path": "gamedata/14176/module/data.txt",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        ]
        canonical = (
            json.dumps({"files": inventory}, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode()
        return hashlib.sha256(canonical).hexdigest()

    def inputs(self):
        return validate_dispatch_inputs(
            {
                "validation_mode": "published-recheck",
                "pr_number": "42",
                "expected_head_sha": self.provenance.expected_head_sha,
                "validated_head_sha": self.provenance.validated_head_sha,
                "validated_base_sha": self.provenance.validated_base_sha,
                "gamever": self.provenance.gamever,
                "snapshot_sha256": self.provenance.snapshot_sha256,
                "gamedata_manifest_sha256": self.provenance.gamedata_manifest_sha256,
            }
        )

    def context(self):
        return DispatchContext(
            repository="HLND2T/CS2_VibeSignatures",
            github_sha=self.expected_head_sha,
            ref_name="dev-example",
            actor=BOT_NAME,
            sender=BOT_NAME,
        )

    def pull_request(self, *, base_sha: str | None = None, head_sha: str | None = None):
        return {
            "number": 42,
            "state": "open",
            "title": "feat: example",
            "user": {"login": "developer"},
            "head": {
                "sha": head_sha or self.expected_head_sha,
                "ref": "dev-example",
                "repo": {"full_name": "HLND2T/CS2_VibeSignatures"},
            },
            "base": {"sha": base_sha or self.validated_base_sha},
        }


class TestPrPublishedRecheck(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.fixture = PublishedRecheckFixture(self.repo)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_bot_commit_is_reusable_and_repeatable(self) -> None:
        self.fixture.publish()
        first = verify_dispatch(
            inputs=self.fixture.inputs(),
            context=self.fixture.context(),
            pull_request=self.fixture.pull_request(),
            repo_root=self.repo,
        )
        second = verify_dispatch(
            inputs=self.fixture.inputs(),
            context=self.fixture.context(),
            pull_request=self.fixture.pull_request(),
            repo_root=self.repo,
        )
        self.assertEqual("published-recheck", first.validation_path)
        self.assertEqual(first, second)

    def test_valid_bot_commit_classifies_pull_request_as_published_recheck(self) -> None:
        self.fixture.publish()

        provenance = classify_pull_request_publication(
            repo_root=self.repo,
            expected_head_sha=self.fixture.expected_head_sha,
            validated_base_sha=self.fixture.validated_base_sha,
        )

        self.assertEqual(self.fixture.provenance, provenance)

    def test_publication_classification_rejects_base_drift(self) -> None:
        self.fixture.publish()

        provenance = classify_pull_request_publication(
            repo_root=self.repo,
            expected_head_sha=self.fixture.expected_head_sha,
            validated_base_sha="d" * 40,
        )

        self.assertIsNone(provenance)

    def test_existing_bot_commit_reuses_its_original_validated_digests(self) -> None:
        self.fixture.publish()
        rebuilt = PublicationProvenance(
            **{
                **self.fixture.provenance.__dict__,
                "snapshot_sha256": "1" * 64,
                "gamedata_manifest_sha256": "2" * 64,
            }
        )
        verified = verify_existing_publication(self.repo, rebuilt)
        self.assertEqual(self.fixture.provenance, verified)

    def test_forged_author_is_rejected(self) -> None:
        self.fixture.publish(bot_identity=False)
        with self.assertRaisesRegex(PublishedRecheckError, "author and committer"):
            verify_published_commit(self.repo, self.fixture.provenance)

    def test_forged_message_is_rejected(self) -> None:
        self.fixture.publish(message="chore(gamesymbols): publish 14176 snapshot\n\nValidated-Head-SHA: forged\n")
        with self.assertRaisesRegex(PublishedRecheckError, "trailers"):
            verify_published_commit(self.repo, self.fixture.provenance)

    def test_wrong_parent_is_rejected(self) -> None:
        self.fixture.publish()
        wrong = PublicationProvenance(**{**self.fixture.provenance.__dict__, "validated_head_sha": "c" * 40})
        with self.assertRaisesRegex(PublishedRecheckError, "exactly validated_head_sha"):
            verify_published_commit(self.repo, wrong)

    def test_base_drift_selects_full_validation(self) -> None:
        self.fixture.publish()
        result = verify_dispatch(
            inputs=self.fixture.inputs(),
            context=self.fixture.context(),
            pull_request=self.fixture.pull_request(base_sha="d" * 40),
            repo_root=self.repo,
        )
        self.assertEqual("full", result.validation_path)
        self.assertEqual("d" * 40, result.base_sha)

    def test_extra_path_is_rejected(self) -> None:
        self.fixture.publish(extra_path=True)
        with self.assertRaisesRegex(PublishedRecheckError, "disallowed paths"):
            verify_published_commit(self.repo, self.fixture.provenance)

    def test_worktree_gamedata_manifest_matches_candidate_for_case_mixed_tree(self) -> None:
        # Regression: the worktree inventory must be sorted by the canonical
        # POSIX string path (case-sensitive), matching
        # gamedata_contract.prefixed_output_inventory. Sorting raw Path objects
        # is case-insensitive on Windows and reorders case-mixed trees such as
        # gamedata/14176, producing a different manifest digest.
        root = self.repo
        gamedata_root = root / "gamedata" / "14176"
        files = {
            "CS2FOW/gamedata/cs2fow.games.txt": "fow\n",
            "CounterStrikeSharp/config/data.json": "css\n",
            "modsharp-public/.asset/core.games.jsonc": "core\n",
            "modsharp-public/.asset/EntityEnhancement.games.jsonc": "entity\n",
        }
        for relative, content in files.items():
            target = gamedata_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        candidate = root / "gamesymbols" / "14176.yaml"
        candidate.write_text("snapshot: published\n", encoding="utf-8")
        inventory = gamedata_contract.prefixed_output_inventory(gamedata_root, "14176")
        manifest = gamedata_contract.gamedata_manifest_sha256(inventory)
        # The session file must live outside the repo so it is not flagged as
        # a disallowed changed path by verify_worktree_publication.
        with tempfile.TemporaryDirectory() as session_dir:
            session = Path(session_dir) / "gamedata.session.json"
            session.write_text(
                json.dumps(
                    {
                        "gamever": "14176",
                        "candidate_sha256": self._sha256(candidate),
                        "gamedata_manifest_sha256": manifest,
                    }
                ),
                encoding="utf-8",
            )

            result = verify_worktree_publication(
                repo_root=root,
                gamever="14176",
                candidate=candidate,
                gamedata_session=session,
            )
            self.assertEqual(manifest, result["gamedata_manifest_sha256"])

    def test_worktree_gamedata_rejects_path_sorted_manifest(self) -> None:
        # Locking the regression: a manifest computed from the case-insensitive
        # Path sort order must be rejected by verify_worktree_publication.
        root = self.repo
        gamedata_root = root / "gamedata" / "14176"
        files = {
            "CS2FOW/gamedata/cs2fow.games.txt": "fow\n",
            "CounterStrikeSharp/config/data.json": "css\n",
        }
        for relative, content in files.items():
            target = gamedata_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        candidate = root / "gamesymbols" / "14176.yaml"
        candidate.write_text("snapshot: published\n", encoding="utf-8")
        wrong_inventory = []
        for path in sorted(gamedata_root.rglob("*")):
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                wrong_inventory.append(
                    {
                        "path": relative,
                        "size": path.stat().st_size,
                        "sha256": self._sha256(path),
                    }
                )
        wrong_manifest = gamedata_contract.gamedata_manifest_sha256(wrong_inventory)
        # The session file must live outside the repo so it is not flagged as
        # a disallowed changed path by verify_worktree_publication.
        with tempfile.TemporaryDirectory() as session_dir:
            session = Path(session_dir) / "gamedata.session.json"
            session.write_text(
                json.dumps(
                    {
                        "gamever": "14176",
                        "candidate_sha256": self._sha256(candidate),
                        "gamedata_manifest_sha256": wrong_manifest,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PublishedRecheckError, "published gamedata differs"):
                verify_worktree_publication(
                    repo_root=root,
                    gamever="14176",
                    candidate=candidate,
                    gamedata_session=session,
                )

    def _sha256(self, path: Path) -> str:
        import hashlib

        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_snapshot_digest_mismatch_is_rejected(self) -> None:
        self.fixture.publish(declared_snapshot_sha256="0" * 64)
        with self.assertRaisesRegex(PublishedRecheckError, "snapshot SHA-256"):
            verify_published_commit(self.repo, self.fixture.provenance)

    def test_gamedata_manifest_mismatch_is_rejected(self) -> None:
        self.fixture.publish(declared_gamedata_manifest_sha256="0" * 64)
        with self.assertRaisesRegex(PublishedRecheckError, "gamedata manifest"):
            verify_published_commit(self.repo, self.fixture.provenance)

    def test_pr_head_advance_is_rejected(self) -> None:
        self.fixture.publish()
        with self.assertRaisesRegex(PublishedRecheckError, "head advanced"):
            verify_dispatch(
                inputs=self.fixture.inputs(),
                context=self.fixture.context(),
                pull_request=self.fixture.pull_request(head_sha="e" * 40),
                repo_root=self.repo,
            )

    def test_pr_head_advance_between_api_checks_is_rejected(self) -> None:
        self.fixture.publish()
        with self.assertRaisesRegex(PublishedRecheckError, "head advanced"):
            verify_dispatch_stable(
                inputs=self.fixture.inputs(),
                context=self.fixture.context(),
                initial_pull_request=self.fixture.pull_request(),
                confirmed_pull_request=self.fixture.pull_request(head_sha="e" * 40),
                repo_root=self.repo,
            )

    def test_untrusted_dispatch_actor_is_rejected(self) -> None:
        self.fixture.publish()
        context = DispatchContext(**{**self.fixture.context().__dict__, "actor": "developer"})
        with self.assertRaisesRegex(PublishedRecheckError, "github-actions"):
            verify_dispatch(
                inputs=self.fixture.inputs(),
                context=context,
                pull_request=self.fixture.pull_request(),
                repo_root=self.repo,
            )


if __name__ == "__main__":
    unittest.main()
