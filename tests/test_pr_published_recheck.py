import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from pr_published_recheck import (
    BOT_EMAIL,
    BOT_NAME,
    DispatchContext,
    PublishedRecheckError,
    PublicationProvenance,
    canonical_commit_message,
    validate_dispatch_inputs,
    verify_dispatch,
    verify_dispatch_stable,
    verify_existing_publication,
    verify_published_commit,
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
