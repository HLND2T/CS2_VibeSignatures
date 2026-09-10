from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

import pages_deployment_sha as pds

SOURCE_SHA = "a" * 40


def _git(cwd: Path, *arguments: str) -> str:
    result = subprocess.run(["git", *arguments], cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _commit(repository: Path, relative_path: str, content: str, message: str) -> str:
    target = repository / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="\n")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-q", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _repository_with_main_and_unmerged_commits(root: Path) -> dict[str, object]:
    repository = root / "repository"
    repository.mkdir()
    _git(root, "init", "-q", str(repository))
    _git(repository, "config", "user.name", "test")
    _git(repository, "config", "user.email", "test@example.invalid")
    source_sha = _commit(repository, "README.md", "data\n", "source")
    default_branch = _git(repository, "rev-parse", "--abbrev-ref", "HEAD")
    deployment_sha = _commit(repository, "code.txt", "deployment\n", "deployment")
    _git(repository, "checkout", "-q", "-b", "unmerged", source_sha)
    unmerged_sha = _commit(repository, "side.txt", "side\n", "unmerged")
    _git(repository, "checkout", "-q", default_branch)
    return {
        "repository": repository,
        "source_sha": source_sha,
        "deployment_sha": deployment_sha,
        "unmerged_sha": unmerged_sha,
    }


class ResolveDeploymentShaTests(unittest.TestCase):
    def test_defaults_to_the_release_source_commit(self) -> None:
        for requested in (None, "", "   "):
            with self.subTest(requested=requested):
                self.assertEqual((SOURCE_SHA, False), pds.resolve_deployment_sha(SOURCE_SHA, requested))

    def test_accepts_an_explicit_uppercase_commit(self) -> None:
        requested = "B" * 40
        self.assertEqual((requested.lower(), True), pds.resolve_deployment_sha(SOURCE_SHA, requested))

    def test_rejects_invalid_commits(self) -> None:
        with self.assertRaises(pds.PagesDeploymentShaError):
            pds.resolve_deployment_sha("not-a-sha", "")
        with self.assertRaises(pds.PagesDeploymentShaError):
            pds.resolve_deployment_sha(SOURCE_SHA, "b" * 39)
        with self.assertRaises(pds.PagesDeploymentShaError):
            pds.resolve_deployment_sha(SOURCE_SHA, "z" * 40)


class VerifyCommitOnMainTests(unittest.TestCase):
    def test_accepts_main_history_and_rejects_unmerged_or_unknown_commits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository_state = _repository_with_main_and_unmerged_commits(Path(temporary))
            repository = repository_state["repository"]
            source_sha = repository_state["source_sha"]
            deployment_sha = repository_state["deployment_sha"]
            unmerged_sha = repository_state["unmerged_sha"]

            pds.verify_commit_on_main(repository, source_sha)
            pds.verify_commit_on_main(repository, deployment_sha)
            self.assertNotEqual(source_sha, deployment_sha)

            with self.assertRaises(pds.PagesDeploymentShaError):
                pds.verify_commit_on_main(repository, unmerged_sha)
            with self.assertRaises(pds.PagesDeploymentShaError):
                pds.verify_commit_on_main(repository, "f" * 40)

    def test_rejects_a_directory_that_is_not_a_git_work_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(pds.PagesDeploymentShaError):
                pds.verify_commit_on_main(Path(temporary), SOURCE_SHA)


class DeploymentShaCliTests(unittest.TestCase):
    def test_records_an_override_for_main_history_and_rejects_an_unmerged_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository_state = _repository_with_main_and_unmerged_commits(root)
            repository = repository_state["repository"]
            source_sha = repository_state["source_sha"]
            deployment_sha = repository_state["deployment_sha"]
            unmerged_sha = repository_state["unmerged_sha"]
            output_path = root / "github-output.txt"

            with contextlib.redirect_stdout(io.StringIO()):
                accepted = pds.main(
                    [
                        "--source-sha",
                        source_sha,
                        "--requested-sha",
                        deployment_sha,
                        "--repository-root",
                        str(repository),
                        "--github-output",
                        str(output_path),
                    ]
                )
            self.assertEqual(0, accepted)
            self.assertEqual(
                f"deployment_sha={deployment_sha}\ndeployment_override=true\n",
                output_path.read_text(encoding="utf-8"),
            )

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rejected = pds.main(
                    [
                        "--source-sha",
                        source_sha,
                        "--requested-sha",
                        unmerged_sha,
                        "--repository-root",
                        str(repository),
                        "--github-output",
                        str(output_path),
                    ]
                )
            self.assertEqual(1, rejected)
            self.assertEqual(
                f"deployment_sha={deployment_sha}\ndeployment_override=true\n",
                output_path.read_text(encoding="utf-8"),
            )

    def test_defaults_to_the_source_commit_without_a_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "github-output.txt"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, pds.main(["--source-sha", SOURCE_SHA, "--github-output", str(output_path)]))
            self.assertEqual(
                f"deployment_sha={SOURCE_SHA}\ndeployment_override=false\n",
                output_path.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
