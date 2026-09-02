from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import trusted_pr_context as tpc


class TrustedPrContextTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stderr or f"git {' '.join(arguments)} failed")
        return result.stdout.strip()

    def _repository(self, root: Path) -> tuple[str, str, str, bytes]:
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.email", "test@example.com")
        self._git(root, "config", "user.name", "Test")
        policy = (
            b"schema_version: 1\nmode: source-owned\nartifact_root: bin_artifacts\n"
            b"artifact_contract_schema_version: 1\n"
        )
        required = {path: f"trusted base {path}\n".encode() for path in tpc.TRUSTED_FILE_PATHS}
        required[tpc.POLICY_REPO_PATH] = policy
        for relative, payload in required.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self._git(root, "add", *required)
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", "feature")
        (root / tpc.POLICY_REPO_PATH).write_text(
            "schema_version: 1\nmode: legacy\nartifact_root: bin_artifacts\nartifact_contract_schema_version: 99\n",
            encoding="utf-8",
        )
        (root / "feature.txt").write_text("head\n", encoding="utf-8")
        self._git(root, "add", tpc.POLICY_REPO_PATH, "feature.txt")
        self._git(root, "commit", "-m", "head")
        head_sha = self._git(root, "rev-parse", "HEAD")
        self._git(root, "switch", "main")
        self._git(root, "merge", "--no-ff", "feature", "-m", "prospective merge")
        merge_sha = self._git(root, "rev-parse", "HEAD")
        return base_sha, head_sha, merge_sha, policy

    def test_context_binds_exact_merge_tree_and_reads_policy_from_base(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_sha, head_sha, merge_sha, base_policy = self._repository(root)

            context = tpc.build_trusted_pr_context(
                repo_root=root,
                base_ref=base_sha,
                head_ref=head_sha,
                merge_ref=merge_sha,
            )

            self.assertEqual(base_sha, context["base_sha"])
            self.assertEqual(head_sha, context["head_sha"])
            self.assertEqual(merge_sha, context["merge_sha"])
            self.assertEqual("pull_request", context["event_kind"])
            self.assertEqual(self._git(root, "rev-parse", f"{merge_sha}^{{tree}}"), context["merge_tree_sha"])
            self.assertEqual("source-owned", context["artifact_policy"]["mode"])
            self.assertEqual(tpc._sha256(base_policy), context["artifact_policy"]["sha256"])
            self.assertEqual(context, tpc.validate_trusted_pr_context(context))

    def test_context_rejects_merge_with_wrong_bound_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_sha, _head_sha, merge_sha, _policy = self._repository(root)

            with self.assertRaisesRegex(tpc.TrustedPrContextError, "prospective merge parents"):
                tpc.build_trusted_pr_context(
                    repo_root=root,
                    base_ref=base_sha,
                    head_ref=base_sha,
                    merge_ref=merge_sha,
                )

    def test_context_digest_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_sha, head_sha, merge_sha, _policy = self._repository(root)
            context = tpc.build_trusted_pr_context(
                repo_root=root,
                base_ref=base_sha,
                head_ref=head_sha,
                merge_ref=merge_sha,
            )
            path = root / "context.json"
            path.write_text(json.dumps(context), encoding="utf-8")
            context["merge_tree_sha"] = "0" * 40
            path.write_text(json.dumps(context), encoding="utf-8")

            with self.assertRaisesRegex(tpc.TrustedPrContextError, "digest mismatch"):
                tpc.load_trusted_pr_context(path)

    def test_merge_group_context_binds_exact_queue_tree_and_rejects_non_descendant_base(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_sha, _head_sha, merge_sha, _policy = self._repository(root)

            context = tpc.build_trusted_merge_group_context(
                repo_root=root,
                base_ref=base_sha,
                merge_ref=merge_sha,
            )

            self.assertEqual("merge_group", context["event_kind"])
            self.assertEqual(merge_sha, context["head_sha"])
            self.assertEqual(merge_sha, context["merge_sha"])
            self.assertEqual(self._git(root, "rev-parse", f"{merge_sha}^{{tree}}"), context["merge_tree_sha"])

            (root / "after.txt").write_text("after\n", encoding="utf-8")
            self._git(root, "add", "after.txt")
            self._git(root, "commit", "-m", "after queue head")
            later_sha = self._git(root, "rev-parse", "HEAD")
            with self.assertRaisesRegex(tpc.TrustedPrContextError, "must descend"):
                tpc.build_trusted_merge_group_context(
                    repo_root=root,
                    base_ref=later_sha,
                    merge_ref=merge_sha,
                )

    def test_policy_rejects_unknown_keys_and_noncanonical_root(self) -> None:
        with self.assertRaises(tpc.TrustedPrContextError):
            tpc.parse_source_artifact_policy(
                b"schema_version: 1\nmode: legacy\nartifact_root: bin\nartifact_contract_schema_version: 1\n"
            )
        with self.assertRaises(tpc.TrustedPrContextError):
            tpc.parse_source_artifact_policy(
                b"schema_version: 1\nmode: legacy\nartifact_root: bin_artifacts\n"
                b"artifact_contract_schema_version: 1\nextra: true\n"
            )
        self.assertEqual(
            "legacy",
            tpc.parse_source_artifact_policy(
                b"schema_version: 1\nmode: legacy\nartifact_root: bin_artifacts\nartifact_contract_schema_version: 1\n"
            ).mode,
        )
        self.assertEqual(
            "bridge",
            tpc.parse_source_artifact_policy(
                b"schema_version: 1\nmode: bridge\nartifact_root: bin_artifacts\nartifact_contract_schema_version: 1\n"
            ).mode,
        )


if __name__ == "__main__":
    unittest.main()
