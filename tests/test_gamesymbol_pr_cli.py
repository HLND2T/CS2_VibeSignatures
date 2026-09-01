import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from unittest.mock import patch

from gamesymbol_snapshot_lib.errors import SnapshotMismatchError
from gamesymbol_snapshot_lib.model import SnapshotContext
from gamesymbol_snapshot_lib.model import ChangedPath
from gamesymbol_snapshot_lib.pr_cli import _load_head_context, _parse_changed_paths, _revision_sources, _run


class TestGitChangeCollection(unittest.TestCase):
    def test_stale_head_config_uses_trusted_base_payload_for_invalidation(self) -> None:
        base = SnapshotContext({"files": {"server/Stable.windows.yaml": {}}}, b"base", "base-contract")
        head_contract = object()

        with (
            patch(
                "gamesymbol_snapshot_lib.pr_cli.load_snapshot_context",
                side_effect=SnapshotMismatchError("digest mismatch", reason="config_digest_mismatch"),
            ),
            patch("gamesymbol_snapshot_lib.pr_cli.load_contract", return_value=head_contract) as load_contract,
        ):
            head = _load_head_context(
                "head.yaml",
                "head-config.yaml",
                "14172",
                "bin",
                "bin_artifacts",
                base,
            )

        self.assertEqual(base.document, head.document)
        self.assertEqual(base.raw_bytes, head.raw_bytes)
        self.assertIs(head_contract, head.contract)
        load_contract.assert_called_once_with(
            "head-config.yaml",
            "14172",
            "bin",
            2,
            artifactdir="bin_artifacts",
        )

    def test_head_snapshot_failures_other_than_config_digest_mismatch_propagate(self) -> None:
        base = SnapshotContext({}, b"base", "base-contract")
        failure = SnapshotMismatchError("snapshot is not canonical", reason="noncanonical_snapshot")

        with patch("gamesymbol_snapshot_lib.pr_cli.load_snapshot_context", side_effect=failure):
            with self.assertRaisesRegex(SnapshotMismatchError, "not canonical"):
                _load_head_context(
                    "head.yaml",
                    "head-config.yaml",
                    "14172",
                    "bin",
                    "bin_artifacts",
                    base,
                )

    def test_parse_name_status_preserves_status_rename_sides_and_spaces(self) -> None:

        raw = (
            b"A\0new file.py\0"
            b"M\0modified.py\0"
            b"D\0deleted.py\0"
            b"R087\0old name.yaml\0new name.yaml\0"
            b"C100\0source.py\0copied file.py\0"
        )

        changes = _parse_changed_paths(raw)

        self.assertEqual(
            [
                ("A", None, "new file.py"),
                ("M", "modified.py", "modified.py"),
                ("D", "deleted.py", None),
                ("R", "old name.yaml", "new name.yaml"),
                ("C", "source.py", "copied file.py"),
            ],
            [(change.status, change.old_path, change.new_path) for change in changes],
        )

    def test_revision_sources_reads_base_and_head_without_checkout_mutation(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            script = root / "ida_preprocessor_scripts" / "find-target.py"
            script.parent.mkdir()
            script.write_bytes(b"VALUE = 1\n")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base_ref = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()
            script.write_bytes(b"VALUE = 2\n")
            subprocess.run(["git", "commit", "-qam", "head"], cwd=root, check=True)
            head_ref = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()

            native_run = subprocess.run
            with patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run", wraps=native_run) as run:
                base_sources = _revision_sources(base_ref, root)
                head_sources = _revision_sources(head_ref, root)
            archive_commands = [item.args[0] for item in run.call_args_list]
            current_ref = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()

        path = "ida_preprocessor_scripts/find-target.py"
        self.assertEqual("VALUE = 1\n", base_sources[path])
        self.assertEqual("VALUE = 2\n", head_sources[path])
        self.assertEqual(head_ref, current_ref)
        self.assertEqual(
            [
                ["git", "archive", "--format=tar", base_ref, "--", "ida_preprocessor_scripts/*.py"],
                ["git", "archive", "--format=tar", head_ref, "--", "ida_preprocessor_scripts/*.py"],
            ],
            archive_commands,
        )

    def test_run_loads_only_required_revision_source_sides(self) -> None:
        reference = "ida_preprocessor_scripts/references/server/Input.windows.yaml"
        preprocessor = "ida_preprocessor_scripts/find-target.py"
        cases = (
            ([ChangedPath("M", "README.md", "README.md")], []),
            ([ChangedPath("D", reference, None)], ["BASE"]),
            ([ChangedPath("A", None, preprocessor)], ["HEAD"]),
            ([ChangedPath("C", reference, "ida_preprocessor_scripts/references/server/Copy.windows.yaml")], ["HEAD"]),
            ([ChangedPath("R", preprocessor, "ida_preprocessor_scripts/find-renamed.py")], ["BASE", "HEAD"]),
        )
        base = SnapshotContext({"files": {}}, b"base", "base-contract")
        head = SnapshotContext({"files": {}}, b"head", "head-contract")
        plan = SimpleNamespace(paths=frozenset(), reasons=())

        for changes, expected_refs in cases:
            args = SimpleNamespace(
                gamever="14175",
                bindir="bin",
                artifactdir="bin_artifacts",
                baseconfigyaml="base-config.yaml",
                basesnapshot="base-snapshot.yaml",
                headconfigyaml="head-config.yaml",
                headsnapshot="head-snapshot.yaml",
                baseref="BASE",
                headref="HEAD",
            )
            with (
                patch("gamesymbol_snapshot_lib.pr_cli.resolve_analysis_config", return_value="head-config.yaml"),
                patch("gamesymbol_snapshot_lib.pr_cli.load_snapshot_context", side_effect=[base, head]),
                patch("gamesymbol_snapshot_lib.pr_cli._changed_paths", return_value=changes),
                patch(
                    "gamesymbol_snapshot_lib.pr_cli._revision_sources",
                    side_effect=lambda ref, _root: {ref: ref},
                ) as revision_sources,
                patch("gamesymbol_snapshot_lib.pr_cli.build_invalidation_plan", return_value=plan) as build_plan,
                patch("gamesymbol_snapshot_lib.pr_cli._delete_paths", return_value=0),
            ):
                _run(args)

            self.assertEqual(expected_refs, [item.args[0] for item in revision_sources.call_args_list])
            self.assertEqual(
                {ref: ref for ref in expected_refs if ref == "BASE"}, build_plan.call_args.kwargs["base_sources"]
            )
            self.assertEqual(
                {ref: ref for ref in expected_refs if ref == "HEAD"}, build_plan.call_args.kwargs["head_sources"]
            )


if __name__ == "__main__":
    unittest.main()
