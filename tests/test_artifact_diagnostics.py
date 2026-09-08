from __future__ import annotations

import tempfile
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import artifact_diagnostics as diagnostics
from artifact_diagnostics import content_diff, read_artifact_bytes


class ArtifactDiagnosticsTests(unittest.TestCase):
    def test_detail_limit_and_raw_byte_fallbacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "1/server"
            module.mkdir(parents=True)
            expected = {}
            for index, actual in enumerate(
                (b"\xff", b"same\r\n", b"\0x", b"a" * (1024 * 1024 + 1), b"new\n", b"last\n")
            ):
                name = f"{index}.yaml"
                (module / name).write_bytes(actual)
                expected[f"bin_artifacts/1/server/{name}"] = b"same\n"
            context = diagnostics.DiagnosticContext(actual_root=root, game_versions=("1",), expected=expected)
            result = diagnostics.append_failure_diagnostics("original", lambda: context)
            self.assertEqual(5, result.count("\n  artifact:"))
            for fact in ("not UTF-8", "line endings", "binary data", "text size limit", "1 file details omitted"):
                self.assertIn(fact, result)

    def test_collection_excludes_unsafe_and_unrelated_files_and_records_write_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            staging = temp / "staging"
            actual = staging / "actual-bin-artifacts"
            module = actual / "1/server"
            module.mkdir(parents=True)
            (module / "safe.yaml").write_bytes(b"safe\n")
            (module / "private.idb").write_bytes(b"private")
            (module / "nested").mkdir()
            (module / "nested/private.yaml").write_bytes(b"private")
            linked = module / "linked.yaml"
            linked.write_bytes(b"private")
            context = diagnostics.DiagnosticContext(
                actual_root=actual,
                game_versions=("1",),
                expected={
                    "bin_artifacts/1/server/safe.yaml": b"expected\n",
                    "bin_artifacts/1/../escape.yaml": b"private",
                },
                evidence={"missing.json": staging / "missing.json"},
            )
            original = diagnostics.is_reparse_point
            with patch.object(
                diagnostics, "is_reparse_point", side_effect=lambda path: path == linked or original(path)
            ):
                diagnostics.collect_failure_bundle(
                    repo_root=temp / "repo",
                    staging=staging,
                    destination=temp / "bundle",
                    error="original",
                    phase="execute",
                    load_context=lambda: context,
                )
            self.assertEqual(b"safe\n", (temp / "bundle/actual/bin_artifacts/1/server/safe.yaml").read_bytes())
            for relative in ("private.idb", "linked.yaml", "nested/private.yaml"):
                self.assertFalse((temp / "bundle/actual/bin_artifacts/1/server" / relative).exists())
            self.assertFalse((temp / "bundle/expected/bin_artifacts/escape.yaml").exists())
            metadata = json.loads((temp / "bundle/diagnostics.json").read_bytes())
            for fact in ("missing", "non-flat", "skipped link", "unsafe"):
                self.assertIn(fact, " ".join(metadata["collection_errors"]))
            original_open = Path.open

            def fail_actual(path, *args, **kwargs):
                if "actual" in path.parts and "bundle2" in path.parts:
                    raise OSError("disk full")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", fail_actual):
                diagnostics.collect_failure_bundle(
                    repo_root=temp / "repo",
                    staging=staging,
                    destination=temp / "bundle2",
                    error="original",
                    phase="execute",
                    load_context=lambda: context,
                )
            self.assertEqual("original\n", (temp / "bundle2/verification-error.txt").read_text())
            self.assertIn("disk full", (temp / "bundle2/diagnostics.json").read_text())

    def test_collection_rejects_overlapping_destinations_and_ancestor_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            for destination in (temp / "repo/bundle", temp / "staging/bundle", temp):
                with self.subTest(destination=destination), self.assertRaises(ValueError):
                    diagnostics.collect_failure_bundle(
                        repo_root=temp / "repo",
                        staging=temp / "staging",
                        destination=destination,
                        error="original",
                        phase="verify",
                        load_context=diagnostics.DiagnosticContext,
                    )
            original = diagnostics.is_reparse_point
            with patch.object(
                diagnostics, "is_reparse_point", side_effect=lambda path: path == temp / "linked" or original(path)
            ):
                with self.assertRaisesRegex(ValueError, "link"):
                    diagnostics.collect_failure_bundle(
                        repo_root=temp / "repo",
                        staging=temp / "staging",
                        destination=temp / "linked/bundle",
                        error="original",
                        phase="verify",
                        load_context=diagnostics.DiagnosticContext,
                    )

    def test_case_collisions_are_rejected_before_opening_either_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "1/server"
            module.mkdir(parents=True)
            target = module / "a.yaml"
            target.write_bytes(b"private")
            original_iterdir = Path.iterdir

            def collision(path):
                return iter((target, module / "A.yaml")) if path == module else original_iterdir(path)

            context = diagnostics.DiagnosticContext(actual_root=root, game_versions=("1",), expected={})
            with patch.object(Path, "iterdir", collision), patch.object(diagnostics, "read_artifact_bytes") as read:
                actual, _errors = diagnostics.read_flat_artifacts(context)
            self.assertEqual({}, actual)
            read.assert_not_called()
            self.assertIn("collision", " ".join(context.errors))

    def test_linked_expected_file_is_unreadable_rather_than_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "1/server/a.yaml"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"private")
            context = diagnostics.DiagnosticContext(
                actual_root=root,
                game_versions=("1",),
                expected={"bin_artifacts/1/server/a.yaml": b"expected"},
            )
            original = diagnostics.is_reparse_point
            with patch.object(
                diagnostics, "is_reparse_point", side_effect=lambda path: path == target or original(path)
            ):
                rendered = diagnostics.render_inventory_diagnostics(context)
            self.assertIn("missing=[] (total=0)", rendered)
            self.assertIn("actual:   skipped link/reparse point", rendered)
            self.assertNotIn("+private", rendered)

    def test_inventory_diagnostics_include_mixed_drift_and_bound_all_lists(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "1/server"
            module.mkdir(parents=True)
            (module / "changed.yaml").write_bytes(b"value: new\n")
            (module / "extra.yaml").write_bytes(b"extra\n")
            expected = {
                "bin_artifacts/1/server/changed.yaml": b"value: old\n",
                "bin_artifacts/1/server/missing.yaml": b"missing\n",
            }
            context = diagnostics.DiagnosticContext(
                actual_root=root,
                game_versions=("1",),
                expected=expected,
                metadata={"expected_source": "merge Git blob", "source_sha": "a" * 40},
            )
            rendered = diagnostics.append_failure_diagnostics("original", lambda: context)
            for fact in ("missing=", "extra=", "changed=", "merge Git blob", "-value: old", "+value: new", "sha256="):
                self.assertIn(fact, rendered)
            context.expected.update({f"bin_artifacts/1/server/{index:05d}.yaml": b"x" for index in range(1000)})
            rendered = diagnostics.append_failure_diagnostics("original", lambda: context, max_characters=1000)
            self.assertLessEqual(len(rendered), 1000 + len("original"))
            self.assertIn("omitted", rendered)

    def test_inventory_renderer_failure_keeps_original(self):
        with patch.object(diagnostics, "render_inventory_diagnostics", side_effect=RuntimeError("renderer failed")):
            result = diagnostics.append_failure_diagnostics("original", lambda: diagnostics.DiagnosticContext())
        self.assertTrue(result.startswith("original"))
        self.assertIn("renderer failed", result)

    def test_text_facts_and_diff(self):
        result = content_diff("a.yaml", b"value: old\n", b"value: new\n")
        for expected in ("size=11 sha256=sha256:", "-value: old", "+value: new"):
            self.assertIn(expected, result)

    def test_missing_binary_and_newline_only(self):
        self.assertIn("expected: missing", content_diff("a", None, b"new\n"))
        self.assertIn("+new", content_diff("a", None, b"new\n"))
        self.assertIn("actual:   missing", content_diff("a", b"old\n", None))
        self.assertIn("not UTF-8", content_diff("a", b"\xff", b"\xfe"))
        self.assertIn("binary data", content_diff("a", b"\0a", b"\0b"))
        self.assertIn("line endings", content_diff("a", b"a\r\n", b"a\n"))

    def test_bounded_diff(self):
        result = content_diff("a", b"old\n" * 100, b"new\n" * 100, max_diff_lines=5)
        self.assertIn("truncated", result)
        self.assertLess(len(result.splitlines()), 15)
        result = content_diff("a", b"a" * 100000, b"b" * 100000)
        self.assertLessEqual(len(result), diagnostics.MAX_DIFF_CHARACTERS)

    def test_unreadable_file_is_a_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "a"
            target.write_bytes(b"a")
            with patch.object(Path, "read_bytes", side_effect=PermissionError("denied")):
                raw, error = read_artifact_bytes(target)
            self.assertIsNone(raw)
            self.assertIn("denied", error)


if __name__ == "__main__":
    unittest.main()
