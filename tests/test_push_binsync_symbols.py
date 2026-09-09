import importlib.util
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from binsync_projection import build_source_projection

SCRIPT = Path("push_binsync_symbols.py")
SPEC = importlib.util.spec_from_file_location("push_binsync_symbols", SCRIPT)
push_binsync_symbols = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(push_binsync_symbols)


def _git(repo: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )


def _build_min_pe(first_section_rva: int = 0x1000) -> bytes:
    """Minimal but structurally valid PE with one section at ``first_section_rva``."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew -> PE header at 0x40
    optsize = 0xF0
    pe = bytearray(4 + 20 + optsize)  # signature + COFF header + PE32+ optional header
    pe[0:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 4, 0x8664, 1, 0, 0, 0, optsize, 0x2022)
    struct.pack_into("<H", pe, 24, 0x20B)  # PE32+ magic
    section = bytearray(40)
    section[0:8] = b".text\0\0\0\0"
    struct.pack_into("<I", section, 12, first_section_rva)  # VirtualAddress
    return bytes(dos) + bytes(pe) + bytes(section)


def _build_min_elf() -> bytes:
    """Minimal ELF64 with a single PT_LOAD at vaddr 0."""
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # ELFCLASS64
    ehdr[5] = 1  # little endian
    ehdr[6] = 1
    ehdr[7] = 3  # ET_DYN
    ehdr[8] = 0x3E  # EM_X86_64
    struct.pack_into("<Q", ehdr, 24, 64)  # e_phoff
    struct.pack_into("<H", ehdr, 52, 56)  # e_phentsize
    struct.pack_into("<H", ehdr, 56, 1)  # e_phnum
    phdr = bytearray(56)
    struct.pack_into("<IIQQQQQQ", phdr, 0, 1, 5, 0, 0, 0x200, 0x200, 0x1000, 0x1000)
    return bytes(ehdr) + bytes(phdr)


class TestCollectManifestSymbols(unittest.TestCase):
    def _make_config(self, root: Path, gamever: str = "14174") -> Path:
        module = root / "bin" / gamever / "engine"
        module.mkdir(parents=True)
        artifact_module = root / "bin_artifacts" / gamever / "engine"
        artifact_module.mkdir(parents=True)
        (module / "engine2.dll").write_bytes(_build_min_pe(first_section_rva=0x1000))
        (module / "libengine2.so").write_bytes(_build_min_elf())

        (artifact_module / "Ctor.windows.yaml").write_text(
            "func_name: Ctor\nfunc_va: '0x1800bab40'\nfunc_rva: '0xbab40'\nfunc_size: '0x1bd'\n",
            encoding="utf-8",
        )
        (artifact_module / "Ctor.linux.yaml").write_text(
            "func_name: Ctor\nfunc_va: '0x533b70'\nfunc_rva: '0x533b70'\nfunc_size: '0x21d'\n",
            encoding="utf-8",
        )
        (artifact_module / "g_pCvar.windows.yaml").write_text(
            "gv_name: g_pCvar\ngv_rva: '0x688b08'\ngv_va: '0x180688b08'\n",
            encoding="utf-8",
        )
        (artifact_module / "g_pCvar.linux.yaml").write_text(
            "gv_name: g_pCvar\ngv_rva: '0xc72230'\ngv_va: '0xc72230'\n",
            encoding="utf-8",
        )

        config = root / "config.yaml"
        config.write_text(
            "modules:\n"
            "  - name: engine\n"
            "    path_windows: game/bin/win64/engine2.dll\n"
            "    path_linux: game/bin/linuxsteamrt64/libengine2.so\n"
            "    symbols:\n"
            "      - name: Ctor\n"
            "        category: func\n"
            "      - name: g_pCvar\n"
            "        category: gv\n"
            "      - name: SomeStruct\n"
            "        category: struct\n"
            "      - name: Missing\n"
            "        category: vfunc\n"
            "      - name: NullRva\n"
            "        category: func\n",
            encoding="utf-8",
        )
        # NullRva.yaml carries no func_rva -> must be skipped, not crash.
        (artifact_module / "NullRva.windows.yaml").write_text("func_name: NullRva\n", encoding="utf-8")
        (artifact_module / "NullRva.linux.yaml").write_text("func_name: NullRva\n", encoding="utf-8")

        return config

    def test_collect_selects_declared_funcs_and_globals_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_config(root)
            manifest = push_binsync_symbols.collect_manifest_symbols(root, "14174", config)

            # Windows manifest addresses are declib-lifted keys: the YAML rva
            # (relative to the PE image base) minus the first section's RVA
            # (0x1000 here), matching BinSync's key = func_va - first_segment_base.
            # Linux loads at vaddr 0, so the rva is used verbatim.
            self.assertEqual(manifest["engine/windows"]["functions"], [0xBAB40 - 0x1000])
            self.assertEqual(manifest["engine/windows"]["globals"], [0x688B08 - 0x1000])
            self.assertEqual(manifest["engine/linux"]["functions"], [0x533B70])
            self.assertEqual(manifest["engine/linux"]["globals"], [0xC72230])
            self.assertEqual(
                {str(0xBAB40 - 0x1000): "Ctor", str(0x688B08 - 0x1000): "g_pCvar"},
                manifest["engine/windows"]["names"],
            )
            self.assertEqual(
                {str(0x533B70): "Ctor", str(0xC72230): "g_pCvar"},
                manifest["engine/linux"]["names"],
            )

    def test_collect_excludes_struct_and_missing_and_null_rva(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_config(root)
            manifest = push_binsync_symbols.collect_manifest_symbols(root, "14174", config)

            for platform in ("windows", "linux"):
                # struct, undeclared-file, and null-rva symbols must not leak in.
                expected = [0x533B70] if platform == "linux" else [0xBAB40 - 0x1000]
                self.assertEqual(manifest[f"engine/{platform}"]["functions"], expected)
                self.assertEqual(len(manifest[f"engine/{platform}"]["functions"]), 1)
                self.assertEqual(len(manifest[f"engine/{platform}"]["globals"]), 1)

    def test_first_segment_lift_bias_windows_vs_linux(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pe_0x1000 = root / "engine2.dll"
            pe_0x1000.write_bytes(_build_min_pe(first_section_rva=0x1000))
            pe_0x2000 = root / "other.dll"
            pe_0x2000.write_bytes(_build_min_pe(first_section_rva=0x2000))
            elf = root / "libengine2.so"
            elf.write_bytes(_build_min_elf())

            self.assertEqual(push_binsync_symbols._first_segment_lift_bias(pe_0x1000), 0x1000)
            self.assertEqual(push_binsync_symbols._first_segment_lift_bias(pe_0x2000), 0x2000)
            self.assertEqual(push_binsync_symbols._first_segment_lift_bias(elf), 0)

    def test_source_projection_aggregates_split_module_declarations(self) -> None:
        config = (
            "modules:\n"
            "  - name: server\n"
            "    symbols:\n"
            "      - {name: A, category: func}\n"
            "  - name: server\n"
            "    symbols:\n"
            "      - {name: B, category: gv}\n"
        ).encode()
        artifacts = {
            "bin_artifacts/1/server/A.windows.yaml": b"func_name: A\nfunc_rva: '0x10'\n",
            "bin_artifacts/1/server/B.windows.yaml": b"gv_name: B\ngv_rva: '0x20'\n",
        }

        projection = build_source_projection(
            game_version="1",
            config_payload=config,
            targets=[{"module": "server", "platform": "windows", "repository_id": "owner__repo"}],
            read_artifact=artifacts.get,
        )

        self.assertEqual(["A", "B"], [entry["symbol"] for entry in projection["entries"]])

    def test_build_manifest_writes_json(self) -> None:
        entries = {"functions": [1, 2, 3], "globals": [4]}
        path = push_binsync_symbols.build_manifest(entries)
        try:
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle), entries)
        finally:
            path.unlink(missing_ok=True)

    def test_binary_export_is_always_redirected_to_local_only_sink(self) -> None:
        completed = type("Completed", (), {"returncode": 0})()
        with patch.object(push_binsync_symbols.subprocess, "run", return_value=completed) as run:
            code = push_binsync_symbols.push_binary(
                "python",
                "headless_force_push.py",
                Path("server.dll"),
                Path("manifest.json"),
            )

        self.assertEqual(0, code)
        command = run.call_args.args[0]
        self.assertIn("--local-only", command)
        self.assertIn("--push", command)

    def test_direct_remote_publication_mode_is_disabled(self) -> None:
        self.assertEqual(2, push_binsync_symbols.main(["14174"]))


class TestBootstrapLocalInit(unittest.TestCase):
    """--bootstrap-local-init must initialize locally and never touch any remote."""

    USER = "bootstrap-validation"

    def _make_workspace(self, root: Path, gamever: str = "14180") -> Path:
        module = root / "bin" / gamever / "SDL3"
        module.mkdir(parents=True)
        (module / "SDL3.dll").write_bytes(_build_min_pe())
        config = root / "config.yaml"
        config.write_text(
            "modules:\n"
            "  - name: SDL3\n"
            "    path_windows: game/bin/win64/SDL3.dll\n"
            "    symbols:\n"
            "      - name: SomeFunc\n"
            "        category: func\n",
            encoding="utf-8",
        )
        return config

    def test_bootstrap_local_init_initializes_missing_repo_without_remote_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_workspace(root)
            binary = root / "bin" / "14180" / "SDL3" / "SDL3.dll"
            binary_md5 = push_binsync_symbols.file_md5(binary)

            with patch.object(push_binsync_symbols, "_remote_heads") as remote_heads:
                snapshots = push_binsync_symbols.prepare_local_repositories(
                    root, "14180", config, self.USER, bootstrap_local_init=True
                )

            remote_heads.assert_not_called()
            repo = binary.parent / "SDL3.dll.bsproj"
            self.assertTrue(repo.is_dir())
            branches = _git(repo, "for-each-ref", "--format=%(refname)", "refs/heads/binsync/").stdout.split()
            self.assertIn("refs/heads/binsync/__root__", branches)
            self.assertIn(f"refs/heads/binsync/{self.USER}", branches)
            self.assertEqual(binary_md5, _git(repo, "show", "binsync/__root__:binary_hash").stdout)
            self.assertEqual(
                "https://github.com/HLND2T/CS2_VibeSignatures_binsync_14180_SDL3.dll",
                _git(repo, "config", "--get", "remote.origin.url").stdout.strip(),
            )
            # The dedicated user branch is checked out and the sidecar is written.
            self.assertEqual(f"binsync/{self.USER}", _git(repo, "branch", "--show-current").stdout.strip())
            sidecar = json.loads((binary.parent / "SDL3.dll.binsync.json").read_text(encoding="utf-8"))
            self.assertEqual(self.USER, sidecar["user"])
            self.assertEqual(binary_md5, sidecar["expected_md5"])

            repository_id = "HLND2T__CS2_VibeSignatures_binsync_14180_SDL3.dll"
            self.assertEqual(
                {repository_id: {"remote_url": "https://github.com/HLND2T/CS2_VibeSignatures_binsync_14180_SDL3.dll"}},
                snapshots,
            )

    def test_bootstrap_local_init_prepare_survives_insteadof_proxy_rewrite(self) -> None:
        # Issue #947: the runner rewrites every GitHub HTTPS read through a git
        # cache proxy via a system-level insteadOf; the local-init prepare must
        # validate origins against the raw stored canonical URL, not the
        # rewritten transport URL that `git remote get-url` would return.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_workspace(root)
            with (
                patch.dict(
                    os.environ,
                    {
                        "GIT_CONFIG_COUNT": "1",
                        "GIT_CONFIG_KEY_0": "url.http://127.0.0.1:8080/.insteadOf",
                        "GIT_CONFIG_VALUE_0": "https://github.com/",
                    },
                ),
                patch.object(push_binsync_symbols, "_remote_heads") as remote_heads,
            ):
                snapshots = push_binsync_symbols.prepare_local_repositories(
                    root, "14180", config, self.USER, bootstrap_local_init=True
                )

            remote_heads.assert_not_called()
            repository_id = "HLND2T__CS2_VibeSignatures_binsync_14180_SDL3.dll"
            self.assertEqual(
                {repository_id: {"remote_url": "https://github.com/HLND2T/CS2_VibeSignatures_binsync_14180_SDL3.dll"}},
                snapshots,
            )

    def test_bootstrap_local_init_is_idempotent_for_existing_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_workspace(root)
            binary = root / "bin" / "14180" / "SDL3" / "SDL3.dll"
            repo = binary.parent / "SDL3.dll.bsproj"

            push_binsync_symbols.prepare_local_repositories(root, "14180", config, self.USER, bootstrap_local_init=True)
            root_commit = _git(repo, "rev-parse", "refs/heads/binsync/__root__").stdout.strip()
            head_commit = _git(repo, "rev-parse", "HEAD").stdout.strip()

            # Re-running over the existing local state must not re-initialize or move refs.
            with patch.object(push_binsync_symbols, "_remote_heads"):
                push_binsync_symbols.prepare_local_repositories(
                    root, "14180", config, self.USER, bootstrap_local_init=True
                )

            self.assertEqual(root_commit, _git(repo, "rev-parse", "refs/heads/binsync/__root__").stdout.strip())
            self.assertEqual(head_commit, _git(repo, "rev-parse", "HEAD").stdout.strip())

    def test_bootstrap_local_init_failure_names_the_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_workspace(root)
            with patch.object(
                push_binsync_symbols,
                "initialize_minimal_binsync_repo",
                side_effect=push_binsync_symbols.InitGamebinError("git init exploded"),
            ):
                with self.assertRaisesRegex(RuntimeError, "SDL3.dll.*git init exploded"):
                    push_binsync_symbols.prepare_local_repositories(
                        root, "14180", config, self.USER, bootstrap_local_init=True
                    )

    def test_remote_mode_clone_failure_names_the_binary_and_keeps_remote_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_workspace(root)
            # Remote mode (default) must keep cloning: a clone failure propagates
            # instead of silently falling back to local initialization.
            with patch.object(
                push_binsync_symbols,
                "_git_result",
                side_effect=RuntimeError(
                    "git clone failed with exit code 128: fatal: repository "
                    "'https://github.com/HLND2T/CS2_VibeSignatures_binsync_14180_SDL3.dll/' not found"
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "SDL3.dll.*exit code 128.*not found"):
                    push_binsync_symbols.prepare_local_repositories(root, "14180", config, self.USER)

    def test_assert_remote_refs_unchanged_rejects_local_init_snapshots(self) -> None:
        snapshots = {
            "HLND2T__CS2_VibeSignatures_binsync_14180_SDL3.dll": {
                "remote_url": "https://github.com/HLND2T/CS2_VibeSignatures_binsync_14180_SDL3.dll"
            }
        }
        with self.assertRaisesRegex(RuntimeError, "never query the canonical remote"):
            push_binsync_symbols.assert_remote_refs_unchanged(snapshots)

    def test_write_bootstrap_local_evidence_records_local_init_mode(self) -> None:
        snapshots = {
            "HLND2T__repo": {"remote_url": "https://github.com/HLND2T/CS2_VibeSignatures_binsync_14180_SDL3.dll"}
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = Path(temp_dir) / "evidence"
            push_binsync_symbols.write_bootstrap_local_evidence(
                candidate,
                "14180",
                snapshots,
                push_binsync_symbols.BOOTSTRAP_LOCAL_INIT_REFS_DIGEST,
                bootstrap_local_init=True,
            )
            document = json.loads((candidate / "local-evidence.json").read_text(encoding="utf-8"))

        self.assertEqual("bootstrap-local-init", document["binsync_mode"])
        self.assertEqual(
            push_binsync_symbols.BOOTSTRAP_LOCAL_INIT_REFS_DIGEST,
            document["remote_refs_before_sha256"],
        )
        self.assertEqual(document["remote_refs_before_sha256"], document["remote_refs_after_sha256"])
        self.assertEqual(
            [
                {
                    "repository_id": "HLND2T__repo",
                    "remote_url": snapshots["HLND2T__repo"]["remote_url"],
                    "initialized_locally": True,
                }
            ],
            document["repositories"],
        )

    def test_write_bootstrap_local_evidence_keeps_remote_mode_schema(self) -> None:
        snapshots = {
            "HLND2T__repo": {
                "remote_url": "https://github.com/HLND2T/CS2_VibeSignatures_binsync_14174_SDL3.dll",
                "heads": {"refs/heads/binsync/__root__": "a" * 40},
            }
        }
        with patch.object(
            push_binsync_symbols,
            "_remote_heads",
            return_value={"refs/heads/binsync/__root__": "a" * 40},
        ) as remote_heads:
            digest = push_binsync_symbols.assert_remote_refs_unchanged(snapshots)
        remote_heads.assert_called_once_with(snapshots["HLND2T__repo"]["remote_url"])
        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = Path(temp_dir) / "evidence"
            push_binsync_symbols.write_bootstrap_local_evidence(candidate, "14174", snapshots, digest)
            document = json.loads((candidate / "local-evidence.json").read_text(encoding="utf-8"))

        self.assertEqual("bootstrap-local-only", document["binsync_mode"])
        self.assertNotIn("initialized_locally", document["repositories"][0])
        self.assertIn("remote_refs_sha256", document["repositories"][0])

    def test_bootstrap_local_init_requires_no_publication_candidate(self) -> None:
        self.assertEqual(
            2,
            push_binsync_symbols.main(
                [
                    "14180",
                    "--prepare-only",
                    "--bootstrap-local-init",
                    "--candidate-dir",
                    "unused",
                    "--preparation",
                    "p",
                    "--release-version",
                    "v",
                    "--build-id",
                    "b",
                    "--ida-runtime-identity",
                    "i",
                    "--actions-artifact-name",
                    "a",
                ]
            ),
        )

    def test_push_binary_passes_bootstrap_local_init_to_headless_export(self) -> None:
        completed = type("Completed", (), {"returncode": 0})()
        with patch.object(push_binsync_symbols.subprocess, "run", return_value=completed) as run:
            push_binsync_symbols.push_binary(
                "python",
                "headless_force_push.py",
                Path("SDL3.dll"),
                Path("manifest.json"),
                bootstrap_local_init=True,
            )

        command = run.call_args.args[0]
        self.assertIn("--bootstrap-local-init", command)


if __name__ == "__main__":
    unittest.main()
