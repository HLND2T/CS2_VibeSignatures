"""Behavioral coverage for isolated platform workers and their evidence."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import analysis_parallel as parallel


class TestParallelEvidence(unittest.TestCase):
    def test_full_and_selected_reports_match_serial_execution(self):
        import ida_analyze_bin as analyzer
        from gamesymbol_snapshot_lib.config import load_contract
        from tests.test_ida_analyze_bin import write_config

        # Exercise real CLI subprocesses, replacing only the expensive IDA boundary.
        driver_source = """
import os, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv.pop(1))
import ida_analyze_bin as a
from process_reporter import PlanNodeType, TaskStatus, ProcessPhase
from ida_analyze_util import canonical_symbol_yaml_bytes
def execute(args, modules, reporting):
    jobs = {job.id: job for job in reporting.plan.jobs}
    for node in reporting.plan.nodes:
        reporting.emit_task_status(node.id, TaskStatus.RUNNING, ProcessPhase.WAITING_FOR_MCP)
        if node.node_type == PlanNodeType.SKILL:
            job = jobs[node.job_id]
            output = Path(args.artifactdir) / str(args.gamever) / job.module_name / f'A.{job.platform}.yaml'
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical_symbol_yaml_bytes({'func_name':'A','func_rva':'0x10'}, category='func'))
            reporting.record_output_attempts(node.id, [str(output)])
            reporting.record_output_produced(node.id, [str(output)])
        reporting.emit_task_status(node.id, TaskStatus.SUCCEEDED, ProcessPhase.FINISHED)
    return [1, 0, 0], False
a._execute_analysis = execute
a.main()
if os.environ.get('TEST_FAIL_PLATFORM') and '-platform' in sys.argv:
    if sys.argv[sys.argv.index('-platform') + 1] == os.environ['TEST_FAIL_PLATFORM']:
        raise SystemExit(9)
"""
        for mode in ("force", "force-failure", "selected", "selected-empty"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config = root / "14179.yaml"
                write_config(
                    config,
                    [
                        {
                            "name": "server",
                            "path_windows": "server.dll",
                            "path_linux": "server.so",
                            "skills": [{"name": "find-a", "expected_output": ["A.{platform}.yaml"]}],
                            "symbols": [{"name": "A", "category": "func"}],
                        }
                    ],
                )
                driver = root / "driver.py"
                # This fixture entry point is injected into child commands below.
                driver.write_text(driver_source, encoding="utf-8")
                target = root / "actual"
                target.mkdir()
                contract = load_contract(config, "14179", root / "bin", artifactdir=target)
                manifest = None
                flags = ["-force_all", "-rename"]
                if not mode.startswith("force"):
                    from ida_analyze_util import canonical_symbol_yaml_bytes

                    execute_nodes = [
                        node
                        for node in contract.nodes.values()
                        if mode != "selected-empty" and node.platform == "windows"
                    ]
                    executed = {node.node_id for node in execute_nodes}
                    inherited = []
                    for node in contract.nodes.values():
                        if node.node_id not in executed:
                            for relative in node.outputs:
                                file = target / "14179" / relative
                                file.parent.mkdir(parents=True, exist_ok=True)
                                file.write_bytes(
                                    canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x10"}, category="func")
                                )
                                inherited.append({"path": relative})
                    manifest = {
                        "schema_version": 1,
                        "execution_strategy": analyzer.SELECTED_EXECUTION_STRATEGY,
                        "plan_sha256": "sha256:" + "a" * 64,
                        "game_version": "14179",
                        "config_sha256": analyzer._sha256_file(config),
                        "initial_actual_inventory_sha256": "sha256:" + "b" * 64,
                        "execute_nodes": [
                            {
                                "node_id": node.node_id,
                                "stage_index": node.stage_index,
                                "module": node.module_name,
                                "platform": node.platform,
                                "skill": node.skill_name,
                                "fingerprint": node.fingerprint,
                            }
                            for node in execute_nodes
                        ],
                        "execute_groups": [
                            {
                                "group_id": group.group_id,
                                "artifact_path": group.artifact_path,
                                "required": group.required,
                                "fingerprint": group.fingerprint,
                                "alternative_node_ids": list(group.alternative_node_ids),
                            }
                            for group in contract.producer_groups.values()
                            if set(group.alternative_node_ids) & executed
                        ],
                        "inherit_paths": inherited,
                        "inherited_absent_groups": [],
                        "removed_paths": [],
                    }
                    manifest["manifest_sha256"] = analyzer._selected_manifest_digest(manifest)
                    manifest_path = root / "manifest.json"
                    manifest_path.write_bytes(analyzer._canonical_json_bytes(manifest))
                    flags = ["-selected_execution", str(manifest_path)]
                serial_root = root / "serial"
                import shutil

                shutil.copytree(target, serial_root)
                report_path = root / "report.json"
                common = [
                    "-gamever",
                    "14179",
                    "-configyaml",
                    str(config),
                    "-bindir",
                    str(root / "bin"),
                    "-oldartifactdir",
                    str(root / "old"),
                    "-oldgamever",
                    "none",
                    "-require_warm_idb",
                    "-process_reporter",
                    "none",
                    *flags,
                ]
                actual_runner = parallel.run_processes

                def with_fixture(commands, logs, **kwargs):
                    commands = {
                        platform: [sys.executable, str(driver), str(Path(analyzer.__file__).parent), *command[6:]]
                        for platform, command in commands.items()
                    }
                    if mode == "force-failure":
                        kwargs["env"]["TEST_FAIL_PLATFORM"] = "windows"
                    return actual_runner(commands, logs, **kwargs)

                argv = [
                    "ida_analyze_bin.py",
                    *common,
                    "-artifactdir",
                    str(target),
                    "-execution_report",
                    str(report_path),
                    "-parallel_platforms",
                    str(root / "logs"),
                ]
                with patch.object(sys, "argv", argv), patch.object(parallel, "run_processes", side_effect=with_fixture):
                    if mode == "force-failure":
                        with self.assertRaises(SystemExit) as failure:
                            analyzer.main()
                        self.assertEqual(1, failure.exception.code)
                    else:
                        analyzer.main()
                report = json.loads(report_path.read_bytes())
                if mode == "force-failure":
                    self.assertFalse(report["valid"])
                    self.assertTrue(any("windows worker exited with 9" in issue for issue in report["issues"]))
                    summary = json.loads((root / "logs" / "summary.json").read_bytes())
                    self.assertEqual("failed", summary["status"])
                    self.assertEqual(0, summary["platforms"]["linux"]["exit_code"])
                    self.assertEqual(9, summary["platforms"]["windows"]["exit_code"])
                    continue
                self.assertTrue(report["valid"], report["issues"])
                self.assertEqual(2, report["inventory"]["file_count"])
                if manifest:
                    self.assertEqual(manifest["manifest_sha256"], report["manifest_sha256"])
                    self.assertEqual(
                        manifest["initial_actual_inventory_sha256"], report["inherited_initial_inventory_sha256"]
                    )
                serial_report = root / "serial-report.json"
                result = subprocess.run(
                    [
                        sys.executable,
                        str(driver),
                        str(Path(analyzer.__file__).parent),
                        *common,
                        "-artifactdir",
                        str(serial_root),
                        "-execution_report",
                        str(serial_report),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                expected = json.loads(serial_report.read_bytes())
                self.assertEqual(expected["producer_groups"], report["producer_groups"])
                self.assertEqual(expected["inventory"], report["inventory"])
                self.assertEqual(expected["summary"], report["summary"])
                unsigned = dict(report)
                digest = unsigned.pop("execution_sha256")
                hash_report = analyzer._selected_execution_digest if manifest else analyzer._force_all_digest
                self.assertEqual(hash_report(unsigned), digest)


class TestPlatformProcesses(unittest.TestCase):
    def test_sibling_processes_serialize_shared_startup_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "lock-worker.py"
            script.write_text(
                "import pathlib,sys,time\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "from analysis_parallel import shared_lock\n"
                "with shared_lock('startup'):\n"
                " with pathlib.Path(sys.argv[2]).open('a') as output:\n"
                "  output.write(sys.argv[3] + '-start\\n'); output.flush()\n"
                "  time.sleep(.2)\n"
                "  output.write(sys.argv[3] + '-end\\n')\n",
                encoding="utf-8",
            )
            events = root / "events"
            commands = {
                platform: [sys.executable, str(script), str(Path(parallel.__file__).parent), str(events), platform]
                for platform in parallel.PLATFORMS
            }
            result = parallel.run_processes(
                commands, root / "logs", env={**os.environ, parallel.LOCK_ROOT_ENV: str(root / "locks")}
            )
            self.assertEqual({"windows": 0, "linux": 0}, result)
            sequence = events.read_text().splitlines()
            first = sequence[0].removesuffix("-start")
            second = "linux" if first == "windows" else "windows"
            self.assertEqual([f"{first}-start", f"{first}-end", f"{second}-start", f"{second}-end"], sequence)

    def test_cancellation_reaps_both_started_workers_and_saves_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            children = [MagicMock(), MagicMock()]
            for child in children:
                child.poll.return_value = None
                child.returncode = 1
            with (
                patch.object(parallel.subprocess, "Popen", side_effect=children),
                patch.object(parallel.time, "sleep", side_effect=KeyboardInterrupt),
                patch.object(parallel, "stop_process") as stop,
                self.assertRaises(KeyboardInterrupt),
            ):
                parallel.run_processes({"windows": ["worker"], "linux": ["worker"]}, Path(temporary))
            self.assertEqual(children, [call.args[0] for call in stop.call_args_list])
            summary = json.loads((Path(temporary) / "summary.json").read_text())
            self.assertEqual("cancelled", summary["status"])

    def test_workers_overlap_and_failure_does_not_cancel_sibling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "worker.py"
            script.write_text(
                "import pathlib, sys, time\n"
                "root, name, other = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]\n"
                "(root / name).touch()\n"
                "deadline = time.monotonic() + 10\n"
                "while not (root / other).exists():\n"
                " if time.monotonic() > deadline: raise RuntimeError('sibling never started')\n"
                " time.sleep(.02)\n"
                "print(name + ' stdout', flush=True)\n"
                "print(name + ' stderr', file=sys.stderr, flush=True)\n"
                "if name == 'windows': sys.exit(3)\n"
                "time.sleep(.2)\n"
                "(root / 'linux-finished').touch()\n",
                encoding="utf-8",
            )
            commands = {
                platform: [sys.executable, str(script), str(root), platform, other]
                for platform, other in (("windows", "linux"), ("linux", "windows"))
            }
            result = parallel.run_processes(commands, root / "logs")
            self.assertEqual({"windows": 3, "linux": 0}, result)
            self.assertTrue((root / "linux-finished").is_file())
            for platform in commands:
                log = (root / "logs" / f"{platform}.log").read_text(encoding="utf-8")
                self.assertIn(f"{platform} stdout", log)
                self.assertIn(f"{platform} stderr", log)
            summary = json.loads((root / "logs" / "summary.json").read_text())
            self.assertEqual("failed", summary["status"])
            self.assertEqual(3, summary["platforms"]["windows"]["exit_code"])

    @unittest.skipUnless(os.name == "nt", "Windows process-tree ownership")
    def test_killing_launcher_reaps_detached_descendant(self):
        import time

        from windows_job import Kernel32JobApi

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "pid"
            command = [
                sys.executable,
                "-c",
                "import subprocess,sys,time,pathlib; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],creationflags=8); "
                "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)",
                str(marker),
            ]
            process = subprocess.Popen(parallel.owned_command(command))
            api = Kernel32JobApi()
            handle = None
            try:
                deadline = time.monotonic() + 10
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                handle = api.open_live_process(int(marker.read_text()))
                parallel.stop_process(process)
                self.assertTrue(api.wait_for_process(handle, 5000))
            finally:
                parallel.stop_process(process)
                if handle:
                    api.close_handle(handle)


class TestArtifactMerge(unittest.TestCase):
    def test_merges_only_owned_outputs_and_preserves_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, worker = root / "actual", root / "worker"
            for directory in (target, worker):
                directory.mkdir()
                (directory / "inherited.yaml").write_bytes(b"seed")
            seed = parallel.inventory(target)
            (worker / "windows.yaml").write_bytes(b"new")
            parallel.merge_artifacts(worker, target, {"windows.yaml"}, seed)
            self.assertEqual(b"new", (target / "windows.yaml").read_bytes())
            self.assertEqual(b"seed", (target / "inherited.yaml").read_bytes())

    def test_rejects_foreign_output_and_changed_or_deleted_inheritance(self):
        for violation in ("foreign", "changed", "deleted"):
            with self.subTest(violation=violation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target, worker = root / "actual", root / "worker"
                for directory in (target, worker):
                    directory.mkdir()
                    (directory / "inherited.yaml").write_bytes(b"seed")
                seed = parallel.inventory(target)
                if violation == "foreign":
                    (worker / "linux.yaml").write_bytes(b"foreign")
                elif violation == "changed":
                    (worker / "inherited.yaml").write_bytes(b"changed")
                else:
                    (worker / "inherited.yaml").unlink()
                with self.assertRaises(ValueError):
                    parallel.merge_artifacts(worker, target, {"windows.yaml"}, seed)
                self.assertEqual({"inherited.yaml": seed["inherited.yaml"]}, parallel.inventory(target))


class TestWorkerEvidence(unittest.TestCase):
    def test_rejects_missing_duplicate_foreign_and_unbound_task_records(self):
        import copy

        from tests.test_ida_analyze_bin import TestForceAllExecutionContract

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, reporting = TestForceAllExecutionContract()._execution_fixture(root, alternatives=False)
            args.platforms = ["windows"]
            reporting.abort_pending("unused", "Fixture task was not used")
            original = parallel.worker_document(args, reporting, [1, 0, 0], False)
            for violation in (
                "missing",
                "duplicate",
                "platform",
                "config",
                "run",
                "path",
                "unfinished",
                "document",
                "totals",
            ):
                with self.subTest(violation=violation):
                    document = copy.deepcopy(original)
                    if violation == "missing":
                        document["tasks"].pop()
                    elif violation == "duplicate":
                        document["tasks"].append(document["tasks"][0])
                    elif violation == "platform":
                        document["platform"] = "linux"
                    elif violation == "config":
                        document["config_sha256"] = "wrong"
                    elif violation == "run":
                        document["run_id"] = "wrong"
                    elif violation == "path":
                        document["tasks"][0]["attempted_outputs"] = [str(root / "foreign.yaml")]
                    elif violation == "document":
                        document = []
                    elif violation == "totals":
                        document["totals"] = [-1, 0, 0]
                    else:
                        document["tasks"][0]["status"] = "running"
                    with self.assertRaises(ValueError):
                        parallel.import_worker(
                            document,
                            reporting,
                            "windows",
                            Path(args.artifactdir),
                            root / "final",
                            original["run_id"],
                            original["config_sha256"],
                        )


if __name__ == "__main__":
    unittest.main()
