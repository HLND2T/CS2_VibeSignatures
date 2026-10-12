"""Run isolated Windows/Linux analysis workers and compose full-run evidence.

Worker records are internal transport, never accepted as trusted execution reports.
Only the coordinator emits the existing complete force-all/selected report.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

PLATFORMS = ("windows", "linux")
WORKER_SCHEMA = "platform-analysis-worker:v1"
LOCK_ROOT_ENV = "CS2VIBE_PARALLEL_LOCK_ROOT"
POLL_SECONDS = 0.1
HEARTBEAT_SECONDS = 30


@contextlib.contextmanager
def shared_lock(name):
    """Serialize short shared operations only within one parallel analysis run."""
    root = os.environ.get(LOCK_ROOT_ENV)
    if not root:
        yield
        return
    path = Path(root) / f"{name}.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.write(b"\0")
        handle.flush()
        while True:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                # The holder has its own startup/Agent deadline. Waiting must not
                # impose a shorter one; process exit releases this OS lock.
                time.sleep(POLL_SECONDS)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def owned_command(command, exit_code_file=None):
    """Enclose all analyzer/Agent/IDA descendants in an owned Windows Job."""
    if os.name != "nt":
        return command
    return [
        sys.executable,
        str(Path(__file__).with_name("ida_mcp_job_launcher.py")),
        "--parent-pid",
        str(os.getpid()),
        *(["--exit-code-file", str(exit_code_file)] if exit_code_file is not None else []),
        "--",
        *command,
    ]


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            # Closing the launcher's only Job handle kills even detached descendants.
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)


def run_processes(commands, logs, *, env=None, heartbeat=None):
    """Start every worker before waiting; preserve both logs even after one fails."""
    logs = Path(logs)
    logs.mkdir(parents=True, exist_ok=True)
    processes, handles, results, timing = {}, {}, {}, {}
    status = "cancelled"
    previous_handler = signal.getsignal(signal.SIGTERM)

    def terminate(_signum, _frame):
        raise KeyboardInterrupt("Parallel analysis cancelled")

    signal.signal(signal.SIGTERM, terminate)
    try:
        for platform, command in commands.items():
            exit_file = logs / f"{platform}.exit-code"
            if exit_file.exists():
                raise ValueError(f"Refusing stale worker exit evidence: {exit_file}")
            handles[platform] = (logs / f"{platform}.log").open("wb")
            timing[platform] = time.monotonic()
            try:
                processes[platform] = subprocess.Popen(
                    owned_command(command, exit_file),
                    stdin=subprocess.DEVNULL,
                    stdout=handles[platform],
                    stderr=subprocess.STDOUT,
                    env=env,
                    start_new_session=os.name != "nt",
                )
            except OSError as exc:
                handles[platform].write(f"Unable to start worker: {exc}\n".encode())
                results[platform] = -1
                timing[platform] = time.monotonic() - timing[platform]
        pending = set(processes)
        heartbeat_at = time.monotonic()
        while pending:
            if heartbeat is not None and time.monotonic() - heartbeat_at >= HEARTBEAT_SECONDS:
                heartbeat()
                heartbeat_at = time.monotonic()
            for platform in tuple(pending):
                code = processes[platform].poll()
                if code is not None:
                    if os.name == "nt":
                        try:
                            code = int((logs / f"{platform}.exit-code").read_text(encoding="utf-8"))
                        except (OSError, ValueError):
                            code = -1
                    results[platform] = code
                    timing[platform] = time.monotonic() - timing[platform]
                    pending.remove(platform)
            if pending:
                time.sleep(POLL_SECONDS)
        status = "succeeded" if all(code == 0 for code in results.values()) else "failed"
        return results
    finally:
        cleanup_errors = []
        try:
            for platform, process in processes.items():
                try:
                    stop_process(process)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    cleanup_errors.append(f"{platform}: {exc}")
                if platform not in results:
                    results[platform] = process.returncode
                    timing[platform] = time.monotonic() - timing[platform]
        finally:
            for handle in handles.values():
                handle.close()
            signal.signal(signal.SIGTERM, previous_handler)
            (logs / "summary.json").write_text(
                json.dumps(
                    {
                        "status": status,
                        "cleanup_errors": cleanup_errors,
                        "platforms": {
                            platform: {"exit_code": results.get(platform), "elapsed_seconds": timing.get(platform)}
                            for platform in commands
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        if cleanup_errors:
            raise RuntimeError(f"Unable to clean platform processes: {cleanup_errors}")


def inventory(root):
    """Hash a real artifact tree without traversing links."""
    from gamesymbol_snapshot_lib.paths import is_reparse_point

    root = Path(root)
    result = {}
    if not root.exists():
        return result
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        for path in [Path(directory), *(Path(directory) / name for name in subdirectories + files)]:
            if is_reparse_point(path):
                raise ValueError(f"Worker artifact tree contains a link: {path}")
        for name in files:
            path = Path(directory) / name
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def merge_artifacts(worker, target, owned, seed):
    """Validate the entire worker tree before copying any platform-owned output."""
    actual = inventory(worker)
    if any(actual.get(path) != digest for path, digest in seed.items()):
        raise ValueError("Platform worker changed or deleted inherited artifacts")
    unexpected = set(actual) - set(seed) - set(owned)
    if unexpected:
        raise ValueError(f"Platform worker wrote unassigned artifacts: {sorted(unexpected)!r}")
    for relative in sorted(set(actual) - set(seed)):
        destination = Path(target) / relative
        if destination.exists():
            raise ValueError(f"Parallel artifact output collision: {relative}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(worker) / relative, destination)


def worker_document(args, reporting, totals, aborted):
    return {
        "schema": WORKER_SCHEMA,
        "platform": args.platforms[0],
        "run_id": reporting.run_id,
        "config_sha256": hashlib.sha256(Path(args.configyaml).read_bytes()).hexdigest(),
        "artifact_root": str(Path(args.artifactdir).resolve()),
        "totals": totals,
        "aborted": aborted,
        "tasks": [reporting.task_record(node.id) for node in [*reporting.plan.jobs, *reporting.plan.nodes]],
    }


def import_worker(document, reporting, platform, worker_root, target_root, run_id, config_digest):
    """Require exact task coverage and translate isolated output paths to the final root."""
    from process_reporter import TaskStatus

    if not isinstance(document, dict):
        raise ValueError(f"Invalid {platform} worker document")
    jobs = {job.id for job in reporting.plan.jobs if job.platform == platform}
    expected = jobs | {node.id for node in reporting.plan.nodes if node.job_id in jobs}
    tasks = document.get("tasks", [])
    totals = document.get("totals")
    if (
        not isinstance(tasks, list)
        or any(not isinstance(task, dict) for task in tasks)
        or not isinstance(totals, list)
        or len(totals) != 3
        or any(type(count) is not int or count < 0 for count in totals)
        or type(document.get("aborted")) is not bool
    ):
        raise ValueError(f"Invalid {platform} worker records or totals")
    if (
        document.get("schema") != WORKER_SCHEMA
        or document.get("platform") != platform
        or document.get("run_id") != run_id
        or document.get("config_sha256") != config_digest
        or document.get("artifact_root") != str(worker_root.resolve())
        or len(tasks) != len(expected)
        or {task["task_id"] for task in tasks} != expected
    ):
        raise ValueError(f"Invalid or incomplete {platform} worker evidence")

    def translate(paths):
        return [str(target_root / Path(path).resolve().relative_to(worker_root.resolve())) for path in paths]

    translated = []
    for task in tasks:
        task_id = task["task_id"]
        status = TaskStatus(task["status"])
        if type(task["attempted"]) is not bool:
            raise ValueError(f"Worker attempt flag is invalid: {task_id}")
        if status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            raise ValueError(f"Worker left task unfinished: {task_id}")
        payload = dict(task["payload"])
        if "produced_outputs" in payload:
            payload["produced_outputs"] = translate(payload["produced_outputs"])
        translated.append(
            {
                **task,
                "attempted_outputs": translate(task["attempted_outputs"]),
                "produced_outputs": translate(task["produced_outputs"]),
                "payload": payload,
            }
        )
    for task in translated:
        reporting.import_task_record(task)


def run_parallel(args, modules, reporting, analyzer):
    """Prepare private roots, execute both CLI workers, and compose their records."""
    from gamesymbol_snapshot_lib.config import load_contract

    logs = Path(args.parallel_platforms).resolve()
    logs.mkdir(parents=True, exist_ok=False)
    target = Path(args.artifactdir).resolve()
    game_root = target / str(args.gamever)
    seed = inventory(game_root)
    contract = load_contract(args.configyaml, args.gamever, args.bindir, artifactdir=target)
    owned = {
        platform: {
            path
            for node in contract.nodes.values()
            if node.platform == platform and (args.selected_node_ids is None or node.node_id in args.selected_node_ids)
            for path in node.outputs
        }
        for platform in PLATFORMS
    }
    if owned["windows"] & owned["linux"] or (owned["windows"] | owned["linux"]) & set(seed):
        raise ValueError("Parallel platforms require disjoint executed and inherited artifact paths")
    binaries = {platform: set() for platform in PLATFORMS}
    for module in modules:
        for platform in PLATFORMS:
            if module.get(f"path_{platform}"):
                binaries[platform].add(
                    Path(
                        analyzer.get_binary_path(args.bindir, args.gamever, module["name"], module[f"path_{platform}"])
                    ).resolve()
                )
    if binaries["windows"] & binaries["linux"]:
        raise ValueError("Parallel platforms must not open the same binary/IDB")

    # Keep original flags, then override only worker-owned locations and run identity.
    original = []
    arguments = iter(sys.argv[1:])
    for argument in arguments:
        if argument == "-parallel_platforms":
            next(arguments)
        elif not argument.startswith("-parallel_platforms="):
            original.append(argument)
    commands, roots, reports, run_ids = {}, {}, {}, {}
    for platform in PLATFORMS:
        roots[platform] = logs / platform / "artifacts"
        roots[platform].mkdir(parents=True)
        if game_root.exists():
            shutil.copytree(game_root, roots[platform] / str(args.gamever))
        reports[platform] = logs / platform / "worker.json"
        run_ids[platform] = f"{reporting.run_id}-{platform}"
        commands[platform] = [
            "uv",
            "run",
            "--no-sync",
            "python",
            "-u",
            str(Path(analyzer.__file__).resolve()),
            *original,
            "-platform",
            platform,
            "-platform_worker",
            "-artifactdir",
            str(roots[platform]),
            "-execution_report",
            str(reports[platform]),
            "-configyaml",
            str(Path(args.configyaml).resolve()),
            "-oldartifactdir",
            str(Path(args.oldartifactdir).resolve()),
            "-oldgamever",
            str(args.oldgamever) if args.oldgamever else "none",
            "-run_id",
            run_ids[platform],
            "-process_reporter",
            "none",
        ]
    env = {**os.environ, LOCK_ROOT_ENV: str(logs / "locks"), "PYTHONUNBUFFERED": "1"}
    results = run_processes(commands, logs, env=env, heartbeat=lambda: reporting.reporter.heartbeat(reporting.run_id))
    totals, aborted, errors = [0, 0, 0], False, []
    for platform in PLATFORMS:
        try:
            document = json.loads(reports[platform].read_text(encoding="utf-8"))
            import_worker(
                document,
                reporting,
                platform,
                roots[platform],
                target,
                run_ids[platform],
                hashlib.sha256(Path(args.configyaml).read_bytes()).hexdigest(),
            )
            merge_artifacts(roots[platform] / str(args.gamever), game_root, owned[platform], seed)
            totals = [left + right for left, right in zip(totals, document["totals"])]
            aborted = aborted or document["aborted"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{platform}: {exc}")
        if results[platform] != 0:
            errors.append(f"{platform} worker exited with {results[platform]}")
    if errors:
        totals[1] += len(errors)
        aborted = True
    args.parallel_errors = errors
    summary_path = logs / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary.update(status="failed" if totals[1] else "succeeded", merge_errors=errors, totals=totals)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Platform analysis finished; logs and summary: {logs}")
    for error in errors:
        print(f"  {error}")
    return totals, aborted
