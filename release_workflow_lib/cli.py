import argparse
import json
import sys
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.github import write_github_output
from release_workflow_lib.legacy_cleanup import migrate_legacy_completed
from release_workflow_lib.manifests import load_tracked_manifest, write_release_metadata
from release_workflow_lib.promotion import (
    cleanup_completed,
    finalize_promotion,
    list_completed,
    promote_bin,
    reconstruct_workspace,
    verify_output_pr,
    verify_promotion,
)
from release_workflow_lib.staging import (
    abandon_pending,
    assert_no_other_ready_build,
    cleanup_incomplete,
    cleanup_unmerged,
    finalize_stage,
    stage_build,
    write_pr_index,
)
from release_workflow_lib.sync_accepted_bin import sync_accepted_bin
from release_workflow_lib.validation import invalidate_republish, prepare_oldgamever_baseline, validate_build_input


def _add_build_parsers(commands) -> None:
    validate = commands.add_parser("validate-build")
    validate.add_argument("--repository", required=True)
    validate.add_argument("--gamever", required=True)
    validate.add_argument("--source-sha", required=True)
    validate.add_argument("--mode", required=True)
    validate.add_argument("--default-ref", required=True)

    invalidate = commands.add_parser("invalidate-republish")
    invalidate.add_argument("--repo-root", default=".")
    invalidate.add_argument("--gamever", required=True)
    invalidate.add_argument("--source-sha", required=True)
    invalidate.add_argument("--bindir", default="bin")
    invalidate.add_argument("--allow-legacy-bootstrap", action="store_true")

    oldgamever = commands.add_parser("prepare-oldgamever")
    oldgamever.add_argument("--repo-root", default=".")
    oldgamever.add_argument("--gamever", required=True)
    oldgamever.add_argument("--bindir", default="bin")
    oldgamever.add_argument("--github-output")

    pending = commands.add_parser("check-pending")
    pending.add_argument("--staging-root", required=True)
    pending.add_argument("--gamever", required=True)
    pending.add_argument("--build-id", required=True)


def _add_staging_parsers(commands) -> None:
    stage = commands.add_parser("stage-build")
    stage.add_argument("--repo-root", default=".")
    stage.add_argument("--staging-root", required=True)
    stage.add_argument("--bin-source", required=True)
    stage.add_argument("--candidate", required=True)
    stage.add_argument("--repository", required=True)
    stage.add_argument("--output-branch", required=True)
    stage.add_argument("--gamever", required=True)
    stage.add_argument("--mode", required=True)
    stage.add_argument("--build-id", required=True)
    stage.add_argument("--source-sha", required=True)
    stage.add_argument("--workflow-run-url", required=True)
    stage.add_argument("--analysis-config", required=True)
    stage.add_argument("--gamedata-session", required=True)

    finalize = commands.add_parser("finalize-stage")
    finalize.add_argument("--repo-root", default=".")
    finalize.add_argument("--staging-root", required=True)
    finalize.add_argument("--gamever", required=True)
    finalize.add_argument("--build-id", required=True)
    finalize.add_argument("--pr-head-sha", required=True)

    index = commands.add_parser("write-pr-index")
    index.add_argument("--staging-root", required=True)
    index.add_argument("--pr-number", required=True, type=int)
    index.add_argument("--gamever", required=True)
    index.add_argument("--build-id", required=True)
    index.add_argument("--pr-head-sha", required=True)


def _add_verification_parsers(commands) -> None:
    verify_pr = commands.add_parser("verify-output-pr")
    verify_pr.add_argument("--repo-root", default=".")
    verify_pr.add_argument("--repository", required=True)
    verify_pr.add_argument("--head-repository", required=True)
    verify_pr.add_argument("--author", required=True)
    verify_pr.add_argument("--branch", required=True)
    verify_pr.add_argument("--base-sha", required=True)
    verify_pr.add_argument("--head-sha", required=True)

    promote = commands.add_parser("verify-promotion")
    promote.add_argument("--repo-root", default=".")
    promote.add_argument("--staging-root", required=True)
    promote.add_argument("--repository", required=True)
    promote.add_argument("--head-repository", required=True)
    promote.add_argument("--author", required=True)
    promote.add_argument("--branch", required=True)
    promote.add_argument("--base-branch", required=True)
    promote.add_argument("--default-branch", required=True)
    promote.add_argument("--pr-number", required=True, type=int)
    promote.add_argument("--event-head-sha", required=True)
    promote.add_argument("--merge-sha", required=True)
    promote.add_argument("--github-output")


def _add_promotion_parsers(commands) -> None:
    reconstruct = commands.add_parser("reconstruct")
    reconstruct.add_argument("--repo-root", default=".")
    reconstruct.add_argument("--stage-dir", required=True)
    reconstruct.add_argument("--gamever", required=True)

    bin_promote = commands.add_parser("promote-bin")
    bin_promote.add_argument("--persisted-root", required=True)
    bin_promote.add_argument("--stage-dir", required=True)
    bin_promote.add_argument("--gamever", required=True)
    bin_promote.add_argument("--build-id", required=True)

    metadata = commands.add_parser("write-release-metadata")
    metadata.add_argument("--manifest", required=True)
    metadata.add_argument("--output-dir", required=True)
    metadata.add_argument("--output-merge-sha", required=True)
    metadata.add_argument("--tag-sha", required=True)
    metadata.add_argument("--repository", required=True)
    metadata.add_argument("--asset", action="append", required=True)

    complete = commands.add_parser("finalize-promotion")
    complete.add_argument("--staging-root", required=True)
    complete.add_argument("--pr-number", required=True, type=int)
    complete.add_argument("--event-head-sha", required=True)
    complete.add_argument("--output-merge-sha", required=True)
    complete.add_argument("--release-provenance", required=True)

    completed = commands.add_parser("cleanup-completed")
    completed.add_argument("--staging-root", required=True)
    completed.add_argument("--persisted-root", required=True)
    completed.add_argument("--gamever", required=True)
    completed.add_argument("--build-id", required=True)

    list_records = commands.add_parser("list-completed")
    list_records.add_argument("--staging-root", required=True)

    legacy = commands.add_parser("migrate-legacy-completed")
    legacy.add_argument("--staging-root", required=True)
    legacy.add_argument("--persisted-root", required=True)
    legacy.add_argument("--gamever", required=True)
    legacy.add_argument("--build-id", required=True)
    legacy.add_argument("--release-provenance", required=True)
    legacy.add_argument("--expected-provenance-sha256", required=True)

    abandon = commands.add_parser("abandon-pending")
    abandon.add_argument("--staging-root", required=True)
    abandon.add_argument("--persisted-root", required=True)
    abandon.add_argument("--repository", required=True)
    abandon.add_argument("--output-branch", required=True)
    abandon.add_argument("--gamever", required=True)
    abandon.add_argument("--build-id", required=True)
    abandon.add_argument("--pr-number", required=True, type=int)
    abandon.add_argument("--event-head-sha", required=True)
    abandon.add_argument("--confirmation", required=True)
    abandon.add_argument("--reason", required=True)

    cleanup = commands.add_parser("cleanup-unmerged")
    cleanup.add_argument("--staging-root", required=True)
    cleanup.add_argument("--pr-number", required=True, type=int)
    cleanup.add_argument("--event-head-sha", required=True)

    incomplete = commands.add_parser("cleanup-incomplete")
    incomplete.add_argument("--staging-root", required=True)
    incomplete.add_argument("--gamever", required=True)
    incomplete.add_argument("--build-id", required=True)

    sync_bin = commands.add_parser("sync-accepted-bin")
    sync_bin.add_argument("--repo-root", default=".")
    sync_bin.add_argument("--persisted-root", required=True)
    sync_bin.add_argument("--gamever", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build, stage, verify, and promote release output")
    commands = parser.add_subparsers(dest="command", required=True)
    _add_build_parsers(commands)
    _add_staging_parsers(commands)
    _add_verification_parsers(commands)
    _add_promotion_parsers(commands)
    return parser


_UNHANDLED = object()


def _run_build(args) -> object:
    if args.command == "validate-build":
        return validate_build_input(
            repository=args.repository,
            gamever=args.gamever,
            source_sha=args.source_sha,
            mode=args.mode,
            default_ref=args.default_ref,
        )
    if args.command == "invalidate-republish":
        return invalidate_republish(
            repo_root=args.repo_root,
            gamever=args.gamever,
            source_sha=args.source_sha,
            bindir=args.bindir,
            allow_legacy_bootstrap=args.allow_legacy_bootstrap,
        )
    if args.command == "prepare-oldgamever":
        result = prepare_oldgamever_baseline(
            repo_root=args.repo_root,
            gamever=args.gamever,
            bindir=args.bindir,
        )
        write_github_output(args.github_output, {"oldgamever": result["oldgamever"]})
        return result
    if args.command == "check-pending":
        return assert_no_other_ready_build(args.staging_root, args.gamever, args.build_id)
    return _UNHANDLED


def _run_staging(args) -> object:
    if args.command == "stage-build":
        return stage_build(
            repo_root=args.repo_root,
            staging_root=args.staging_root,
            bin_source=args.bin_source,
            candidate=args.candidate,
            repository=args.repository,
            output_branch=args.output_branch,
            gamever=args.gamever,
            mode=args.mode,
            build_id=args.build_id,
            source_sha=args.source_sha,
            workflow_run_url=args.workflow_run_url,
            analysis_config=args.analysis_config,
            gamedata_session=args.gamedata_session,
        )
    if args.command == "finalize-stage":
        return finalize_stage(
            repo_root=args.repo_root,
            staging_root=args.staging_root,
            gamever=args.gamever,
            build_id=args.build_id,
            pr_head_sha=args.pr_head_sha,
        )
    if args.command == "write-pr-index":
        return str(
            write_pr_index(
                staging_root=args.staging_root,
                pr_number=args.pr_number,
                gamever=args.gamever,
                build_id=args.build_id,
                pr_head_sha=args.pr_head_sha,
            )
        )
    return _UNHANDLED


def _run_verification(args) -> object:
    if args.command == "verify-output-pr":
        return verify_output_pr(
            repo_root=args.repo_root,
            repository=args.repository,
            head_repository=args.head_repository,
            author=args.author,
            branch=args.branch,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
        )
    if args.command == "verify-promotion":
        result = verify_promotion(
            repo_root=args.repo_root,
            staging_root=args.staging_root,
            repository=args.repository,
            head_repository=args.head_repository,
            author=args.author,
            branch=args.branch,
            base_branch=args.base_branch,
            default_branch=args.default_branch,
            pr_number=args.pr_number,
            event_head_sha=args.event_head_sha,
            merge_sha=args.merge_sha,
        )
        write_github_output(
            args.github_output,
            {
                "gamever": result["gamever"],
                "build_id": result["build_id"],
                "mode": result["mode"],
                "stage_dir": result["stage_dir"],
            },
        )
        return result
    return _UNHANDLED


def _run_promotion(args) -> object:
    if args.command == "reconstruct":
        return str(reconstruct_workspace(args.repo_root, args.stage_dir, args.gamever))
    if args.command == "promote-bin":
        return promote_bin(
            persisted_root=args.persisted_root,
            stage_dir=args.stage_dir,
            gamever=args.gamever,
            build_id=args.build_id,
        )
    if args.command == "write-release-metadata":
        manifest = load_tracked_manifest(args.manifest)
        paths = write_release_metadata(
            output_dir=args.output_dir,
            manifest=manifest,
            output_merge_sha=args.output_merge_sha,
            tag_sha=args.tag_sha,
            repository=args.repository,
            assets=[Path(path) for path in args.asset],
        )
        return [str(path) for path in paths]
    if args.command == "finalize-promotion":
        return finalize_promotion(
            staging_root=args.staging_root,
            pr_number=args.pr_number,
            event_head_sha=args.event_head_sha,
            output_merge_sha=args.output_merge_sha,
            release_provenance=args.release_provenance,
        )
    if args.command == "cleanup-completed":
        return cleanup_completed(
            staging_root=args.staging_root,
            persisted_root=args.persisted_root,
            gamever=args.gamever,
            build_id=args.build_id,
        )
    if args.command == "list-completed":
        return list_completed(args.staging_root)
    if args.command == "migrate-legacy-completed":
        return migrate_legacy_completed(
            staging_root=args.staging_root,
            persisted_root=args.persisted_root,
            gamever=args.gamever,
            build_id=args.build_id,
            release_provenance=args.release_provenance,
            expected_provenance_sha256=args.expected_provenance_sha256,
        )
    if args.command == "abandon-pending":
        return abandon_pending(
            staging_root=args.staging_root,
            persisted_root=args.persisted_root,
            repository=args.repository,
            output_branch=args.output_branch,
            gamever=args.gamever,
            build_id=args.build_id,
            pr_number=args.pr_number,
            event_head_sha=args.event_head_sha,
            confirmation=args.confirmation,
            reason=args.reason,
        )
    if args.command == "cleanup-unmerged":
        return cleanup_unmerged(args.staging_root, args.pr_number, args.event_head_sha)
    if args.command == "cleanup-incomplete":
        return cleanup_incomplete(args.staging_root, args.gamever, args.build_id)
    if args.command == "sync-accepted-bin":
        return sync_accepted_bin(
            repo_root=args.repo_root,
            persisted_root=args.persisted_root,
            gamever=args.gamever,
        )
    return _UNHANDLED


def _run(args) -> object:
    for handler in (_run_build, _run_staging, _run_verification, _run_promotion):
        result = handler(args)
        if result is not _UNHANDLED:
            return result
    raise AssertionError(args.command)


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = _run(args)
    except ReleaseWorkflowError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if result is not None:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0
