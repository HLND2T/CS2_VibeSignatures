#!/usr/bin/env python3

import argparse
import traceback

from analysis_config import AnalysisConfigError, resolve_analysis_config
from gamesymbol_snapshot_lib.candidate import (
    CandidateContractError,
    CandidatePublicationError,
    build_candidate_snapshot,
    compare_snapshots,
    complete_candidate_step,
    guard_candidate,
    publish_candidate,
)
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError
from gamesymbol_store import CandidateChangedError, SymbolStoreError


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Build, compare, guard, and publish game-symbol candidates")
    parser.add_argument("-debug", action="store_true", help="Print tracebacks on errors")
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build")
    build.add_argument("-gamever", required=True)
    build.add_argument("-bindir", default="bin")
    build.add_argument("-artifactdir", default="bin_artifacts")
    build.add_argument("-configyaml", default=None, help="Analysis config path; defaults to configs/<GAMEVER>.yaml")
    build.add_argument("-output", required=True)
    build.add_argument("-session", required=True)
    build.add_argument(
        "-last-publish-time",
        help="Explicit UTC publication time (YYYY-MM-DDTHH:mm:ssZ); defaults to the current time",
    )

    compare = commands.add_parser("compare")
    compare.add_argument("-gamever", required=True)
    compare.add_argument("-candidate", required=True)
    compare.add_argument("-expected", required=True)
    compare.add_argument("-configyaml", default=None, help="Analysis config path; defaults to configs/<GAMEVER>.yaml")
    compare.add_argument("-session")

    for command in ("guard", "mark", "publish"):
        subparser = commands.add_parser(command)
        subparser.add_argument("-candidate", required=True)
        subparser.add_argument("-session", required=True)
        if command == "mark":
            subparser.add_argument("-step", choices=("gamedata", "cpp_tests"), required=True)
        if command == "publish":
            subparser.add_argument("-snapshot", required=True)
    return parser.parse_args(argv)


def _print_info(info) -> None:
    print(f"Game version: {info.game_version}")
    print(f"Snapshot schema: {info.snapshot_schema_version}")
    print(f"Config digest version: {info.config_digest_version}")
    print(f"File count: {info.file_count}")
    print(f"Config digest: {info.config_sha256}")
    print(f"Candidate SHA-256: {info.candidate_sha256}")
    print(f"Path: {info.path}")


def _run(args) -> None:
    if args.command == "build":
        args.configyaml = str(resolve_analysis_config(args.gamever, args.configyaml))
        print(f"Analysis config: {args.configyaml}")
        info = build_candidate_snapshot(
            game_version=args.gamever,
            bin_root=args.bindir,
            artifact_root=args.artifactdir,
            config_path=args.configyaml,
            output_path=args.output,
            session_path=args.session,
            last_publish_time=args.last_publish_time,
        )
        print("Candidate snapshot ready:")
        _print_info(info)
    elif args.command == "compare":
        args.configyaml = str(resolve_analysis_config(args.gamever, args.configyaml))
        print(f"Analysis config: {args.configyaml}")
        diff = compare_snapshots(
            actual_path=args.candidate,
            expected_path=args.expected,
            config_path=args.configyaml,
            expected_game_version=args.gamever,
            session_path=args.session,
        )
        print(f"Candidate matches expected snapshot: {diff.actual_sha256}")
    elif args.command == "guard":
        _print_info(guard_candidate(candidate_path=args.candidate, session_path=args.session))
    elif args.command == "mark":
        info = complete_candidate_step(
            candidate_path=args.candidate,
            session_path=args.session,
            step=args.step,
        )
        print(f"Candidate validation step completed: {args.step} ({info.candidate_sha256})")
    else:
        info = publish_candidate(
            candidate_path=args.candidate,
            session_path=args.session,
            destination=args.snapshot,
        )
        print(f"Published candidate bytes: {info.path} ({info.candidate_sha256})")


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        _run(args)
    except CandidatePublicationError as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 3
    except (CandidateChangedError, SnapshotMismatchError) as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 1
    except (AnalysisConfigError, CandidateContractError, SnapshotConfigError, SymbolStoreError) as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
