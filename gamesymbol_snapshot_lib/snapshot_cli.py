import argparse
import json
import traceback

from analysis_config import AnalysisConfigError, resolve_analysis_config
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError, SnapshotUntrustedError
from gamesymbol_snapshot_lib.operations import (
    check_snapshot_contract,
    migrate_snapshot,
    pack_snapshot,
    restore_snapshot,
    verify_snapshot,
)


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-gamever", required=True, help="Game version to snapshot")
    parser.add_argument("-bindir", default="bin", help="Binary workspace root")
    parser.add_argument(
        "-artifactdir",
        default="bin_artifacts",
        help="Per-symbol artifact workspace root (default: bin_artifacts)",
    )
    parser.add_argument(
        "-configyaml",
        default=None,
        help="Analysis config path; defaults to configs/<GAMEVER>.yaml",
    )
    parser.add_argument("-snapshot", help="Snapshot path; defaults to gamesymbols/<GAMEVER>.yaml")
    parser.add_argument("-debug", action="store_true", help="Print tracebacks on errors")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Pack, restore, verify, check, or migrate game-symbol snapshots")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("pack", "restore", "verify", "check-contract", "migrate"):
        subparser = commands.add_parser(command)
        _add_common_arguments(subparser)
        if command == "restore":
            subparser.add_argument("-replace", action="store_true", help="Replace only YAML files under the game root")
        elif command == "check-contract":
            subparser.add_argument("-json", action="store_true", help="Emit one machine-readable JSON result")
        elif command == "migrate":
            subparser.add_argument("-output", help="Output path; defaults to replacing -snapshot atomically")
            subparser.add_argument(
                "-sourceconfigyaml",
                help="Optional historical config used only to validate the schema-1 source",
            )
            subparser.add_argument(
                "-last-publish-time",
                help="Explicit UTC historical publication time (YYYY-MM-DDTHH:mm:ssZ)",
            )
    return parser.parse_args(argv)


def _run(args) -> None:
    args.configyaml = str(resolve_analysis_config(args.gamever, args.configyaml))
    if args.command != "check-contract" or not args.json:
        print(f"Analysis config: {args.configyaml}")
    common = (args.gamever, args.bindir, args.configyaml, args.snapshot)
    if args.command == "pack":
        data = pack_snapshot(*common, artifactdir=args.artifactdir)
        print(f"Packed {args.snapshot or f'gamesymbols/{args.gamever}.yaml'} ({len(data)} bytes)")
    elif args.command == "restore":
        restore_snapshot(*common, replace=args.replace, artifactdir=args.artifactdir)
        print(f"Restored game-symbol snapshot for {args.gamever}")
    elif args.command == "verify":
        verify_snapshot(*common, artifactdir=args.artifactdir)
        print(f"Verified game-symbol snapshot for {args.gamever}")
    elif args.command == "check-contract":
        context = check_snapshot_contract(*common, artifactdir=args.artifactdir)
        result = {
            "trusted": True,
            "reason": "trusted",
            "schema_version": context.document["schema_version"],
            "config_digest_version": context.contract.config_digest_version,
            "analysis_output_contract_version": context.contract.analysis_output_contract_version,
        }
        print(json.dumps(result, sort_keys=True) if args.json else "Snapshot contract is trusted")
    else:
        data = migrate_snapshot(
            *common,
            output_path=args.output,
            source_config_path=args.sourceconfigyaml,
            last_publish_time=args.last_publish_time,
            artifactdir=args.artifactdir,
        )
        print(f"Migrated {args.output or args.snapshot or f'gamesymbols/{args.gamever}.yaml'} ({len(data)} bytes)")


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        _run(args)
    except SnapshotUntrustedError as exc:
        result = {"trusted": False, "reason": exc.reason, "detail": str(exc)}
        print(json.dumps(result, sort_keys=True) if getattr(args, "json", False) else f"Untrusted: {exc.reason}: {exc}")
        if args.debug:
            traceback.print_exc()
        return 3
    except SnapshotMismatchError as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 1
    except (AnalysisConfigError, SnapshotConfigError) as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 2
    return 0
