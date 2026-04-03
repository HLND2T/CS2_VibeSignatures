# copy_depot_bin

## Overview
Copies CS2 binaries from a local Steam depot into the repository's versioned `bin/` layout based on module entries in `config.yaml`, so later analysis steps can work with locally extracted binaries instead of downloaded ones.

## Responsibilities
- Parse CLI arguments for game version, output directory, platform filter, depot root, and config path.
- Read `config.yaml` and extract module metadata needed for copying.
- Resolve source paths inside the local depot for Windows and Linux binaries.
- Copy binaries into `bin/<gamever>/<module>/<filename>` while creating parent directories as needed.
- Skip existing targets, count success/failure totals, and return a non-zero exit code when any copy fails.

## Files Involved (no line numbers)
- copy_depot_bin.py
- config.yaml
- bin/<gamever>/<module>/<binary>
- <depotdir>/<platform>/<configured module path>
- ida_analyze_bin.py

## Architecture
The script is a single-pass CLI pipeline:
```
parse_args
  -> validate config path and depot directory
  -> parse_config (load modules with name/path_windows/path_linux)
  -> for each module
      -> process_module
          -> choose platform(s)
          -> build_source_path(depotdir/platform/configured path)
          -> copy_file(source, bin/gamever/module/filename)
  -> print summary and decide exit code
```
`process_module` owns platform filtering, target path assembly, existing-file skipping, source existence checks, and per-module success/failure counting. `copy_file` creates parent directories and uses `shutil.copy2` so copied binaries keep source metadata. The generated target layout matches the binary path convention used later by `ida_analyze_bin.py`.

## Dependencies
- PyYAML (`yaml.safe_load`) for reading `config.yaml`
- Python standard library: `argparse`, `os`, `shutil`, `sys`, `pathlib`
- Local filesystem access for reading depot files and writing into `bin/`
- `config.yaml` module fields: `name`, `path_windows`, `path_linux`
- Local depot layout rooted at `<depotdir>/<platform>/...`

## Notes
- If `-platform` is omitted, the script attempts both `windows` and `linux`; missing `path_<platform>` entries are skipped without being counted as failures.
- Existing target files are skipped and counted as successful work.
- Missing source binaries in the depot are counted as failures and will cause exit code `1` after the summary.
- Modules without `name` are skipped with a warning during config parsing.
- Because the script preserves the same `bin/<gamever>/<module>/<filename>` layout as the download workflow, it can serve as an offline/local-depot replacement for populating binaries before analysis.

## Callers (optional)
- Direct CLI invocation: `python copy_depot_bin.py -gamever=<version> [-bindir=bin] [-platform=windows|linux] [-depotdir "path/to/cs2_depot"]`
