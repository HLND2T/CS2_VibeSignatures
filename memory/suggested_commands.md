---
title: suggested_commands
type: note
permalink: cs2-vibesignatures/suggested-commands
---

# Suggested commands
Prerequisites: install or prepare `uv`, DepotDownloader, IDA/idalib, ida-pro-mcp, Clang/LLVM, and the configured Agent/LLM tools.

Prepare binaries (disposable cache only):

```powershell
uv run download_depot.py -tag <gamever>
uv run copy_depot_bin.py -gamever <gamever> -platform all-platform
```

Analyze and write canonical source-owned artifacts:

```powershell
uv run ida_analyze_bin.py -gamever <gamever> -artifactdir bin_artifacts -oldartifactdir bin_artifacts -oldgamever <previous_gamever> -debug
uv run python bin_artifact_contract.py -gamever <gamever>
```

For tests that must force producers without touching expected Git bytes, seed a checkout-external artifact root and pass it with `-artifactdir`; keep tracked `bin_artifacts` as `-oldartifactdir`.

Generate an LLM_DECOMPILE reference (binary remains under `bin/`, predecessor YAML resolves from `bin_artifacts/`):

```powershell
uv run generate_reference_yaml.py -gamever <gamever> -module <module> -platform <platform> -func_name <func_name> -auto_start_mcp -binary bin/<gamever>/<module>/<binary_name>
```

Build one release-local downstream candidate set:

```powershell
uv run gamesymbol_candidate.py build -gamever <gamever> -bindir bin -artifactdir bin_artifacts -configyaml configs/<gamever>.yaml -output <temp/candidate.yaml> -session <temp/candidate.session.json>
uv run gamedata_candidate.py build -gamever <gamever> -build-id local-1 -snapshot <temp/candidate.yaml> -configyaml configs/<gamever>.yaml -candidate-root <temp/gamedata-candidate> -session <temp/gamedata.session.json>
uv run gamedata_candidate.py guard -session <temp/gamedata.session.json>
uv run run_cpp_tests.py -gamever <gamever> -configyaml configs/<gamever>.yaml -snapshot <temp/candidate.yaml>
```

Source PRs stage source/config/reference changes and the computed `bin_artifacts` closure. Never stage `gamesymbols/`, `gamedata/`, `release-manifests/`, or `bin/**/*.yaml`.

Primary completion gates:

```powershell
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
uv run python tests/run_test_suite.py release-integration -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
git diff --check
```