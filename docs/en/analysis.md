[Back to README](../../README.md) | [中文](../zh-CN/analysis.md)

# Initialize the latest game binaries

For a new checkout, use `SKILL: init-gamebin` to initialize the binaries for the latest game version listed in
`download.yaml` before running symbol analysis. Ask the agent explicitly:

```text
Use SKILL: init-gamebin
```

The skill resolves `latest` from the repository's version list, downloads or merges the matching binaries without overwriting existing files, and then restore symbol YAMLs. If no game version is specified, the skill lists the available entries and asks you to choose one.

## Analyze configured symbols

The Analyzer finds and generates signatures for symbols declared in `configs/<GAMEVER>.yaml`.

Command synopsis:

```bash
uv run ida_analyze_bin.py -gamever 14156 [-oldgamever=14155] [-configyaml=path/to/custom.yaml] [-modules=server] [-skill=find-CBaseEntity_vtable] [-platform=windows] [-agent=claude/codex/opencode/"claude.cmd"/"codex.cmd"/"opencode.cmd"] [-maxretry=3] [-vcall_finder=g_pNetworkMessages] [-llm_model=gpt-4o] [-llm_apikey=your-key] [-llm_baseurl=https://api.example.com/v1] [-llm_temperature=0.2] [-llm_effort=medium] [-llm_fake_as=codex] [-require_warm_idb] [-rename] [-debug]
```

Optional LLM parameters:

- `-llm_apikey`: required when an LLM-backed workflow is enabled, including `vcall_finder` aggregation and `LLM_DECOMPILE`.
- `-llm_baseurl`: optional custom compatible base URL; required with `-llm_fake_as=codex`.
- `-llm_model`: optional; defaults to `gpt-4o`.
- `-llm_temperature`: optional; sent only when explicitly set.
- `-llm_effort`: optional; defaults to `medium`; supports `none|minimal|low|medium|high|xhigh`.
- `-llm_fake_as`: optional; `codex` switches to direct `/v1/responses` SSE transport.
- Environment fallbacks: `CS2VIBE_LLM_APIKEY`, `CS2VIBE_LLM_BASEURL`, `CS2VIBE_LLM_MODEL`, `CS2VIBE_LLM_TEMPERATURE`, `CS2VIBE_LLM_EFFORT`, and `CS2VIBE_LLM_FAKE_AS`.
- LLM workflows do not read `OPENAI_API_KEY`, `OPENAI_API_BASE`, or `OPENAI_API_MODEL`.

Analyzer behavior:

- Old signatures from `bin/{previous_gamever}/{module}/{symbol}.{platform}.yaml` are tried through MCP before Agent skills run. Successful reuse does not consume Agent tokens.
- `-agent="claude.cmd"` selects the Claude CLI installed through npm on Windows.
- `-agent="opencode.cmd"` selects the npm-installed OpenCode CLI on Windows. OpenCode loads `.opencode/agents/sig-finder.md` and runs skills non-interactively.
- Prefer programmatic preprocessors, then `LLM_DECOMPILE` preprocessors, then Agent skills.
- `-skill=<exact-name>` only runs an exact skill name within the active `-modules` filter. It does not run prerequisites automatically; required `expected_input` artifacts must already exist.
- `-rename` runs rename/comment post-processing over existing expected-output YAML files.
- `-require_warm_idb` requires a pre-existing `.i64`/`.idb`. Missing databases or binary-identity verification failures stop the binary without deleting the database or rebuilding it through inline auto-analysis. PR and release CI always enable this mode after restoring a published cache generation.

Process reporting, the Redis-backed Scheduler, and the progress dashboard are documented in [Process reporting, scheduling, and dashboard](process-monitoring.md).

## `vcall_finder`

- `-vcall_finder=g_pNetworkMessages` explicitly selects one or more comma-separated object names. It requires an explicit `-modules=...`; every selected object is processed for every selected module, and `*` is not supported.
- `vcall_finder` objects are not registered in `configs/<GAMEVER>.yaml`. If an object is absent from every selected module and platform, the command fails instead of aggregating stale detail files.
- The script exports full disassembly and pseudocode for each referencing function into `vcall_finder/{gamever}/{object_name}/{module}/{platform}/`, then runs LLM aggregation after all module/platform IDA work finishes.
- If a detail YAML already has a top-level `found_vcall`, that function skips the LLM call and reuses the cached result. A successful response immediately writes `found_vcall: [...]` or `found_vcall: []` back to the detail YAML.
- `vcall_finder/{gamever}/{object_name}.txt` is an appended YAML document stream. Each record directly contains `insn_va`, `insn_disasm`, and `vfunc_offset` without a nested `found_vcall` wrapper.

Example:

```bash
uv run ida_analyze_bin.py -gamever=14141 -modules=networksystem -platform=windows -vcall_finder=g_pNetworkMessages -llm_model=gpt-5.4 -llm_apikey=your-key -llm_effort=high -llm_fake_as=codex -llm_baseurl=http://127.0.0.1:8080/v1
```

Example outputs:

- `vcall_finder/14141/g_pNetworkMessages/networksystem/windows/sub_140123450.yaml`
- `vcall_finder/14141/g_pNetworkMessages.txt`

## IDA preprocessor string setup

`CS2VIBE_STRING_MIN_LENGTH` controls optional IDA string-list setup for preprocessor string enumeration only:

- Unset or empty: do not call `idautils.Strings.setup`; use the IDB current string-list state.
- Integer `>=1`: call `idautils.Strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=<value>)` when the current IDB has not already been set up with the same parameters.
- Non-integer or values `<1`: fall back to `4` and use the same IDB-level setup guard.
- Setup state is stored per IDB; changing the effective `minlen` triggers setup again.
- This is not an LLM parameter.

For `LLM_DECOMPILE` inputs, continue with [Reference YAML for `LLM_DECOMPILE`](reference-yaml.md). For immutable candidate creation and downstream validation, continue with [Snapshots and gamedata](snapshot-and-gamedata.md).
