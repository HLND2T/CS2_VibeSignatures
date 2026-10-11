---
title: Windows checkouts need core.longpaths before checkout
type: guide
permalink: cs2-vibesignatures/lessons/windows-checkouts-need-core-longpaths
tags:
- cs2vibesignatures
- ci
- windows
- checkout
- max-path
---

# Windows checkouts need core.longpaths before checkout

## Symptom
A `windows-latest` job fails inside `actions/checkout` with
`error: unable to create file <path>: Filename too long`, which skips every later step
(uv setup, artifact bind/download, MSVC init). The same job's Linux shard passes.

## Root cause
Windows Git refuses paths beyond the 260-character `MAX_PATH` limit unless `core.longpaths` is true, and this
repository never sets it. The repository tracks a **210-character** longest path
(`ida_preprocessor_scripts/find-CCSPlayerController_PlayerForceTeamThink-AND-...-InventoryUpdateThink-linux.py`),
so a checkout only fits at the workspace root:

| checkout | target | longest absolute path |
|---|---|---|
| workspace root | `D:\a\<Repo>\<Repo>` (42) | 253 chars — fits by **7** |
| `.ci-tools` (tooling copy) | root + 10 | **263 chars — over** |

A 7-character margin means shortening checkout paths is not a real mitigation: the next long artifact name
breaks it again.

## Correct approach
Enable it **before any checkout**, for every Windows leg:
```yaml
- name: Enable git long paths
  if: runner.os == 'Windows'
  shell: pwsh
  run: |
    git config --system core.longpaths true
    if ($LASTEXITCODE -ne 0) { throw 'Unable to enable git long paths.' }
```
`--system` needs elevation, which is why this lives in a conditional step on a hosted runner rather than a
repo-level config file. A repo config cannot supply it — `git config --system` is machine-local.

## Latent-failure trap (why this hid for months)
`cpp-validation` is gated on `validate`. Every recent run had `validate` failing upstream, so the Windows leg
was **always skipped** and the overflow never executed. Fixing the upstream failure is what first exposed it —
expect other gated-on-green jobs to surface their own latent breakage the same way.

## Audit result
Only `cpp-validation.yml` (`windows-latest` matrix) runs on Windows. Every `[self-hosted, cross-platform]` job
is **Linux** (confirm from job logs: `/home/<user>/actions-runner`). In `bootstrap-new-gamever-artifacts.yml`,
`warmup-idb.yml`, and `source-artifact-warmup-bridge.yml` the "windows" matches are the `matrix.platform`
**string value**, not an OS — do not misread them as Windows legs.

## Verification
The Windows shard must actually execute to prove the fix; a plan that classifies the change as `light` mode
skips `validate-full` entirely, so verify from a PR that triggers **`full`** mode. Log signature of success:
`Updating files: 100% (<n>/<n>) ... done` on **both** checkouts.

## Scope
Any `windows-latest` (or Windows self-hosted) job that checks the tree out — currently `cpp-validation.yml`
only, both the `inputs.source_sha` and `github.workflow_sha` checkouts.

## See also
[[ci-windows-long-paths]], [[Warm IDB lease identity must not encode the run attempt]], [[pr-self-runner]].
