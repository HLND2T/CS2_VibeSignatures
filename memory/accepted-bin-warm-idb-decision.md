---
title: accepted-bin-warm-idb-decision
type: decision
permalink: cs2-vibesignatures/memory/accepted-bin-warm-idb-decision
tags:
- release
- ci-cd
- storage
- decision
---

# Keep Accepted Bin: warm IDB cache vs accepted bin (2026-08-22)

## Decision

Keep `PERSISTED_WORKSPACE/bin/<GAMEVER>` (accepted bin) as-is. Do NOT de-duplicate it against the warm IDB cache, and do NOT move gamebin to GitHub artifacts. Removing accepted bin would force every warmup/analysis run to re-download the current-version binaries (from Release asset or depot) and re-fetch the oldgamever baseline from the previous version's Release — extra download bandwidth we are not willing to pay.

## Context / trigger

`build-on-self-runner` now runs the required reusable `warmup-idb` job before `build`: it restores an immutable idb-cache generation and analyzes with `-require_warm_idb`. This re-opened the question of storage redundancy in the release lifecycle.

## Analysis (useful conclusions)

### Where the current-version binaries live (4 copies)
warm generation, accepted bin, staged bin, GitHub Release `gamebin-<gamever>.7z`. The payload duplication is real, but the stores' *functions* are not redundant.

### warm IDB cache vs accepted bin
| dimension | warm IDB cache | accepted bin |
|---|---|---|
| scope | current version only | all released versions |
| lifecycle | prunable (3 newest + READY, others after 7d) | not auto-pruned |
| payload | binary + `.i64` atomically (key = binary hash) | binaries only, no `.i64` |
| function | saves IDA warmup (expensive, recomputable) | cross-version oldgamever baseline + identity anchor |

- Warm cache MUST carry binaries with `.i64`: an `.i64` is only valid for the exact bytes it was built against; restore does byte-identity verification. Atomic identity contract, not accidental duplication.
- oldgamever baseline needs previous-version binaries under `bin/<oldgamever>`; warm cache structurally cannot serve this (pruned, per-version, few generations).

### Stripping staged gamebin (feasible but low value)
- Staged bin has three consumers: promote-bin transaction source, release-asset source (`reconstruct_workspace`), and snapshot↔binary hash anchor.
- warmup's `sync-accepted-bin` already mirrors identical bytes into accepted bin, so staged bin is a third copy — technically removable (staging keeps only the hash manifest).
- Low value: the disk hog is idb-cache `.i64`, not staged bin. If ever done: `stage_build` stops copytree; `promote_bin` verifies accepted bin; `reconstruct_workspace` restores from accepted bin.

### Moving `promote` to GitHub-hosted runners (boundary)
- Movable (byte-consumption + GitHub API): verify / reconstruct / create-archives / publish-release.
- NOT movable (must write PERSISTED_WORKSPACE): promote-bin / finalize-promotion / cleanup-completed. Reason: `os.replace` directory swaps and msvcrt/fcntl file locks are same-machine OS semantics.
- Resulting shape: Job A (hosted, bytes+API) + Job B (self-hosted thin, persisted-state transactions).
- Full migration requires accepted bin + release audit state to stop being local-load-bearing (Release assets + git-backed state) — rejected here due to the download-bandwidth cost.

### Why state lives on the local runner (for future reference)
- Hard OS constraints: atomic tree swaps + file locks are same-filesystem only.
- accepted bin consumers: build `prepare-workspace` robocopy, oldgamever baseline, warmup `sync-accepted-bin` restore source, `invalidate-republish`, promote-bin verification target.
- release-staging ledger: pr-index (PR→build identity), PROMOTION_* markers (crash recovery), completed/ (idempotent cleanup + audit), locks.
- Convention-only parts that could move later: audit records (git-backed), accepted bin as warmup restore source.

## Constraints

- Binaries are immutable per GAMEVER; warm cache key is binary-content based, so warm hits do not depend on a local accepted bin copy.
- Cross-version baseline genuinely needs previous binaries locally; that is accepted bin's load-bearing role.

## Revisit triggers

Disk pressure from idb-cache, or changed bandwidth/storage costs, may reopen the de-dup decision.

## See also

[[build-on-self-runner]], [[warmup_idb]], [[release-staging]], [[promote-release-after-output-merge]]