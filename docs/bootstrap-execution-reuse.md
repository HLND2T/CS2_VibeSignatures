# Bootstrap execution reuse

The PR full-validation worker probes for an existing new-GAMEVER bootstrap before
starting IDA warmup. The trusted planner still emits `full`, and the worker still
has to succeed for the required check. Existing-version changes use normal
validation.

`bootstrap_reuse.py probe` runs on a hosted runner using the immutable base's
verification code. Commit trailers only locate a possible run. The probe checks
the allowlisted repository, workflow, event, source head, run attempt, successful
candidate job, and successful hosted verification/commit preparation steps. The
publisher's final push or overall run may have failed. Both downloaded ZIPs are
checked against GitHub's artifact digests; their original plan, candidate manifest,
and force-all report are verified again.

Reuse requires an artifact-only direct child of the original source head in the
current head's ancestry. Its complete artifact tree must equal the current
prospective Git tree and candidate inventory. Config, binary lock, prior baseline,
producer groups/nodes and their fingerprints must match. Unknown source changes
fall back to rebuilding. Explicitly unrelated documentation, tests, downstream
and publication files may change. Bootstrap failure diagnostics and run-scoping
of existing local evidence paths are ignored when comparing that workflow;
producer commands, flags and other workflow changes remain significant.

On a hit, a same-run Actions artifact carries the evidence and a receipt bound to
the current plan and merge tree. The validation worker independently rechecks it,
materializes exact Git blobs outside the checkout, and skips IDA warmup, restore
and producer execution. Binary lock verification, snapshot/gamedata generation,
C++ ABI validation and the separate repository test job still run on the current
tree. A worker-side mismatch fails the job; it cannot silently accept a stale
hosted receipt. Release rebuild behavior is unchanged.

Missing, expired, incompatible or unauthenticated evidence makes the hosted probe
return a miss and use the existing full-validation path. Evidence retention is
seven days. No new persistent artifact truth or Git-tracked attestation is added.

Validation includes a replay of PR #957: bootstrap run `34430170553`, publication
`666d4a5983368d476b687000b6d27ddc2d777c18`, and the prospective merge commit
`4f7e394861f3007bfed176b6385ce85e00c59a84` from run `34440618235`.
