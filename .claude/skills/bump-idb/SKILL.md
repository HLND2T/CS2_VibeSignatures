---
name: bump-idb
description: |
  Bump the project to the latest game version declared in `download.yaml`: update
  `.env` -> `CS2VIBE_GAMEVER` if it lags behind, refuse the bump when any IDA
  instance has the new gamever's IDB open (an `*.id0` file exists), and otherwise
  run `uv run ida_analyze_bin.py -gamever <LATEST> -rename -debug` to rebuild the
  per-version YAMLs and rename symbols in the IDBs. Use when the user says
  "bump idb", "update gamever", or "sync to latest gamever".
disable-model-invocation: true
---

# Bump IDB to Latest Game Version

End-to-end workflow to advance the project to the newest `download.yaml` tag and
re-analyze every binary against the freshly-loaded IDBs. This skill is purely
mechanical — no judgment calls, do not skip steps, and **abort immediately** with a
user-visible error if any step fails its precondition.

## When to Use

- The user explicitly asks to "bump idb", "bump gamever", "update to latest
  gamever", or similar.
- A new tag has been added to `download.yaml` and the project must be brought up
  to it.

## Inputs

None. Everything is read from the repo state:

- `download.yaml` — last `tag:` entry under `downloads:` is the latest gamever.
- `.env` — current `CS2VIBE_GAMEVER=` line.
- `bin/{LATEST_GAMEVER}/*/` — used to detect open IDBs.

## Steps

### Step 1 — Determine LATEST_GAMEVER from download.yaml

Read every `- tag: "<value>"` line under `downloads:` in `download.yaml`. The
**last** one in document order is the latest. Strip the surrounding quotes.

```bash
LATEST_GAMEVER=$(grep -E '^\s*-\s+tag:' download.yaml | tail -1 | sed -E 's/.*tag:\s*"([^"]+)".*/\1/')
echo "LATEST_GAMEVER=$LATEST_GAMEVER"
```

If `LATEST_GAMEVER` is empty, abort and tell the user that `download.yaml` has no
`tag:` entries.

### Step 2 — Read current GAMEVER from .env

```bash
CURRENT_GAMEVER=$(grep -E '^CS2VIBE_GAMEVER=' .env | sed -E 's/^CS2VIBE_GAMEVER=//')
echo "CURRENT_GAMEVER=$CURRENT_GAMEVER"
```

If `.env` does not contain a `CS2VIBE_GAMEVER=` line, treat `CURRENT_GAMEVER` as
empty and proceed to Step 3 (the bump will create the line).

### Step 3 — Bump .env if needed

If `CURRENT_GAMEVER == LATEST_GAMEVER`, skip this step and report
"GAMEVER already at latest (`<value>`)."

Otherwise, rewrite the `CS2VIBE_GAMEVER=` line in-place. Use the `Edit` tool with
exact string match — do NOT use a global `sed -i` that could clobber other
variables. If the line is missing entirely, append it.

Report the change to the user:
`Bumped CS2VIBE_GAMEVER: <old> -> <new>`

### Step 4 — Check for open IDBs (`*.id0` files)

An `*.id0` file inside `bin/{LATEST_GAMEVER}/<module>/` means IDA Pro currently
has that IDB open. Bumping while an IDB is open will corrupt the database, so we
**refuse** the bump in that case.

```bash
LOCK_FILES=$(ls bin/$LATEST_GAMEVER/*/*.id0 2>/dev/null)
```

If `LOCK_FILES` is non-empty, abort with a user-visible error like:

> Cannot bump IDB: detected open IDA instance(s) for gamever
> `<LATEST_GAMEVER>`. The following `*.id0` lock file(s) exist:
>
> - `<path1>`
> - `<path2>`
>
> Close the IDA window(s) holding these IDBs and re-run the bump.

Do not continue to Step 5.

> **Note:** It is fine if `bin/{LATEST_GAMEVER}/` does not exist yet — that just
> means no IDBs have ever been opened for this gamever. The glob simply produces
> no matches.

### Step 5 — Run ida_analyze_bin.py

Run the analyzer for the newly-bumped gamever, redirecting all output to a log
file so the conversation isn't flooded:

```bash
uv run ida_analyze_bin.py -gamever $LATEST_GAMEVER -rename -debug >> /tmp/bump_idb_output.log 2>&1
```

**Important:**
- Always pass `-gamever $LATEST_GAMEVER` explicitly, never rely on env-var
  resolution — at this point `.env` was just rewritten and the new value may not
  yet be exported in the current shell.
- The `>>` (append) operator is intentional: it lets the user inspect prior runs.
  If you want a fresh log, truncate the file first with `: > /tmp/bump_idb_output.log`.
- **DO NOT set a timeout.** This command routinely runs longer than 10 minutes
  (the Bash tool's maximum timeout). Run it in the background with
  `run_in_background: true` and wait for the completion notification before
  proceeding to Step 6. Polling the log mid-run is unnecessary — the harness
  notifies you when the task finishes.

### Step 6 — Report the outcome

**On exit code 0:**

Report success to the user, including the gamever and a one-line summary lifted
from the end of `/tmp/bump_idb_output.log` (typically a `Summary: Total=..,
Passed=.., Failed=..` line):

```bash
tail -20 /tmp/bump_idb_output.log
```

Example success message:

> Bump complete: `CS2VIBE_GAMEVER` is now `14164`. Analyzer finished with 0
> failures. Full log: `/tmp/bump_idb_output.log`.

**On non-zero exit code:**

Do NOT claim success. Read the tail of the log and surface the actual failure to
the user:

```bash
tail -60 /tmp/bump_idb_output.log
```

If a meaningful error block isn't visible in the tail, grep for `Error|Failed|
Traceback` to locate the failure:

```bash
grep -nE 'Error|Failed|Traceback' /tmp/bump_idb_output.log | tail -20
```

Present the relevant excerpt verbatim and tell the user where the full log lives
(`/tmp/bump_idb_output.log`). Do not attempt to "fix" the failure inside this
skill — that is out of scope. The user will decide how to proceed.

## Checklist

- [ ] `LATEST_GAMEVER` derived from the **last** `- tag:` entry in
      `download.yaml`.
- [ ] `.env` `CS2VIBE_GAMEVER=` line edited only if it differs from
      `LATEST_GAMEVER`; other variables in `.env` left untouched.
- [ ] `bin/{LATEST_GAMEVER}/*/*.id0` check performed AFTER the env bump (so the
      user sees "bumped but blocked" rather than a silent no-op).
- [ ] If any `*.id0` lock exists, skill aborts with the full list of lock paths
      and does NOT run `ida_analyze_bin.py`.
- [ ] `ida_analyze_bin.py` invoked with explicit `-gamever $LATEST_GAMEVER
      -rename -debug` and output appended to `/tmp/bump_idb_output.log`.
- [ ] Exit code checked; success and failure paths produce distinct, accurate
      user-facing reports.
