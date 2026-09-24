# Parallel platform analysis

PR and Release rebuilds pass `-parallel_platforms <fresh-log-directory>` to
`ida_analyze_bin.py`. The coordinator validates the original force-all/selected
root and launches two CLI workers with `-platform windows` and `-platform linux`
in the same Windows runner job. Each platform retains the existing module and
producer ordering. Bootstrap reuse and tracked-artifact Release paths still skip
analysis.

Each worker has a separate artifact root, seeded with the same inherited files
for selected execution. The coordinator rejects shared platform outputs or
binary paths before launch. After both workers exit, it checks exact task
coverage, run/config identity, unchanged inherited bytes and output ownership,
then composes the full artifact tree. The existing force-all/selected report
builders perform full producer-group and inventory validation; downstream
verifiers consume the unchanged report format and path. Internal `worker.json`
records cannot substitute for a full execution report.

A failed platform does not cancel its sibling. Any process, evidence, merge or
full-report failure fails the analysis step, blocking subsequent verification,
candidate building and publication. A platform with no selected tasks still
contributes an empty execution record.

Detailed stdout/stderr go to `windows.log` and `linux.log`; the console prints
only coordinator configuration and summaries. Both workflows upload these logs,
`summary.json` and per-platform `worker.json` on success or failure. Summary data
includes exit codes, elapsed times and merge/full-report errors. Forced runner
shutdown may prevent artifact upload, but the files remain in the runner temp
directory until normal runner cleanup.

On Windows, each worker and all its descendants run in an owned kill-on-close
Job, using the existing parent-watching launcher. Cancellation or coordinator
death reaps the analyzer, Agent and IDA descendants. The launcher records the
child exit code before closing its own Job, because that close can terminate
the launcher before its normal exit code is returned.

MCP port allocation through listener startup is serialized between sibling
workers. Codex/OpenCode fallback retry sequences are also serialized to avoid
cross-platform reuse of their "latest session"; Claude uses explicit session
IDs and remains concurrent. These locks affect only a parallel run and do not
change ordinary serial CLI execution.

Validation uses real subprocess overlap/failure tests, Windows detached-process
cleanup tests, and CLI worker fixtures that substitute the IDA boundary while
exercising real argument parsing, artifact isolation and report construction.
Full IDA/LLM runtime compatibility and elapsed-time improvement require a real
self-hosted workflow run.
