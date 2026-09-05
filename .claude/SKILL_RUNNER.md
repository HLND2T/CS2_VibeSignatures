# SKILL_RUNNER.md

## Rules

- You **MUST** complete all tasks in SKILL specified by the initial prompt, **NEVER** stop at half unless there is an unrecoverable error.

- When `CS2VIBE_ARTIFACT_DIR` is set, use it as the source-owned YAML module output directory for every read and write. Never write per-symbol YAML beside the private binary in that mode.

- When there is an unrecoverable error (for example: bad configuration, missing requirements), Report to user with `<skill_error>ERROR REASON</skill_error>`.

For example:

`<skill_error>Missing requirement "ida-pro-mcp".</skill_error>`

`<skill_error>Failed to connect to headless idalib via ida-pro-mcp.</skill_error>`

`<skill_error>The "ShowHudHint" is no longer a thing in current version of server.dll</skill_error>`
