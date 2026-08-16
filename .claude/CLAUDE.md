# CLAUDE.md

This file provides guidance and important rules working with code in this repository.

## When coding / building plan

- Use a progressive disclosure approach for agent coding in this repository: start from high-level information in the Basic Memory knowledge base, and only locate/read specific files or symbols when necessary to avoid expanding too much context at once.

#### Basic Memory knowledge base (Keep context clean)

- Notes live in `memory/` (markdown with YAML frontmatter: `title`/`type`/`permalink`), tracked in git.
- Basic Memory is registered as MCP server `basic-memory`, pinned to the `cs2-vibesignatures` project (`--project cs2-vibesignatures` via project-level `.mcp.json`).
- Prefer Basic Memory MCP tools (`search_notes` / `read_note` / `write_note` / `edit_note`) for project knowledge.

#### When Notes Are Insufficient (On-Demand Querying and Reading)

- Check `README.md`