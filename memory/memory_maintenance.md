---
title: memory_maintenance
type: note
permalink: cs2-vibesignatures/memory-maintenance
---

# Memory Maintenance

## Discovery Model

- Core principle: progressive discovery through references, building a graph of notes.
- Start from `[[core]]` as the top-level entry point (graph root).
  It references other notes covering major project domains; those in turn reference even more specific notes, and so on.
  The depth of the graph depends on the project complexity.
- Use topics/folders to group related notes (e.g. modules or topics like debugging, architecture).
- Link notes with `[[note_title]]` wikilinks; Basic Memory indexes them as relations.
  The surrounding text must clearly indicate when to read the note / which content to expect —
  more precise guidance than the note title alone.
- Notes themselves should not say when to read them; that is the responsibility of the referring note.

## Style

Dense agent notes, not prose docs. Prefer invariants, terse bullets.
Avoid obvious context, rationale, and examples unless they prevent likely mistakes.
Keep guidance durable and generalizable, not task-local.

## Add/update threshold

Add or update notes only with stable, non-obvious project conventions that avoid complex rediscovery in the future.
Do not add: quick-read facts; generic language/framework knowledge; one-off task notes; volatile line-level details; behavior likely to change soon.

## Maintenance Actions

- Prefer Basic Memory MCP tools (`search_notes` / `read_note` / `write_note` / `edit_note`) for project knowledge.
- Check sync health with `basic-memory status` / `basic-memory doctor`.
- Note files live in `memory/` (markdown with YAML frontmatter `title`/`type`/`permalink`), tracked in git.
  Local runtime data (`memory.db`, `config.json`) stays in `~/.basic-memory/` and is gitignored.
