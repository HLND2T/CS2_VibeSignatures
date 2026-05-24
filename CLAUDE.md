# CLAUDE.md

This file provides guidance and important rules working with code in this repository.

## When coding / building plan

 - Use a progressive disclosure approach for agent coding in this repository: start from high-level information in Serena memories, and only locate/read specific files or symbols when necessary to avoid expanding too much context at once.

#### Serena memories (Keep context clean)

- Perfer use serena mcp tools to understand the architecture and code hierarchy quickly.
- **ALWAYS** Call Serena's `activate_project` before reading memories.

#### When Memories Are Insufficient (On-Demand Querying and Reading)

- Check `READMD.md`

## IDA Pro MCP Tools Reference

See Serena memory: `ida-pro-mcp`
