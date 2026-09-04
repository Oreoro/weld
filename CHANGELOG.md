# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `mcp.tool`, `llm.call`, and `agent.spawn` events for supervising
  MCP servers, LLM usage, and nested agent invocations.
- `weld run --name <server>` so MCP-level rules can target the proxied
  server by name.
- `derive_fs_events` / `derive_agent_events` so plain shell commands
  (`rm`, `mv`, `cp`, `touch`, `cat`, ...) are checked against filesystem
  rules and agent-CLI invocations against agent/model policies.
- `hard_firing_rules` on the supervisor plus a refined `tools/list` filter:
  only tools that are *unconditionally* denied are hidden, while
  conditionally-guarded tools remain advertised so agents can replan.
- Regression tests for shell-command derivation and tool-list filtering.
