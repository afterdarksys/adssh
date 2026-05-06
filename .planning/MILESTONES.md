# Milestones

## v0.x — Foundation (shipped)

**Goal:** Working programmable shell with security primitives.

**Shipped:**
- Hybrid REPL (Starlark + POSIX shell, auto-detection)
- Built-in SSH server with public-key auth and session mirroring
- Cloud namespaces: aws, oci, gcp, git, github, containers
- RBAC via YAML entitlements + audit log
- Container audit trail (ephemeral Docker, JSONL, replay)
- Go plugin system (.so via sys.load_plugin)
- Virtual builtins: jq, yq, http

---

## v1.0 — AI-ready layer (current)

**Goal:** Make adssh programmable by AI — Rego policy engine, MCP server, Claude Code skill, ADSSHA agent.

**Status:** In progress
