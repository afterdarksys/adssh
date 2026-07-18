# Advanced Virtual Binaries Implementation Plan

> **For Codex:** Use `${SUPERPOWERS_SKILLS_ROOT}/skills/collaboration/executing-plans/SKILL.md` to implement this plan task-by-task.

**Goal:** Add eight production-quality VBIN families: `pick`, `nav`, structured data pipelines, `why`, `runbook`, `par`, `evidence`, and `lease`.

**Architecture:** Interactive commands share a Charm Bubble Tea picker model with deterministic non-interactive modes. Commands that launch child processes use one engine-owned governed executor so every child is policy/RBAC/CM/four-eyes checked and audited. Structured commands exchange JSONL over ordinary POSIX byte streams; governance and evidence commands expose read-only engine decisions and HMAC-chain records.

**Tech Stack:** Go 1.26, `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/bubbles`, `github.com/charmbracelet/lipgloss`, Starlark, mvdan shell handler contexts, standard-library JSON/CSV/process APIs.

---

### Task 1: Governed child-command runtime

**Files:**
- Create: `security/vbin_runtime.go`
- Create: `security/vbin_runtime_test.go`
- Modify: `security/virtualbin_registry.go`

1. Write a failing test proving a child command denied by Rego never reaches an injected executor.
2. Run `go test ./security -run TestGovernedCommand -count=1 -v`; expect the missing runtime API failure.
3. Add a context-carried executor and `Engine.runGovernedCommand` that resolves session identity, invokes the same authorization gate as shell commands, supports registered VBINs, and executes external argv without reparsing through `/bin/sh`.
4. Add cancellation, cwd, environment overlay, and stdout/stderr capture without logging injected secret values.
5. Re-run the focused test; expect PASS.

### Task 2: Shared Charm picker and `pick`

**Files:**
- Create: `internal/vbinui/picker.go`
- Create: `internal/vbinui/picker_test.go`
- Create: `security/vbin_pick.go`
- Create: `security/vbin_pick_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

1. Write failing tests for fuzzy ranking, cancellation, indexed selection, newline input, JSON input, and deterministic non-TTY output.
2. Run the focused packages and verify RED.
3. Add Bubble Tea/Bubbles/Lipgloss dependencies.
4. Implement a reusable picker model with filtering, cursor movement, preview text, enter-to-select, and escape/Ctrl-C cancellation.
5. Implement `pick [--query text] [--index n] [--json] [items...]`, falling back to newline-delimited stdin.
6. Verify focused tests pass.

### Task 3: `nav` multi-column file manager

**Files:**
- Create: `internal/vbinui/navigator.go`
- Create: `internal/vbinui/navigator_test.go`
- Create: `security/vbin_nav.go`
- Create: `security/vbin_nav_test.go`

1. Write failing tests for sorted directory entries, parent/current/preview columns, hidden-file toggling, safe preview truncation, and non-TTY JSON listing.
2. Verify RED.
3. Implement the Bubble Tea navigator with parent, current, and preview panes; directory traversal; hidden toggle; and selected-path result.
4. Implement `nav [path] [--json] [--select query]`; interactive directory selection updates the current shell via the handler’s `cd` builtin, while file selection prints the path.
5. Verify focused tests pass.

### Task 4: Structured JSONL pipeline family

**Files:**
- Create: `security/vbin_structured.go`
- Create: `security/vbin_structured_test.go`

1. Write failing table tests for `from json`, `from jsonl`, `from csv`, `where <Starlark expression>`, `select field,...`, and `to json|jsonl|csv|table`.
2. Verify RED.
3. Implement bounded record decoding, Go-to-Starlark conversion, boolean predicate enforcement, dotted-field selection, stable field ordering, and streaming encoders.
4. Reject malformed input, non-boolean predicates, oversized records, and unsupported formats with useful errors.
5. Verify focused tests pass.

### Task 5: `why` governance explainer

**Files:**
- Create: `security/explain.go`
- Create: `security/explain_test.go`
- Create: `security/vbin_why.go`
- Create: `security/vbin_why_test.go`

1. Write failing tests showing policy denial, entitlement denial, restricted-mode denial, CM requirement, and matching four-eyes rules without creating approval files or waiting.
2. Verify RED.
3. Implement a side-effect-free `Engine.ExplainCommand` returning ordered stage decisions and an overall allow/deny/approval-required result.
4. Implement `why [--json] -- command args...`, using the authenticated session identity.
5. Verify focused tests pass.

### Task 6: `runbook` typed Starlark procedures

**Files:**
- Create: `security/vbin_runbook.go`
- Create: `security/vbin_runbook_test.go`
- Create: `examples/runbooks/diagnose.star`

1. Write failing tests for discovery, required typed parameters, dry-run output, argv-only steps, interpolation, cancellation, and fail-fast execution.
2. Verify RED.
3. Define a runbook contract with `description`, `params`, and `steps`; each step is an argv list, never a shell string.
4. Implement `runbook list`, `runbook show NAME`, and `runbook run NAME [--param k=v] [--dry-run]` using configured/XDG runbook directories.
5. Execute every non-dry-run step through the governed child-command runtime.
6. Verify focused tests pass.

### Task 7: `par` bounded parallel execution

**Files:**
- Create: `security/vbin_par.go`
- Create: `security/vbin_par_test.go`

1. Write failing tests for `--jobs` bounds, ordered results, `{}` substitution, stdin items, cancellation, nonzero aggregation, and per-child policy denial.
2. Verify RED.
3. Implement a worker pool accepting `par [--jobs N] [items...] -- command {}` with isolated output buffers and deterministic ordered rendering.
4. Route every child through the governed runtime; never use `/bin/sh -c`.
5. Verify focused and race tests pass.

### Task 8: `evidence` signed audit bundles

**Files:**
- Create: `security/vbin_evidence.go`
- Create: `security/vbin_evidence_test.go`

1. Write failing tests for verified-chain bundles, session/change/time filters, tamper rejection, JSON output, and secure file output.
2. Verify RED.
3. Implement `evidence [--session id] [--change id] [--since ts] [--until ts] [--out path]` using the engine’s configured ledger and `VerifyChain` before export.
4. Include bundle metadata, verification state, SHA-256 digest, and matching chain entries; write output files with mode `0600`.
5. Verify focused tests pass.

### Task 9: `lease` command-scoped credentials

**Files:**
- Create: `security/vbin_lease.go`
- Create: `security/vbin_lease_test.go`

1. Write failing tests for `env:SOURCE`, permission-checked `file:path`, destination variable naming, TTL validation, command cancellation, policy denial, and absence of secret material from output/errors/audit arguments.
2. Verify RED.
3. Implement `lease --from env:NAME|file:path --as DEST [--ttl duration] -- command args...` with in-memory secret handling and a command-scoped environment overlay.
4. Zero temporary byte buffers where practical and never print or serialize secret values.
5. Verify focused tests pass.

### Task 10: Registration, help, docs, and final verification

**Files:**
- Modify: `security/help_content.go`
- Modify: `docs/VBIN-SPEC.md`
- Modify: `README.md`
- Modify: `internal/repl/completer.go`
- Modify: `CODEX_REVIEW.md` only if implementation changes prior remediation claims

1. Add a failing registry/help test asserting all new VBIN names and descriptions are discoverable.
2. Register every VBIN and add completions/help/examples.
3. Document JSONL pipeline contracts, runbook schema, governed child execution, evidence guarantees, and lease threat boundaries.
4. Run `gofmt` on touched Go files and `git diff --check`.
5. Run `go test ./...`, `go vet ./...`, and `go test -race ./cmd/adssh-mcp ./engine ./security ./internal/vbinui`.
6. Inspect the final diff for secret leakage, shell-string execution, shared mutable state, and unrelated changes.
