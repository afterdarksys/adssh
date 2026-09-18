# Enhanced Starlark + capability-group policy framework

Status: in progress (stage 1 underway)
Author: session 2026-09-17
Scope: `internal/starlarkext/`, `security/`, `policy/`

## Goal

Make adssh's enhanced Starlark more complete (file tests, strings, regex,
status/data, secure process execution) AND gate the whole extension surface by
**capability groups** — named sets like `cloud`, `stdio`, `security`, `strings`,
`databases`, `regex`, `fileops`, `proc`, `net`, `tcp` — so a policy can allow or
deny an entire class of operation instead of enumerating individual builtins.

## What already exists (the foundation — do not rebuild)

- **Extension surface:** `SetupExtensions` (`internal/starlarkext/starlarkext.go`)
  registers namespaced dicts: `crypto`, `net`, `re`, `sys`, `data`, `i18n`,
  `cloud`, plus module setups (AWS/GCP/Azure/OCI, k8s, secrets, db, notify,
  expect, docker, vcs, containers, security, fs, template).
- **Universal governance:** `govern.go` wraps every builtin so each call routes
  through `sec.AuthorizeCommand(["starlark.<ns>.<fn>", args...])`. Single
  chokepoint; the dotted path is the group key.
- **Policy engine:** OPA/Rego (`security/policy.go`, `engine.go`), keyed on
  `input.command`, `input.args`, `input.user`, `input.groups`, plus
  elevation/gateway/lease/agent claims. Fail-closed, deny-by-default once a
  policy loads, allow-all when none. The command gate is `gateCommandWithExtra`
  (`security/interceptor.go:120`), which builds `PolicyContext` via
  `BuildPolicyContext` and calls `EvaluatePolicy`.
- **Bundles:** `policy/default.rego` (allow-all) and `policy/bundles/*` (ai-agent,
  regulated-ops, gateway-only, home-permissive, admin-api).

Gap: no capability-group concept. Policies match individual command names.
Restricted mode is the only grouping and is hard-coded via omission in
`SetupExtensions`.

## Key design decisions

1. **Registry owned in Go, fail-closed** (chosen over a Rego/JSON data file).
   Single source of truth co-located with the engine; unclassified Starlark
   paths are tagged so a strict policy can deny them. A policy-side override
   (hybrid) is a documented later extension, not stage 1.
2. **Import-cycle constraint:** `starlarkext` imports `security`, so the
   classifier MUST live in `security` (pure string→groups logic, no starlark
   types). It is a static prefix table, not a runtime registration.
3. **New policy-input field is `capabilities`, NOT `groups`.**
   `PolicyContext.Groups` already means the caller's OS/RBAC principals. Adding
   `Capabilities []string` keeps `input.groups` = "who" and `input.capabilities`
   = "what the op touches". Overloading `groups` would be a silent security bug.
4. **Shell commands stay unchanged.** Classification only fires for
   `starlark.*` paths; external binaries (`ls`, `git`) classify to nil and keep
   today's behavior.

## Capability taxonomy (initial)

| Namespace / path                       | Capabilities            |
|-----------------------------------------|-------------------------|
| `net.*`                                 | `net`, `tcp`            |
| `re.*`, `str.*` (regex helpers)         | `regex`                 |
| `str.*` (string helpers)                | `strings`               |
| `db.*`                                   | `databases`             |
| `fs.*`, `sys.read_file`/`write_file`    | `fileops`               |
| `sys.exec_*`, `expect.*`, `sys.load_*`  | `proc`, `stdio`         |
| `sys.getenv`/`setenv`                    | `stdio`                 |
| `crypto.*`                               | `crypto`                |
| `data.*`                                 | `data`                  |
| `aws.*`/`gcp.*`/`azure.*`/`oci.*`/`cloud.*` | `cloud`             |
| `k8s.*`                                  | `k8s`                   |
| `docker.*`/`containers.*`               | `containers`            |
| `secrets.*`                              | `secrets`, `security`   |
| `sec.*`                                  | `security`              |
| `vcs.*`                                  | `vcs`                   |
| `notify.*`                               | `notify`                |
| `template.*`, `i18n.*`                  | `template`              |
| `starlark.*` with no match              | `unclassified` (fail-closed hook) |

## Stages

### Stage 1 — the framework (foundation; everything hangs off it)
- `security/capabilities.go`: `ClassifyCapabilities(command string) []string`
  with the static prefix table; sorted-unique output; nil for non-`starlark.*`;
  `["unclassified"]` for an unknown `starlark.*` path.
- `PolicyContext.Capabilities []string` (`json:"capabilities,omitempty"`);
  populate in `gateCommandWithExtra` after `BuildPolicyContext`; add
  `input["capabilities"]` in `EvaluatePolicy`.
- `policy/bundles/capabilities.rego` + `policy/examples/capability-groups.rego`:
  demonstrate allow/deny by `input.capabilities`.
- Tests: `security/capabilities_test.go` (classification) + a policy test proving
  a `deny cloud` policy blocks `starlark.aws.*` and allows `starlark.str.*`.
- Restricted-mode-as-capability-profile is **stage 1b** (deferred): keep the
  existing omission for now; caps are additive and non-breaking.

### Stage 2 — enhanced feature set (low-risk, isolated)
- `str` module: fields/split/join, trim, contains, has_prefix/suffix, replace,
  sprintf, case.
- `fs` file tests: `exists`, `is_file`, `is_dir`, `stat` (size/mode/mtime/uid),
  `glob`, `checksum`.
- `re` extensions: `find`, `findall`, `replace`, `split`, `groups`, compiled.
- `data`: csv/toml; a status probe capturing exit/stdout/stderr/duration.
- Each new builtin added to the capability table in the same change.

### Stage 3 — secure process execution (security-heavy; own pass)
- Rework `exec_cmd`/`exec_json`/`exec_async` (see `TODO(session)` in
  `starlarkext.go`): thread the per-session engine, argv-based exec (never
  `sh -c`), timeouts, env allowlist, output caps, all gated via `proc`/`stdio`.
- Bound by `~/development/ads-fable-utils/SECURITY-RULES.md`: `Threats:` note +
  negative tests (injection, oversized output, disallowed env, denied
  capability, fail-closed).

## Verification
- `go build ./...` and `go test ./security/... ./internal/starlarkext/...`.
  This repo has no `.tool-versions`; run under system Go or add one.
- Author/reviewer separation: a separate code-review / security-review pass
  approves each stage; no self-approval.
