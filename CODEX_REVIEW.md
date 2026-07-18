# Codex Code Review

## Bottom line

adssh has a strong, distinctive shell concept, but the advertised governance layer has release-blocking gaps. This review treats command execution, filesystem access, networking, and extensibility as intentional shell behavior. Findings are limited to correctness bugs and cases where adssh's own policy, identity, RBAC, audit, SSH authentication, or approval guarantees are not consistently enforced.

## Remediation status (2026-07-18)

Codex implemented the repository-contained fixes from this review, with regression tests:

- **Fixed:** background `&` programs remain inside the shell interpreter and its policy/audit interceptors.
- **Fixed:** SSH user certificates are checked with `ssh.CertChecker`; CA keys must be explicitly marked `cert-authority`, while direct user keys remain supported.
- **Fixed:** authenticated SSH user/principals reach command and declaration-keyword policy contexts.
- **Fixed:** configured RBAC entitlements are enforced as an additional command allow-list.
- **Fixed:** four-eyes approval validates the authenticated approver, rejects requester self-approval, and honors a configured approver.
- **Fixed:** active change tickets are keyed by session rather than shared across the engine.
- **Substantially fixed:** MCP policy receives deterministic request arguments; restricted mode, RBAC, HMAC audit chaining, cancellation, and serialized access to shared Starlark state are enabled. Starlark source is visible to the outer policy, but individual operations performed inside an allowed `eval_starlark` program are not yet independently re-authorized.
- **Fixed:** audit-log limits are validated and the handler keeps a bounded tail instead of loading the entire file.
- **Fixed:** shipped Rego examples compile, README policy paths/packages and Go version match the implementation, profile errors propagate, and demo security virtual bins cannot claim clean/no-threat verdicts.

## Blockers

### Background commands bypass the execution pipeline

**Verified.** Input ending in `&` is sent directly to `/bin/sh -c` before parsing, policy evaluation, restricted-mode checks, and auditing. A denied command can potentially be backgrounded to evade those controls.

- `internal/repl/repl.go:163`
- `internal/repl/repl.go:688`

### SSH certificate authentication is incomplete

**Verified.** The public-key callback trusts `cert.SignatureKey` merely because its bytes appear in `authorized_keys`. It does not validate the certificate signature, validity window, certificate type, critical options, or login principal using `ssh.CertChecker`. It also treats every ordinary authorized key as a certificate authority.

- `internal/sys/ssh.go:119`

### SSH identity never reaches command policy

**Verified.** `gateCommand` always calls `BuildPolicyContext(..., "")`, so SSH commands are evaluated as the local OS account—typically root—not as `conn.User()` or its certificate principals. This also makes SSH audit attribution unreliable.

- `security/interceptor.go:116`

### Loaded RBAC entitlements do not enforce commands

**Verified.** `IsAuthorized` works in isolation but has no production caller in the execution chain. The test suite explicitly acknowledges this gap.

- `security/entitlements.go:36`
- `security/gate_negative_test.go:17`

## High priority

### Four-eyes does not verify the approver

**Verified.** `FourEyesRule.Approver` is stored but never checked. Any session able to invoke `4eyes approve`, including the requester, can write the approval marker.

- `security/vbin_foureyes.go:100`
- `security/foureyes.go:346`

### Change-management state is shared across every session

**Verified.** The active ticket is stored once on `security.Engine`, so one SSH user's approved ticket applies to other concurrent users.

- `security/cm.go:261`

### MCP enforcement is coarser than documented

**Verified.** The outer policy receives only tool names such as `eval_starlark` or `container_exec`, without the requested code, image, command, namespace, or function. Therefore, allowing `eval_starlark` permits direct cloud, Docker, and GitHub builtins without operation-level policy decisions. MCP also hardcodes unrestricted mode and leaves RBAC and hash-chain setup disabled.

- `cmd/adssh-mcp/server.go:108`
- `cmd/adssh-mcp/main.go:40`

### MCP shares mutable Starlark state across concurrent workers

**Verified.** The MCP library defaults to five tool workers, while adssh supplies one shared Go map and mutable Starlark dictionaries without synchronization. Concurrent calls can race or contaminate one another.

- `cmd/adssh-mcp/main.go:67`

## Other bugs and polish

### Negative audit-log limits can panic

**Verified.** `audit_log(limit=-1)` can cause an out-of-range slice panic. The handler also reads the complete audit log into memory before tailing it.

- `cmd/adssh-mcp/tools_audit.go:22`

### Shipped Rego examples and policy documentation are inconsistent

**Verified.** `ops_group_only.rego` and `migrate-from-yaml.rego` do not compile because they use `in` without enabling the future keyword. Both were exercised through the real application startup path. The README policy also uses the wrong package, `adssh` instead of `adssh.authz`.

- `policy/examples/ops_group_only.rego`
- `policy/examples/migrate-from-yaml.rego`
- `README.md:130`

### Documented Go version does not match the module

**Verified.** The README says Go 1.21+, while `go.mod` requires Go 1.26.0.

- `README.md:23`
- `go.mod:3`

### Profile execution errors are swallowed

**Verified.** `LoadProfiles` ignores profile and RC execution errors and always returns `nil`, making its callers' error handling unreachable.

- `internal/config/profile.go:26`

### Simulated security tools look operational in the README

**Verified.** `darkscan` and `memforensics` always produce simulated clean results. They are identified as stubs deeper in the documentation, but the README presents them as operational tools.

- `security/virtualbin.go:137`

## Original pre-remediation ratings

- **Core idea / cool factor: 9/10.** Fish-like UX plus Starlark, cloud SDKs, policy, SSH, virtual binaries, and MCP is genuinely distinctive.
- **Shell engineering: 7.5/10.** There is substantial functionality and good work on session isolation and fail-closed Rego evaluation.
- **Governance readiness: 4/10** until identity, RBAC, background execution, certificates, and approval state are fixed.
- **Overall today: 6.5/10**, with a credible path to 8.5+.

## Verification

- Before remediation, `go test ./...` and `go vet ./...` passed, which showed that the original suite did not cover these gaps.
- After remediation, fresh `go test ./...` and `go vet ./...` runs pass.
- E2E-tagged tests are still not included in the normal suite.
