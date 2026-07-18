package security

// Threats:
//   This file proves the interceptor's defense-in-depth ordering (interceptor.go:
//   policy -> CM -> four-eyes -> custom cmd -> builtins -> vbins -> restricted ->
//   exec) cannot be subverted: a policy DENY must win over every later stage, so
//   a denied command can never be rescued by a matching vbin, custom command, or
//   shell builtin, and never falls through to real exec. It also proves the
//   policy layer FAILS CLOSED under type-confusion / malformed input, that DENY
//   decisions are written to the tamper-evident audit chain, and that oversized
//   input does not crash evaluation.
//
//   These tests run through the process-global defaultEngine via the shared
//   runShell/sentinelRecorder harness (interceptor_test.go). They isolate global
//   state with resetPolicy/resetChain + t.Cleanup and per-test temp dirs.
//
//   NOT covered here: four-eyes and change-management gating through the
//   interceptor (see gate_negative_test.go), and the audit chain's tamper-
//   evidence threat model (see audit_chain_negative_test.go). Enforcement of the
//   RBAC IsAuthorized helper is also in gate_negative_test.go.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// denyAllRegoNeg is a policy that denies everything (explicit default).
const denyAllRegoNeg = `package adssh.authz
default allow = false`

// allowAllRegoNeg allows everything (explicit default).
const allowAllRegoNeg = `package adssh.authz
default allow = true`

// negPrecedenceVBin is a virtual binary whose Run flips ran=true. Registered
// under a unique name so gate-precedence tests can prove a policy deny stops the
// interceptor before the vbin registry is ever consulted.
type negPrecedenceVBin struct{ ran *bool }

func (v negPrecedenceVBin) Name() string        { return "neg-precedence-vbin" }
func (v negPrecedenceVBin) Description() string { return "gate-precedence negative-test vbin" }
func (v negPrecedenceVBin) Usage() string       { return "neg-precedence-vbin" }
func (v negPrecedenceVBin) Run(ctx context.Context, args []string) error {
	*v.ran = true
	return nil
}

// --- A. Gate precedence / defense-in-depth ---

// A.1: deny-all policy + a vbin whose name is the command => DENIED and the
// vbin's Run never executes (policy is stage 0, vbins are stage 2).
func TestGateNeg_PolicyDenyBeatsVBin(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	ran := false
	Register(negPrecedenceVBin{ran: &ran}) // unique name; panics on collision

	if err := LoadPolicy(writePolicy(t, denyAllRegoNeg)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "neg-precedence-vbin arg")

	if runErr == nil || !strings.Contains(runErr.Error(), "access denied") {
		t.Fatalf("expected access-denied error, got: %v", runErr)
	}
	if ran {
		t.Error("SECURITY: vbin Run executed despite a policy deny that precedes the vbin stage")
	}
	if len(rec.calls) != 0 {
		t.Errorf("denied vbin command fell through to exec: %v", rec.calls)
	}
}

// A.2: deny-all policy + a registered __custom_commands__ callable for the
// command => DENIED, callable never invoked (policy stage 0 < custom stage 1).
func TestGateNeg_PolicyDenyBeatsCustomCommand(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	invoked := false
	fn := starlark.NewBuiltin("neg-custom", func(th *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		invoked = true
		return starlark.None, nil
	})
	cmds := new(starlark.Dict)
	_ = cmds.SetKey(starlark.String("neg-custom"), fn)
	globals := starlark.StringDict{"__custom_commands__": cmds}

	if err := LoadPolicy(writePolicy(t, denyAllRegoNeg)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, globals, "neg-custom x")

	if runErr == nil || !strings.Contains(runErr.Error(), "access denied") {
		t.Fatalf("expected access-denied error, got: %v", runErr)
	}
	if invoked {
		t.Error("SECURITY: custom command callable invoked despite a policy deny that precedes it")
	}
	if len(rec.calls) != 0 {
		t.Errorf("denied custom command fell through to exec: %v", rec.calls)
	}
}

// A.3: deny-all policy + shell keywords/builtins the interceptor implements.
//
// FIXED IN THIS COMMIT (finding #1): mvdan.cc/sh implements alias/set/unset/read/
// type/dirs/pushd/popd/disown/unalias as NATIVE builtins routed through
// Runner.call, and export/readonly/declare/local/typeset/nameref as DeclClause
// KEYWORDS routed through neither the call nor the exec handler. Previously
// BashInterceptor was wired only as an exec handler, so ALL of these bypassed the
// authorization gate (Rego policy, CM, four-eyes, audit). The gate now lives in a
// mvdan CallHandler (covers the builtins) plus an AST pre-scan, GateProgram, run
// before Runner.Run (covers the DeclClause keywords like `export`). This test
// PINS the fixed behavior as a HARD assertion: under a deny-all policy every one
// of alias/set/export MUST be blocked with "access denied", and none may fall
// through to real exec.
func TestGateNeg_MvdanBuiltinsGatedByPolicy(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	if err := LoadPolicy(writePolicy(t, denyAllRegoNeg)); err != nil {
		t.Fatal(err)
	}

	for _, src := range []string{"alias negfoo=negbar", "set x=1", "export NEGVAR=1"} {
		_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, src)
		if runErr == nil || !strings.Contains(runErr.Error(), "access denied") {
			t.Errorf("SECURITY: builtin/keyword %q bypassed deny-all policy (err=%v) — must be policy-gated", src, runErr)
		}
		if len(rec.calls) != 0 {
			t.Errorf("builtin/keyword %q fell through to real exec: %v", src, rec.calls)
		}
	}
}

// A.4: restricted mode must not let a '/'-path binary reach real exec, including
// via the `command`/`type` indirection. Runs allow-by-default (no policy) so
// only the restricted-mode check stands between the command and exec.
//
// Observed: mvdan re-dispatches `command X` by handing X to the exec handler, so
// `command /bin/echo` hits the interceptor's restricted '/'-check and is blocked;
// `type` is a mvdan builtin that never execs its target. Neither reaches exec —
// the restricted guard holds. This test guards against a regression that would
// let a '/'-path slip through either indirection.
func TestGateNeg_Restricted_NoSlashExecViaIndirection(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	// Direct '/'-path is blocked by the restricted check (regression guard).
	_, _, directErr, directRec := runShell(t, true, starlark.StringDict{}, "/bin/echo hi")
	if directErr == nil || !strings.Contains(directErr.Error(), "restricted") {
		t.Fatalf("expected restricted error for direct '/'-path, got: %v", directErr)
	}
	if len(directRec.calls) != 0 {
		t.Errorf("SECURITY: direct '/'-path reached exec in restricted mode: %v", directRec.calls)
	}

	// `command /bin/echo hi`: mvdan strips `command` and re-dispatches
	// `/bin/echo` to the exec handler, which the restricted '/'-check blocks.
	_, _, cmdErr, cmdRec := runShell(t, true, starlark.StringDict{}, "command /bin/echo hi")
	if cmdErr == nil || !strings.Contains(cmdErr.Error(), "restricted") {
		t.Errorf("SECURITY: `command` indirection was not blocked by restricted mode, err=%v", cmdErr)
	}
	if len(cmdRec.calls) != 0 {
		t.Errorf("SECURITY: `command` indirection reached real exec with a '/'-path in restricted mode: %v", cmdRec.calls)
	}

	// `type /bin/echo`: never execs the target.
	_, _, _, typeRec := runShell(t, true, starlark.StringDict{}, "type /bin/echo")
	if len(typeRec.calls) != 0 {
		t.Errorf("SECURITY: `type` indirection reached real exec in restricted mode: %v", typeRec.calls)
	}
}

// A.5: empty / whitespace-only / comment-only input must not panic and must not
// reach exec.
func TestGateNeg_EmptyAndWhitespaceCommand_NoExec(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	for _, src := range []string{"", "   ", "\t  \n", "\n\n", "# only a comment\n"} {
		_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, src)
		if runErr != nil {
			t.Errorf("empty/whitespace src %q returned error: %v", src, runErr)
		}
		if len(rec.calls) != 0 {
			t.Errorf("empty/whitespace src %q reached exec: %v", src, rec.calls)
		}
	}
}

// --- B. Deny is audited ---

// B: a denied command must leave a policy-decision entry (allowed=false) in the
// audit chain, and an allowed command must leave allowed=true. The interceptor
// logs through the defaultEngine, so the chain is initialised on defaultEngine
// via the InitChain shim.
func TestAuditNeg_PolicyDecisionsAreChained(t *testing.T) {
	resetPolicy()
	resetChain()
	t.Cleanup(resetPolicy)
	t.Cleanup(resetChain)

	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	InitChain(ledger, filepath.Join(dir, "key"), "audit-neg")

	// Denied run.
	denyRego := `package adssh.authz
default allow = false
deny_reason = "audit-neg-deny" { input.command == "denyaudit-cmd" }`
	if err := LoadPolicy(writePolicy(t, denyRego)); err != nil {
		t.Fatal(err)
	}
	_, _, denyErr, denyRec := runShell(t, false, starlark.StringDict{}, "denyaudit-cmd flag")
	if denyErr == nil {
		t.Fatal("expected denied command to error")
	}
	if len(denyRec.calls) != 0 {
		t.Errorf("denied command reached exec: %v", denyRec.calls)
	}

	// Allowed run (reload policy so the same ledger records an allowed decision).
	if err := LoadPolicy(writePolicy(t, allowAllRegoNeg)); err != nil {
		t.Fatal(err)
	}
	_, _, allowErr, _ := runShell(t, false, starlark.StringDict{}, "allowaudit-cmd flag")
	if allowErr != nil {
		t.Fatalf("unexpected error on allowed command: %v", allowErr)
	}

	lines := readChainLines(t, ledger)
	var sawDeny, sawAllow bool
	for _, l := range lines {
		e := unmarshalEntry(t, l)
		if e.Type != "policy" || e.Allowed == nil {
			continue
		}
		if !*e.Allowed && strings.Contains(e.Command, "denyaudit-cmd") {
			sawDeny = true
			if e.Reason != "audit-neg-deny" {
				t.Errorf("deny chain entry missing reason: got %q", e.Reason)
			}
		}
		if *e.Allowed && strings.Contains(e.Command, "allowaudit-cmd") {
			sawAllow = true
		}
	}
	if !sawDeny {
		t.Error("SECURITY: policy DENY was not recorded in the audit chain (no allowed=false entry for the command)")
	}
	if !sawAllow {
		t.Error("policy ALLOW was not recorded in the audit chain (no allowed=true entry for the command)")
	}

	// The chain must still verify (deny logging must not corrupt linkage).
	if ok, badSeq, err := defaultEngine.VerifyChain(ledger); err != nil || !ok {
		t.Errorf("audit chain failed to verify after deny+allow logging: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}

// --- C. Policy fail-closed / type-confusion ---

// C.1: malformed inline PolicySource => NewEngine returns an error (fail closed;
// no engine that silently allows everything is produced).
func TestPolicyNeg_MalformedSource_FailsClosed(t *testing.T) {
	if _, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh.authz\nallow = {{{ not rego")}); err == nil {
		t.Error("SECURITY: NewEngine accepted malformed Rego source instead of failing closed")
	}
}

// C.2: a non-boolean `allow` value must NOT be treated as allow=true by
// coincidence — it must fail closed.
//
// FIXED IN THIS COMMIT (finding #2): EvaluatePolicy now rejects a non-boolean
// `allow` (e.g. `allow = "yes"` / `allow = 1`) and DENIES, instead of silently
// keeping an allow-by-default value. This test PINS the fixed fail-closed
// behavior as a HARD assertion.
func TestPolicyNeg_NonBooleanAllow_FailsClosed(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`package adssh.authz
allow = "yes" { input.command == "anything" }`)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	allowed, reason, err := eng.EvaluatePolicy(PolicyContext{Command: "anything"})
	if err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	if allowed {
		t.Error("SECURITY: non-boolean `allow` (\"yes\") was treated as ALLOW — must fail closed (deny)")
	}
	if !strings.Contains(reason, "non-boolean allow") {
		t.Errorf("expected deny reason to mention non-boolean allow, got %q", reason)
	}
}

// C.3: deny_reason set while allow=true does NOT block. Documents precedence:
// the boolean `allow` decides; deny_reason is only a message surfaced on deny.
func TestPolicyNeg_DenyReasonWithAllowTrue_DoesNotBlock(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	rego := `package adssh.authz
default allow = true
deny_reason = "cosmetic" { input.command == "reasoncmd" }`

	eng, err := NewEngine(EngineConfig{PolicySource: []byte(rego)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	allowed, reason, err := eng.EvaluatePolicy(PolicyContext{Command: "reasoncmd"})
	if err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true when default allow=true regardless of deny_reason")
	}
	if reason != "cosmetic" {
		t.Errorf("expected deny_reason surfaced as %q, got %q", "cosmetic", reason)
	}

	// Through the interceptor it must actually run (deny_reason alone is inert).
	if err := LoadPolicy(writePolicy(t, rego)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "reasoncmd arg")
	if runErr != nil {
		t.Fatalf("unexpected error: %v", runErr)
	}
	if len(rec.calls) != 1 || rec.calls[0][0] != "reasoncmd" {
		t.Errorf("expected reasoncmd to reach exec (allow wins over deny_reason), got: %v", rec.calls)
	}
}

// C.4: a policy package with rules that do NOT match the command and NO explicit
// `default allow = false` currently evaluates to ALLOW, because EvaluatePolicy
// defaults allowed=true when the result set carries no `allow` boolean.
//
// FIXED IN THIS COMMIT (finding #3): deny-by-default IS now the contract when a
// policy is loaded. A loaded policy whose result carries no `allow` key (e.g. the
// author wrote a matching rule but forgot `default allow = false`, and the rule
// does not fire for this command) DENIES. This test PINS the fixed fail-closed
// behavior as a HARD assertion, both at EvaluatePolicy and through the interceptor.
func TestPolicyNeg_NoDefaultNoMatch_FailsClosed(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	rego := `package adssh.authz
allow = true { input.command == "onlythis" }`

	eng, err := NewEngine(EngineConfig{PolicySource: []byte(rego)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	allowed, _, err := eng.EvaluatePolicy(PolicyContext{Command: "somethingelse"})
	if err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	if allowed {
		t.Error("SECURITY: loaded policy + no matching rule + no `default allow` => ALLOW; deny-by-default must be honored")
	}

	// Through the interceptor the unmatched command must be blocked and never exec.
	if err := LoadPolicy(writePolicy(t, rego)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "somethingelse arg")
	if runErr == nil || !strings.Contains(runErr.Error(), "access denied") {
		t.Errorf("SECURITY: unmatched command was not denied by deny-by-default, err=%v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("SECURITY: unmatched command fell through to real exec: %v", rec.calls)
	}
}

// C.5: an oversized argument (1 MiB) under an allow policy must not crash; a
// decision is still returned.
func TestPolicyNeg_OversizedArg_NoCrash(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(allowAllRegoNeg)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	big := strings.Repeat("A", 1<<20) // 1 MiB
	allowed, _, err := eng.EvaluatePolicy(PolicyContext{Command: "bigcmd", Args: []string{big}})
	if err != nil {
		t.Fatalf("EvaluatePolicy on oversized arg errored: %v", err)
	}
	if !allowed {
		t.Error("expected allow-all policy to allow oversized-arg command")
	}
}
