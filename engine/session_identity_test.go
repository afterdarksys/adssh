package engine

import (
	"context"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
)

// onlyUserPolicy allows a command only when input.user equals user.
func onlyUserPolicy(user string) []byte {
	return []byte(fmt.Sprintf("package adssh\nauthz := {\"allow\": input.user == %q, \"deny_reason\": \"user not allowed\"}\n", user))
}

func currentOSUser(t *testing.T) string {
	t.Helper()
	u, err := osuser.Current()
	if err != nil {
		t.Skipf("no current OS user: %v", err)
	}
	return u.Username
}

func newIdentityEngine(t *testing.T, policy []byte, auditPath string) *security.Engine {
	t.Helper()
	sec, err := security.NewEngine(security.EngineConfig{
		RequirePolicy: true,
		PolicySource:  policy,
		AuditLogPath:  auditPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

func openSession(t *testing.T, opts SessionOptions) *Session {
	t.Helper()
	s, err := NewSession(opts)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The finding-3 reproduction: a session declared for an untrusted user under a
// policy that only allows the host OS user must be denied, and the audit log
// must record the denial under the declared user, not the host user.
func TestSessionIdentityUntrustedUserIsDenied(t *testing.T) {
	host := currentOSUser(t)
	audit := filepath.Join(t.TempDir(), "audit.log")
	sec := newIdentityEngine(t, onlyUserPolicy(host), audit)

	s := openSession(t, SessionOptions{User: "untrusted-review-user", SessionID: "unregistered", Engine: sec})
	err := s.RunShell(context.Background(), "echo identity-check")
	if err == nil || !IsAccessDenied(err) {
		t.Fatalf("untrusted session ran as host user: err=%v", err)
	}
	data, rerr := os.ReadFile(audit)
	if rerr != nil {
		t.Fatal(rerr)
	}
	log := string(data)
	if !strings.Contains(log, "user=untrusted-review-user command=echo identity-check allowed=false") {
		t.Fatalf("audit log missing denial for declared user:\n%s", log)
	}
	if strings.Contains(log, "user="+host+" ") {
		t.Fatalf("audit log attributed the command to the host user %q:\n%s", host, log)
	}
}

func TestSessionIdentityTwoUsersOneEngine(t *testing.T) {
	sec := newIdentityEngine(t, onlyUserPolicy("alice"), "")
	alice := openSession(t, SessionOptions{User: "alice", SessionID: "sess-alice", Engine: sec})
	bob := openSession(t, SessionOptions{User: "bob", SessionID: "sess-bob", Engine: sec})

	if err := alice.RunShell(context.Background(), "echo hi"); err != nil {
		t.Fatalf("alice denied: %v", err)
	}
	if err := bob.RunShell(context.Background(), "echo hi"); err == nil || !IsAccessDenied(err) {
		t.Fatalf("bob allowed under alice-only policy: %v", err)
	}
	// Again after bob, so a shared last-writer cannot flip alice's decision.
	if err := alice.RunShell(context.Background(), "echo again"); err != nil {
		t.Fatalf("alice denied after bob: %v", err)
	}
}

func TestSessionIdentitySameIDSeparateEngines(t *testing.T) {
	secA := newIdentityEngine(t, onlyUserPolicy("alice"), "")
	secB := newIdentityEngine(t, onlyUserPolicy("alice"), "")
	a := openSession(t, SessionOptions{User: "alice", SessionID: "shared-id", Engine: secA})
	b := openSession(t, SessionOptions{User: "mallory", SessionID: "shared-id", Engine: secB})

	if err := a.RunShell(context.Background(), "echo a"); err != nil {
		t.Fatalf("engine A alice denied: %v", err)
	}
	if err := b.RunShell(context.Background(), "echo b"); err == nil || !IsAccessDenied(err) {
		t.Fatalf("engine B mallory borrowed alice's identity: %v", err)
	}
	if err := secB.AuthorizeCommand([]string{"echo"}, "shared-id"); err == nil {
		t.Fatal("engine B authorized shared-id as alice")
	}
	if err := secA.AuthorizeCommand([]string{"echo"}, "shared-id"); err != nil {
		t.Fatalf("engine A lost alice: %v", err)
	}
}

func TestSessionIdentityConflictingRebindRefused(t *testing.T) {
	sec := newIdentityEngine(t, onlyUserPolicy("alice"), "")
	openSession(t, SessionOptions{User: "alice", SessionID: "taken", Engine: sec})
	if _, err := NewSession(SessionOptions{User: "mallory", SessionID: "taken", Engine: sec}); err == nil {
		t.Fatal("second session rebound a live session ID to another user")
	}
	if err := sec.AuthorizeCommand([]string{"echo"}, "taken"); err != nil {
		t.Fatalf("refused rebind changed the live identity: %v", err)
	}
}

func TestSessionIdentityStarlarkExecDenied(t *testing.T) {
	host := currentOSUser(t)
	sec := newIdentityEngine(t, onlyUserPolicy(host), "")
	s := openSession(t, SessionOptions{User: "untrusted-review-user", SessionID: "star-unregistered", Engine: sec})
	_, err := s.RunStarlark(context.Background(), `sys["exec_cmd"]("echo x")`)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("sys.exec_cmd ran as host user: %v", err)
	}

	// Positive control: the same path agrees on an allowed principal.
	ok := openSession(t, SessionOptions{User: host, SessionID: "star-host", Engine: sec})
	if _, err := ok.RunStarlark(context.Background(), `sys["exec_cmd"]("echo x")`); err != nil {
		t.Fatalf("sys.exec_cmd denied for allowed principal: %v", err)
	}
}

func TestSessionIdentityGateProgramAgrees(t *testing.T) {
	sec := newIdentityEngine(t, onlyUserPolicy("alice"), "")
	bob := openSession(t, SessionOptions{User: "bob", SessionID: "decl-bob", Engine: sec})
	if err := bob.RunShell(context.Background(), "export FOO=1"); err == nil || !IsAccessDenied(err) {
		t.Fatalf("declaration gate allowed bob: %v", err)
	}
	alice := openSession(t, SessionOptions{User: "alice", SessionID: "decl-alice", Engine: sec})
	if err := alice.RunShell(context.Background(), "export FOO=1"); err != nil {
		t.Fatalf("declaration gate denied alice: %v", err)
	}
}

func TestSessionIdentityCloseUnbinds(t *testing.T) {
	sec := newIdentityEngine(t, []byte("package adssh\nauthz := {\"allow\": true}\n"), "")
	s, err := NewSession(SessionOptions{User: "alice", SessionID: "closing", Engine: sec})
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.AuthorizeCommand([]string{"echo"}, "closing"); err != nil {
		t.Fatalf("bound session denied: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = sec.AuthorizeCommand([]string{"echo"}, "closing")
	if err == nil || !strings.Contains(err.Error(), "session identity unknown") {
		t.Fatalf("closed session still authorized: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSessionIdentityZeroValueUsesOSUser(t *testing.T) {
	host := currentOSUser(t)
	s := openSession(t, SessionOptions{})
	if s.SessionID == "" {
		t.Fatal("zero-value session has no session ID")
	}
	if s.User != host {
		t.Fatalf("zero-value session User = %q, want %q", s.User, host)
	}
	if err := s.RunShell(context.Background(), "true"); err != nil {
		t.Fatalf("zero-value session under allow-all: %v", err)
	}
	pctx := security.BuildPolicyContext("true", nil, s.SessionID)
	if pctx.IdentityUnknown || pctx.User != host {
		t.Fatalf("zero-value policy context = user %q unknown=%v, want %q", pctx.User, pctx.IdentityUnknown, host)
	}
}

func TestSessionIdentitySysRegistryStillResolves(t *testing.T) {
	sec := newIdentityEngine(t, onlyUserPolicy("ssh-alice"), "")
	id := "ssh-registered-identity"
	if err := sys.RegisterSession(&sys.Session{ID: id, User: "ssh-alice"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	if err := sec.AuthorizeCommand([]string{"echo"}, id); err != nil {
		t.Fatalf("sys-registered session denied: %v", err)
	}
}

func TestSessionIdentityUnregisteredIDDenied(t *testing.T) {
	sec := newIdentityEngine(t, []byte("package adssh\nauthz := {\"allow\": true}\n"), "")
	err := sec.AuthorizeCommand([]string{"echo"}, "bogus-unregistered-id")
	if err == nil || !strings.Contains(err.Error(), "session identity unknown") {
		t.Fatalf("unknown session ID authorized as process user: %v", err)
	}
}

// In a session runner, `set` is the shell builtin and never writes the
// globals; the exec-handler form is refused in the security package
// (TestExecHandlerRefusesReservedSetNames). Either way the next command must
// still run as the bound principal.
func TestSessionIdentitySetSessionIDDoesNotMoveIdentity(t *testing.T) {
	sec := newIdentityEngine(t, onlyUserPolicy("alice"), "")
	s := openSession(t, SessionOptions{User: "alice", SessionID: "set-alice", Engine: sec})
	openSession(t, SessionOptions{User: "bob", SessionID: "set-bob", Engine: sec})
	for _, src := range []string{"set SESSION_ID=set-bob", "set SESSION_ID set-bob", "set SESSION_ID=nope"} {
		_ = s.RunShell(context.Background(), src)
		if got := s.Globals["SESSION_ID"]; got == nil || got.String() != `"set-alice"` {
			t.Fatalf("%q changed SESSION_ID global to %v", src, got)
		}
		if err := s.RunShell(context.Background(), "echo x"); err != nil {
			t.Fatalf("after %q alice was not gated as alice: %v", src, err)
		}
	}
}

// A tampered SESSION_ID global must not move the session to another
// principal: the session's fixed ID wins.
func TestSessionIdentityTamperedGlobalIgnored(t *testing.T) {
	sec := newIdentityEngine(t, onlyUserPolicy("alice"), "")
	alice := openSession(t, SessionOptions{User: "alice", SessionID: "tamper-alice", Engine: sec})
	bob := openSession(t, SessionOptions{User: "bob", SessionID: "tamper-bob", Engine: sec})

	// A Starlark assignment does not write the predeclared globals.
	if _, err := bob.RunStarlark(context.Background(), `SESSION_ID = "tamper-alice"`); err != nil {
		t.Fatalf("starlark assignment: %v", err)
	}
	if err := bob.RunShell(context.Background(), "echo x"); err == nil || !IsAccessDenied(err) {
		t.Fatalf("bob ran as alice after starlark assignment: %v", err)
	}

	// Direct tampering of the globals dict still does not change the gate ID.
	bob.Globals["SESSION_ID"] = starlark.String("tamper-alice")
	if err := bob.RunShell(context.Background(), "echo x"); err == nil || !IsAccessDenied(err) {
		t.Fatalf("bob ran as alice after tampering SESSION_ID: %v", err)
	}
	if err := bob.RunShell(context.Background(), "export FOO=1"); err == nil || !IsAccessDenied(err) {
		t.Fatalf("bob declaration ran as alice after tampering SESSION_ID: %v", err)
	}
	alice.Globals["SESSION_ID"] = starlark.String("nope")
	if err := alice.RunShell(context.Background(), "echo x"); err != nil {
		t.Fatalf("alice lost her identity after tampering SESSION_ID: %v", err)
	}
}
