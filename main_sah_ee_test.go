//go:build ee

package main

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/security"
)

func TestSAHExecuteRequiresPolicyAndRejectsVirtual(t *testing.T) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = sahExecute(eng.Security(), "sess", []string{"/bin/echo", "hi"})
	if err == nil || err.Error() != "policy_required" {
		t.Fatalf("no policy: %v", err)
	}

	eng, err = engine.New(engine.Config{
		EngineConfig: security.EngineConfig{
			PolicySource: []byte(`package adssh.authz
default allow = false
allow { input.command == "/bin/echo" }
`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !eng.Security().PolicyLoaded() {
		t.Fatal("policy not loaded")
	}
	bindTestSession(t, eng.Security())
	_, _, _, err = sahExecute(eng.Security(), "sess", []string{"lease", "--from", "env:X"})
	if err == nil || err.Error() != "command_rejected" {
		t.Fatalf("vbin: %v", err)
	}
	_, _, _, err = sahExecute(eng.Security(), "sess", []string{"/bin/not-allowed"})
	if err == nil || err.Error() != "policy_denied" {
		t.Fatalf("deny: %v", err)
	}
	stdout, stderr, code, err := sahExecute(eng.Security(), "sess", []string{"/bin/echo", "hi"})
	if err != nil || code != 0 || strings.TrimSpace(stdout) != "hi" {
		t.Fatalf("echo: code %d err %v stdout %q stderr %q", code, err, stdout, stderr)
	}
}

func allowShEngine(t *testing.T) *security.Engine {
	t.Helper()
	eng, err := engine.New(engine.Config{
		EngineConfig: security.EngineConfig{
			PolicySource: []byte(`package adssh.authz
default allow = false
allow { input.command == "/bin/sh" }
`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindTestSession(t, eng.Security())
	return eng.Security()
}

// bindTestSession gives session "sess" an identity, as main does for the
// local session; an unbound session id is denied as identity-unknown.
func bindTestSession(t *testing.T, sec *security.Engine) {
	t.Helper()
	if err := sec.BindSessionIdentity("sess", "tester", nil); err != nil {
		t.Fatal(err)
	}
}

// The sah child must not see the listener's secrets or any ADSSH_* setting.
func TestSAHExecuteChildEnvIsAllowlisted(t *testing.T) {
	t.Setenv("ADSSH_AUDIT_TOKEN", "listener-secret")
	t.Setenv("ADSSH_POLICY", "/nonexistent/policy.rego")
	t.Setenv("SOME_API_KEY", "k")
	t.Setenv("LANG", "C.UTF-8")
	stdout, _, code, err := sahExecute(allowShEngine(t), "sess", []string{"/bin/sh", "-c", "env"})
	if err != nil || code != 0 {
		t.Fatalf("env: code %d err %v", code, err)
	}
	for _, leaked := range []string{"ADSSH_AUDIT_TOKEN", "ADSSH_POLICY", "SOME_API_KEY", "listener-secret"} {
		if strings.Contains(stdout, leaked) {
			t.Fatalf("child env leaked %q:\n%s", leaked, stdout)
		}
	}
	if !strings.Contains(stdout, "LANG=C.UTF-8") || !strings.Contains(stdout, "PATH=") {
		t.Fatalf("child env missing allowlisted vars:\n%s", stdout)
	}
}

// Output is capped while the child runs, not after it has all been buffered.
func TestSAHExecuteCapsOutputWhileRunning(t *testing.T) {
	stdout, stderr, code, err := sahExecute(allowShEngine(t), "sess",
		[]string{"/bin/sh", "-c", "head -c 5000000 /dev/zero | tr '\\0' x; head -c 100000 /dev/zero | tr '\\0' y >&2"})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	if len(stdout) > sahOutputCap || len(stderr) > sahOutputCap {
		t.Fatalf("output not capped: stdout %d stderr %d", len(stdout), len(stderr))
	}
	if len(stdout) == 0 || len(stderr) == 0 {
		t.Fatal("expected a prefix of the output to be kept")
	}
}
