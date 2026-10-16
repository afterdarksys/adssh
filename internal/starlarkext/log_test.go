package starlarkext

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

func logEnv(t *testing.T, eng *security.Engine, restricted bool, stderr *bytes.Buffer) starlark.StringDict {
	t.Helper()
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env, Restricted: restricted, Engine: eng, SessionID: "sess-log", Err: stderr})
	GovernStarlarkGlobalsInPlace(eng, env)
	return env
}

func TestLogWritesAuditAndEcho(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	eng, err := security.NewEngine(security.EngineConfig{AuditLogPath: auditPath})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	var stderr bytes.Buffer
	env := logEnv(t, eng, false, &stderr)
	_, err = starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `
log["info"]("deploy started", app="web", count=3)
log["warn"]("disk low")
log["error"]("bad\nline", token="hunter2")
`, env)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	audit := string(data)
	for _, want := range []string{
		`STARLARK_LOG level=info session="sess-log" msg="deploy started" app="web" count="3"`,
		`STARLARK_LOG level=warn session="sess-log" msg="disk low"`,
		`STARLARK_LOG level=error session="sess-log" msg="bad\nline" token=[REDACTED]`,
	} {
		if !strings.Contains(audit, want) {
			t.Fatalf("audit missing %q:\n%s", want, audit)
		}
	}
	// Only the STARLARK_LOG event is checked here: the govern gate's own
	// [BASH]/[POLICY] lines render kwargs as "token"="…", which the
	// redaction pattern does not match (reported separately).
	for _, line := range strings.Split(audit, "\n") {
		if strings.Contains(line, "STARLARK_LOG") && strings.Contains(line, "hunter2") {
			t.Fatalf("secret field reached the STARLARK_LOG event:\n%s", line)
		}
	}
	echo := stderr.String()
	if !strings.Contains(echo, `msg="deploy started"`) || strings.Contains(echo, "hunter2") {
		t.Fatalf("stderr echo = %q", echo)
	}
	if strings.Count(echo, "\n") != 3 {
		t.Fatalf("stderr echo should be one line per call, got %q", echo)
	}
}

// If the audit write fails the call returns an error and echoes nothing.
func TestLogFailsClosedOnAuditError(t *testing.T) {
	dir := t.TempDir()
	eng, err := security.NewEngine(security.EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log")})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// A ledger path that is a directory makes every chain append fail.
	ledger := filepath.Join(dir, "ledger")
	if err := os.Mkdir(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := eng.InitChain(ledger, filepath.Join(dir, "chain.key"), "sess-log"); err != nil {
		t.Fatalf("InitChain: %v", err)
	}
	var stderr bytes.Buffer
	env := logEnv(t, eng, false, &stderr)
	// The govern gate also audits through the chain, so call the builtin
	// directly to reach the log write itself.
	logDict := starlark.StringDict{}
	SetupLogAPI(logDict, ExtensionOptions{Engine: eng, SessionID: "sess-log", Err: &stderr, Env: env})
	info, _, _ := logDict["log"].(*starlark.Dict).Get(starlark.String("info"))
	_, err = starlark.Call(&starlark.Thread{Name: "t"}, info.(starlark.Callable), starlark.Tuple{starlark.String("hello")}, nil)
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("err = %v, want an audit failure", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("echoed despite audit failure: %q", stderr.String())
	}
}

// log.* is gated as starlark.log.* in the audit capability group.
func TestLogGatedByAuditCapability(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz
import future.keywords.in
default allow = true
allow = false { "audit" in input.capabilities }
deny_reason = "audit capability denied" { "audit" in input.capabilities }
`)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	var stderr bytes.Buffer
	env := logEnv(t, eng, false, &stderr)
	_, err = starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `log["info"]("x")`, env)
	if err == nil || !strings.Contains(err.Error(), "audit capability denied") {
		t.Fatalf("err = %v, want the audit capability denial", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("echoed despite denial: %q", stderr.String())
	}
}

func TestLogRejectsOversized(t *testing.T) {
	var stderr bytes.Buffer
	env := logEnv(t, allowAllEngine(t), false, &stderr)
	env["BIG"] = starlark.String(strings.Repeat("x", maxLogEventBytes+1))
	if _, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `log["info"](BIG)`, env); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want a size refusal", err)
	}
}

func TestLogAndUDPAbsentWhenRestricted(t *testing.T) {
	var stderr bytes.Buffer
	env := logEnv(t, allowAllEngine(t), true, &stderr)
	for _, src := range []string{`log["info"]("x")`, `net["dial_udp"]("127.0.0.1", 53, "x")`} {
		if _, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", src, env); err == nil {
			t.Fatalf("%s: expected absent in restricted mode", src)
		}
	}
}

// In an SSH login child the listener holds the audit sinks, so log.* would
// claim to audit and write nothing. It fails closed instead.
func TestLogRefusedInRemoteGateProcess(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	eng, err := security.NewEngine(security.EngineConfig{AuditLogPath: auditPath})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	security.SetRemoteGate(func(bool, []string, string) error { return nil })
	t.Cleanup(func() { security.SetRemoteGate(nil) })
	var stderr bytes.Buffer
	logDict := starlark.StringDict{}
	SetupLogAPI(logDict, ExtensionOptions{Engine: eng, SessionID: "sess-log", Err: &stderr, Env: starlark.StringDict{}})
	info, _, _ := logDict["log"].(*starlark.Dict).Get(starlark.String("info"))
	_, err = starlark.Call(&starlark.Thread{Name: "t"}, info.(starlark.Callable), starlark.Tuple{starlark.String("hello")}, nil)
	if err == nil || !strings.Contains(err.Error(), "log.info: not available in an SSH session") {
		t.Fatalf("err = %v, want the SSH refusal", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("echoed: %q", stderr.String())
	}
	if data, err := os.ReadFile(auditPath); err == nil && strings.Contains(string(data), "STARLARK_LOG") {
		t.Fatalf("audit written:\n%s", data)
	}
}
