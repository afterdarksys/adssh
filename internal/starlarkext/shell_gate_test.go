package starlarkext

// Gate tests for shell features mvdan inherits: here-strings, here-docs and
// process substitution. The inner command of each form must reach the
// engine's CallHandler gate and be audited, exactly like a plain command.
//
// Threats: a redirection or substitution form that runs its inner command
// without passing CallHandler would bypass Rego policy and the audit log.
// These tests prove each form is denied and audited; they do not test which
// commands a policy should allow.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/security"
)

// denyIDPolicy denies the `id` command and allows everything else.
const denyIDPolicy = `
package adssh.authz
default allow = false
allow { input.command != "id" }
deny_reason = "id denied by gate test" { input.command == "id" }
`

func auditedDenyEngine(t *testing.T) (*security.Engine, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(denyIDPolicy), AuditLogPath: auditPath})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng, auditPath
}

func TestShellFormsInnerCommandIsGated(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"here-string command", `out = sys["exec_cmd"]("id <<< hello")`},
		{"here-string substitution", `out = sys["exec_cmd"]("cat <<< \"$(id)\"")`},
		{"here-doc command", "out = sys[\"exec_cmd\"](\"id <<EOF\\nhello\\nEOF\\n\")"},
		{"here-doc substitution", "out = sys[\"exec_cmd\"](\"cat <<EOF\\n$(id)\\nEOF\\n\")"},
		{"process substitution read", `out = sys["exec_cmd"]("cat <(id)")`},
		{"process substitution write", `out = sys["exec_cmd"]("echo hi > >(id)")`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, auditPath := auditedDenyEngine(t)
			env := execEnv(t, eng, false)
			g, err := evalExec(t, env, tc.src)
			// The outer command may succeed (an inner substitution failing
			// does not fail `cat`), but the inner `id` must never run.
			if err == nil {
				out, _ := g["out"].(interface{ String() string })
				if out != nil && strings.Contains(out.String(), "uid=") {
					t.Fatalf("id ran: output %q", out.String())
				}
			} else if strings.Contains(err.Error(), "uid=") {
				t.Fatalf("id ran: %v", err)
			}
			audit := waitForAudit(t, auditPath, "command=id allowed=false")
			if !strings.Contains(audit, "[BASH] id") {
				t.Fatalf("inner id was not audited through the gate:\n%s", audit)
			}
			if !strings.Contains(audit, "command=id allowed=false") {
				t.Fatalf("inner id denial was not audited:\n%s", audit)
			}
		})
	}
}

// waitForAudit polls the audit log until it contains want or 3s pass. A
// write process substitution `>(cmd)` runs its inner command on a goroutine
// that is gated after exec_cmd returns, so its decision can land late.
func waitForAudit(t *testing.T, path, want string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		if strings.Contains(string(data), want) || time.Now().After(deadline) {
			return string(data)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
