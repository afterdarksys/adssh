package security

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

// These tests prove that each audited action below does not happen when its
// audit record cannot be written: breakChain makes every later append fail.

func TestMirrorKillFailsClosedWhenAuditFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &sys.Session{ID: "mirror-kill-audit-fail", User: "alice"}
	session.SetContext(ctx, cancel)
	registerTestSession(t, session)
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	if _, err := runMirrorVBin(t, eng, []string{"mirror", "kill", session.ID}); err == nil {
		t.Fatal("mirror kill succeeded with a failing audit sink")
	}
	if ctx.Err() != nil {
		t.Fatal("session was terminated although the audit write failed")
	}
}

func TestIdentitySSHCAInitFailsClosedWhenAuditFails(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	out := filepath.Join(t.TempDir(), "ca")
	if _, err := runVBin(t, eng, "", []string{"identity", "ssh-ca", "init", "--out", out}); err == nil {
		t.Fatal("ssh-ca init succeeded with a failing audit sink")
	}
	for _, p := range []string{out, out + ".pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s written although the audit write failed: %v", p, err)
		}
	}
}

func TestGrantFailsClosedWhenAuditFails(t *testing.T) {
	session := &sys.Session{ID: "grant-audit-fail", User: "alice", Principals: []string{"held"}}
	registerTestSession(t, session)
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	if _, err := runVBin(t, eng, session.ID, []string{"grant", "request", "ops"}); err == nil {
		t.Fatal("grant request succeeded with a failing audit sink")
	}
	if _, err := runVBin(t, eng, session.ID, []string{"grant", "drop", "held"}); err == nil {
		t.Fatal("grant drop succeeded with a failing audit sink")
	}
	got := session.PrincipalList()
	if len(got) != 1 || got[0] != "held" {
		t.Fatalf("principals changed although the audit write failed: %v", got)
	}
}
