//go:build ee

package security

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

type mirrorShareFixture struct {
	eng       *Engine
	chainPath string
	owner     *sys.Session
	viewer    *sys.Session
	admin     *sys.Session
}

func newMirrorShareFixture(t *testing.T, prefix string) *mirrorShareFixture {
	t.Helper()
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    "supervisor",
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &mirrorShareFixture{
		eng:       eng,
		chainPath: chainPath,
		owner:     &sys.Session{ID: prefix + "-owner", User: "alice", Out: sys.NewOutputBroadcaster(&bytes.Buffer{})},
		viewer:    &sys.Session{ID: prefix + "-viewer", User: "bob"},
		admin:     &sys.Session{ID: prefix + "-admin", User: "root-op", Principals: []string{RoleAdsshAdmin}},
	}
	for _, s := range []*sys.Session{f.owner, f.viewer, f.admin} {
		if err := sys.RegisterSession(s); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, s := range []*sys.Session{f.owner, f.viewer, f.admin} {
			sys.UnregisterSession(s.ID)
		}
		clearMirrorGrants(f.owner.ID)
	})
	return f
}

func (f *mirrorShareFixture) run(t *testing.T, sessionID string, args ...string) (string, error) {
	t.Helper()
	return runSessionVBin(t, f.eng, mirrorBinary{}, sessionID, args)
}

// attach runs mirror view/console with an already-canceled context so a
// permitted attach returns at once.
func (f *mirrorShareFixture) attach(t *testing.T, sessionID, mode string) error {
	t.Helper()
	return f.eng.mirrorAuthorize(sessionID, f.owner.ID, mode == "console")
}

func (f *mirrorShareFixture) chain(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.chainPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMirrorShareNonPrivilegedViewerNeedsGrant(t *testing.T) {
	f := newMirrorShareFixture(t, "ms-grant")
	if err := f.attach(t, f.viewer.ID, "view"); err == nil {
		t.Fatal("non-privileged user viewed another session without a grant")
	}
	if _, err := f.run(t, f.viewer.ID, "mirror", "view", f.owner.ID); err == nil {
		t.Fatal("mirror view without a grant succeeded")
	}
	if err := f.attach(t, f.admin.ID, "view"); err != nil {
		t.Fatalf("privileged path refused: %v", err)
	}
	if err := f.attach(t, f.owner.ID, "console"); err != nil {
		t.Fatalf("owner refused on own session: %v", err)
	}

	out, err := f.run(t, f.owner.ID, "mirror", "share", "--with", "bob", "--for", "10m")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "bob") || !strings.Contains(out, "view") {
		t.Fatalf("share output = %q", out)
	}
	if err := f.attach(t, f.viewer.ID, "view"); err != nil {
		t.Fatalf("granted viewer refused: %v", err)
	}
	if err := f.attach(t, f.viewer.ID, "console"); err == nil {
		t.Fatal("view grant allowed console")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.eng.mirrorAttach(ctx, f.viewer.ID, f.owner.ID, false, &bytes.Buffer{}, nil); err != nil {
		t.Fatalf("granted attach: %v", err)
	}

	chain := f.chain(t)
	for _, want := range []string{
		"MIRROR_SHARE: session=" + f.owner.ID + " owner=alice with=bob mode=view",
		"MIRROR_DENIED: session=" + f.owner.ID + " user=bob mode=view",
		"MIRROR_ATTACH: session=" + f.owner.ID + " user=bob mode=view via=grant",
	} {
		if !strings.Contains(chain, want) {
			t.Fatalf("chain missing %q:\n%s", want, chain)
		}
	}
}

func TestMirrorShareConsoleRequiresConsoleFlag(t *testing.T) {
	f := newMirrorShareFixture(t, "ms-console")
	if _, err := f.run(t, f.owner.ID, "mirror", "share", "--with", "bob", "--for", "5m", "--console"); err != nil {
		t.Fatal(err)
	}
	if err := f.attach(t, f.viewer.ID, "console"); err != nil {
		t.Fatalf("console grant refused: %v", err)
	}
	if err := f.attach(t, f.viewer.ID, "view"); err != nil {
		t.Fatalf("console grant must include view: %v", err)
	}
	if !strings.Contains(f.chain(t), "with=bob mode=console") {
		t.Fatalf("console grant not audited:\n%s", f.chain(t))
	}
}

func TestMirrorUnshareRevokes(t *testing.T) {
	f := newMirrorShareFixture(t, "ms-revoke")
	if _, err := f.run(t, f.owner.ID, "mirror", "share", "--with", "bob", "--for", "10m"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, f.owner.ID, "mirror", "unshare", "--with", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := f.attach(t, f.viewer.ID, "view"); err == nil {
		t.Fatal("viewer still allowed after unshare")
	}
	if !strings.Contains(f.chain(t), "MIRROR_UNSHARE: session="+f.owner.ID+" owner=alice with=bob") {
		t.Fatalf("unshare not audited:\n%s", f.chain(t))
	}
	if _, err := f.run(t, f.owner.ID, "mirror", "unshare", "--with", "bob"); err == nil {
		t.Fatal("unshare of a missing grant succeeded")
	}
}

func TestMirrorShareExpires(t *testing.T) {
	f := newMirrorShareFixture(t, "ms-expire")
	now := time.Now()
	restore := setMirrorClock(func() time.Time { return now })
	t.Cleanup(restore)
	if _, err := f.run(t, f.owner.ID, "mirror", "share", "--with", "bob", "--for", "10m"); err != nil {
		t.Fatal(err)
	}
	if err := f.attach(t, f.viewer.ID, "view"); err != nil {
		t.Fatalf("fresh grant refused: %v", err)
	}
	now = now.Add(10*time.Minute + time.Second)
	if err := f.attach(t, f.viewer.ID, "view"); err == nil {
		t.Fatal("expired grant still allowed")
	}
	chain := f.chain(t)
	if !strings.Contains(chain, "MIRROR_SHARE_EXPIRED: session="+f.owner.ID+" owner=alice with=bob") {
		t.Fatalf("expiry not audited:\n%s", chain)
	}
	if strings.Count(chain, "MIRROR_SHARE_EXPIRED") != 1 {
		t.Fatalf("expiry audited more than once:\n%s", chain)
	}
}

func TestMirrorShareTimerExpiryAudits(t *testing.T) {
	f := newMirrorShareFixture(t, "ms-timer")
	if err := f.eng.shareMirror(f.owner.ID, "bob", 20*time.Millisecond, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(f.chain(t), "MIRROR_SHARE_EXPIRED") {
		if time.Now().After(deadline) {
			t.Fatalf("timer expiry not audited:\n%s", f.chain(t))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := f.attach(t, f.viewer.ID, "view"); err == nil {
		t.Fatal("grant survived its timer")
	}
}

func TestMirrorShareRejectsBadInput(t *testing.T) {
	f := newMirrorShareFixture(t, "ms-bad")
	for _, args := range [][]string{
		{"mirror", "share"},
		{"mirror", "share", "--with", "bob"},
		{"mirror", "share", "--for", "10m"},
		{"mirror", "share", "--with", "bob", "--for", "0s"},
		{"mirror", "share", "--with", "bob", "--for", "-1m"},
		{"mirror", "share", "--with", "bob", "--for", "25h"},
		{"mirror", "share", "--with", "bob", "--for", "soon"},
		{"mirror", "share", "--with", "alice", "--for", "10m"},
		{"mirror", "share", "--with", "bob;rm", "--for", "10m"},
		{"mirror", "share", "--with", "bob", "--for", "10m", "--bogus"},
	} {
		if _, err := f.run(t, f.owner.ID, args...); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	// A session that is not registered cannot share.
	if _, err := f.run(t, "ms-bad-nobody", "mirror", "share", "--with", "bob", "--for", "10m"); err == nil {
		t.Fatal("share from an unknown session accepted")
	}
	if err := f.attach(t, f.viewer.ID, "view"); err == nil {
		t.Fatal("a rejected share granted access")
	}
}

func TestMirrorShareAgentCannotShareOrView(t *testing.T) {
	f := newMirrorShareFixture(t, "ms-agent")
	agent := &sys.Session{ID: "ms-agent-agent", User: "bob"}
	if err := sys.RegisterSession(agent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(agent.ID) })
	agent.BindManagedAgent(&sys.ManagedAgent{ID: "a1", ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := f.run(t, f.owner.ID, "mirror", "share", "--with", "bob", "--for", "10m"); err != nil {
		t.Fatal(err)
	}
	if err := f.attach(t, agent.ID, "view"); err == nil {
		t.Fatal("agent session used a grant made for its user")
	}
	if _, err := f.run(t, agent.ID, "mirror", "share", "--with", "carol", "--for", "10m"); err == nil {
		t.Fatal("agent session shared")
	}
}

func TestPolicyExampleMirrorShare(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "policy", "examples", "mirror_share.rego"))
	if err != nil {
		t.Fatal(err)
	}
	eng := newPolicyEngine(t, string(data))
	decide := func(groups []string, args ...string) PolicyDecision {
		t.Helper()
		d, err := eng.EvaluatePolicyDecision(PolicyContext{User: "alice", Groups: groups, Command: "mirror", Args: args})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := decide(nil, "share", "--with", "bob", "--for", "10m"); !d.Allowed {
		t.Fatalf("10m view share denied: %#v", d)
	}
	if d := decide(nil, "share", "--with", "bob", "--for", "2h"); d.Allowed || d.Rule == "" {
		t.Fatalf("2h share allowed or unnamed: %#v", d)
	}
	if d := decide(nil, "share", "--with", "bob", "--for", "10m", "--console"); d.Allowed || d.RequiredRole == "" {
		t.Fatalf("console share by non-lead: %#v", d)
	}
	if d := decide([]string{"oncall-lead"}, "share", "--with", "bob", "--for", "10m", "--console"); !d.Allowed {
		t.Fatalf("console share by lead denied: %#v", d)
	}
}
