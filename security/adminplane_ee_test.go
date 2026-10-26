//go:build ee

package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

func guardPlane(t *testing.T) {
	t.Helper()
	prevDo, prevEuid, prevLookup := doRun, doEuid, doLookup
	prevUnit, prevInvoke, prevJournal := unitRun, unitInvoke, journalRun
	prevChmod := hostChmod
	prevNet, prevShow, prevDisk := netRun, netShow, diskRun
	prevWalk := walkClose
	t.Cleanup(func() {
		doRun, doEuid, doLookup = prevDo, prevEuid, prevLookup
		unitRun, unitInvoke, journalRun = prevUnit, prevInvoke, prevJournal
		hostChmod = prevChmod
		netRun, netShow, diskRun = prevNet, prevShow, prevDisk
		walkClose = prevWalk
	})
	doRun, doEuid, doLookup = nil, nil, nil
	unitRun, unitInvoke, journalRun = nil, nil, nil
	hostChmod = os.Chmod
	netRun, netShow, diskRun = nil, nil, nil
	walkClose = nil
	for _, key := range []string{
		"ADSSH_QUARANTINE",
		"ADSSH_QUARANTINE_FILE",
		"ADSSH_SAH_REQUIRE_LEASE",
		"ADSSH_REFUSE_ALLOW_ALL",
		"ADSSH_HOST_PROFILE",
		"ADSSH_HOST_PROFILE_PREV",
		"ADSSH_HOST_PROFILE_KEYS",
		"ADSSH_HOST_PROFILE_NARROW",
		"ADSSH_HOST_ID",
		"ADSSH_AGENT_UNIT",
		"ADSSH_ADMIN_LISTEN",
		"ADSSH_SAH_LEASE_KEYS",
		"ADSSH_SAH_ISSUER",
		"ADSSH_SAH_HOST_ID",
		"ADSSH_SAH_LEASE_STATE",
	} {
		t.Setenv(key, "")
	}
}

func planeID(t *testing.T, suffix string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name() + "/" + suffix))
	return "s" + hex.EncodeToString(sum[:8])
}

func planeCtx(eng *Engine, sid string) context.Context {
	return WithSessionID(context.WithValue(context.Background(), engineCtxKey, eng), sid)
}

func registerPlane(t *testing.T, id, user string) {
	t.Helper()
	if err := sys.RegisterSession(&sys.Session{ID: id, User: user}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
}

func adminFix(t *testing.T) (*Engine, context.Context, string) {
	t.Helper()
	guardPlane(t)
	eng := policyEngine(t, allowAllPolicy)
	sid := planeID(t, "s")
	registerPlane(t, sid, "alice")
	return eng, planeCtx(eng, sid), sid
}

func breakAudit(t *testing.T, eng *Engine) {
	t.Helper()
	eng.chainPath = t.TempDir()
	eng.chainKey = bytesOf(7, 32)
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func denyEngine(t *testing.T) *Engine {
	t.Helper()
	return policyEngine(t, "package adssh.authz\ndefault allow = false\n")
}

func TestAdminPlaneRawNamesRefused(t *testing.T) {
	eng, _, sid := adminFix(t)
	names := []string{"sudo", "systemctl", "journalctl", "apt", "apt-get", "/usr/bin/sudo"}
	for _, name := range names {
		equalErr(t, eng.AuthorizeCommand([]string{name}, sid), "admin plane: raw admin name refused")
	}
	if err := eng.AuthorizeCommand([]string{"id"}, sid); err != nil {
		t.Fatal(err)
	}
}

func TestAdminPlaneAgentRawNameIsAllowlist(t *testing.T) {
	eng, _, sid := adminFix(t)
	sess := sys.GetSession(sid)
	sess.BindManagedAgent(&sys.ManagedAgent{ID: "agent-1", ExpiresAt: time.Now().Add(time.Hour)})
	equalErr(t, eng.AuthorizeCommand([]string{"sudo"}, sid), `adssh: agent cannot run "sudo"`)
	rewritten, note, err := rewriteAdminPlane([]string{"sudo", "--", "--user", "alice", "--reason", "box", "--", "id"})
	if err != nil || note != "alias: sudo → do" || len(rewritten) == 0 || rewritten[0] != "do" {
		t.Fatalf("rewrite = %v %q %v", rewritten, note, err)
	}
	equalErr(t, eng.AuthorizeCommand([]string{"do"}, sid), `adssh: agent cannot run "do"`)
}

func TestRewriteAdminPlane(t *testing.T) {
	ok := []struct {
		in   []string
		out  []string
		note string
	}{
		{
			[]string{"sudo", "--user", "alice", "--reason", "box office", "--", "id"},
			[]string{"do", "--user", "alice", "--reason", "box office", "--", "id"},
			"alias: sudo → do",
		},
		{
			[]string{"sudo", "--", "--user", "alice", "--reason", "box office", "--", "id"},
			[]string{"do", "--", "--user", "alice", "--reason", "box office", "--", "id"},
			"alias: sudo → do",
		},
		{
			[]string{"/usr/bin/sudo", "--", "id"},
			[]string{"do", "--", "id"},
			"alias: sudo → do",
		},
		{
			[]string{"systemctl", "status", "nginx.service"},
			[]string{"unit", "status", "nginx.service"},
			"alias: systemctl → unit",
		},
		{
			[]string{"/usr/bin/systemctl", "restart", "nginx.service"},
			[]string{"unit", "restart", "nginx.service"},
			"alias: systemctl → unit",
		},
		{
			[]string{"systemctl", "stop", "nginx.service"},
			[]string{"unit", "stop", "nginx.service"},
			"alias: systemctl → unit",
		},
		{
			[]string{"journalctl", "-u", "nginx.service"},
			[]string{"unit", "logs", "nginx.service"},
			"alias: journalctl → unit logs",
		},
		{
			[]string{"journalctl", "-u", "nginx.service", "--no-pager"},
			[]string{"unit", "logs", "nginx.service"},
			"alias: journalctl → unit logs",
		},
		{
			[]string{"journalctl", "--no-pager", "-u", "nginx.service"},
			[]string{"unit", "logs", "nginx.service"},
			"alias: journalctl → unit logs",
		},
		{
			[]string{"ls", "-la"},
			[]string{"ls", "-la"},
			"",
		},
	}
	for _, tc := range ok {
		got, note, err := rewriteAdminPlane(tc.in)
		if err != nil || note != tc.note || !sameArgs(got, tc.out) {
			t.Fatalf("%v → %v %q %v", tc.in, got, note, err)
		}
	}
	refused := []struct {
		in   []string
		want string
	}{
		{[]string{"sudo", "id"}, "alias: sudo is refused; the governed verb is do"},
		{[]string{"systemctl", "status", "nginx.service", "--no-pager"}, "alias: systemctl is refused; the governed verb is unit"},
		{[]string{"systemctl"}, "alias: systemctl is refused; the governed verb is unit"},
		{[]string{"journalctl"}, "alias: journalctl is refused; the governed verb is unit logs NAME"},
		{[]string{"journalctl", "-n", "20"}, "alias: journalctl is refused; the governed verb is unit logs NAME"},
		{[]string{"apt", "install", "nginx"}, "alias: apt is refused; the governed verb is package"},
		{[]string{"apt-get", "update"}, "alias: apt is refused; the governed verb is package"},
		{[]string{"/usr/bin/apt", "install", "nginx"}, "alias: apt is refused; the governed verb is package"},
	}
	for _, tc := range refused {
		_, _, err := rewriteAdminPlane(tc.in)
		equalErr(t, err, tc.want)
	}
}

func sameArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestQuarantineGate(t *testing.T) {
	eng, _, sid := adminFix(t)
	if err := eng.AuthorizeCommand([]string{"id"}, sid); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_QUARANTINE", "1")
	equalErr(t, eng.AuthorizeCommand([]string{"id"}, sid), "admin plane: quarantine")
	equalErr(t, eng.AuthorizeCommand([]string{"package", "list"}, sid), "admin plane: quarantine")
	equalErr(t, eng.AuthorizeCommand([]string{"unit", "stop", "nginx.service"}, sid), "admin plane: quarantine")
	allowed := [][]string{
		{"journal"},
		{"host", "drift"},
		{"host", "status"},
		{"host", "verify"},
		{"unit", "check"},
		{"unit", "timers"},
		{"unit", "status", "nginx.service"},
		{"unit", "logs", "nginx.service"},
		{"net"},
		{"disk"},
		{"posture"},
		{"asof"},
		{"why"},
		{"evidence"},
	}
	for _, args := range allowed {
		if err := eng.AuthorizeCommand(args, sid); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	t.Setenv("ADSSH_AGENT_UNIT", "agent.service")
	if err := eng.AuthorizeCommand([]string{"unit", "restart", "agent.service"}, sid); err != nil {
		t.Fatal(err)
	}
	equalErr(t, eng.AuthorizeCommand([]string{"unit", "restart", "nginx.service"}, sid), "admin plane: quarantine")
}

func TestQuarantineFileActivates(t *testing.T) {
	eng, _, sid := adminFix(t)
	missing := filepath.Join(t.TempDir(), "absent")
	t.Setenv("ADSSH_QUARANTINE_FILE", missing)
	if err := eng.AuthorizeCommand([]string{"id"}, sid); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "mark")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_QUARANTINE_FILE", link)
	equalErr(t, eng.AuthorizeCommand([]string{"id"}, sid), "admin plane: quarantine")
}

func TestQuarantineFileENOTDIR(t *testing.T) {
	eng, _, sid := adminFix(t)
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_QUARANTINE_FILE", parent+"/child")
	equalErr(t, eng.AuthorizeCommand([]string{"id"}, sid), "admin plane: quarantine")
}

func TestPackageRefusedInRecoverAndQuarantine(t *testing.T) {
	_, ctx, _ := adminFix(t)
	equalErr(t, packageBinary{}.Run(WithRecover(ctx), []string{"package", "list"}), "package: refused")
	t.Setenv("ADSSH_QUARANTINE", "1")
	equalErr(t, packageBinary{}.Run(context.Background(), []string{"package", "list"}), "package: refused")
}

func TestRecoverGateDoesNotSeeAuthorizeCommand(t *testing.T) {
	eng, _, sid := adminFix(t)
	if err := eng.AuthorizeCommand([]string{"package", "list"}, sid); err != nil {
		t.Fatal(err)
	}
}

func TestLiftQuarantine(t *testing.T) {
	guardPlane(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := writeKeyLine(t, "k1", pub, 0o600)
	t.Setenv("ADSSH_HOST_PROFILE_KEYS", keys)
	payload, err := json.Marshal(map[string]any{"v": 1, "action": "lift"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := signEnvelope([]testSigner{{Kid: "k1", Priv: priv}}, payload)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "q")
	if err := os.WriteFile(path, []byte("on"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LiftQuarantine(path, body); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("file remained: %v", err)
	}

	if err := os.WriteFile(path, []byte("on"), 0o600); err != nil {
		t.Fatal(err)
	}
	var env signedEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	env.Sigs[0].Sig = "aaaa"
	bad, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	err = LiftQuarantine(path, bad)
	equalErr(t, err, errSignedPayload.Error())
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatal(statErr)
	}

	wrongPayload, err := json.Marshal(map[string]any{"v": 1, "action": "nope"})
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := signEnvelope([]testSigner{{Kid: "k1", Priv: priv}}, wrongPayload)
	if err != nil {
		t.Fatal(err)
	}
	err = LiftQuarantine(path, wrong)
	equalErr(t, err, errSignedPayload.Error())
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatal(statErr)
	}

	t.Setenv("ADSSH_HOST_PROFILE_KEYS", filepath.Join(t.TempDir(), "missing-keys"))
	err = LiftQuarantine(path, body)
	if err == nil || errors.Is(err, errSignedPayload) {
		t.Fatalf("key load = %v", err)
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatal(statErr)
	}

	t.Setenv("ADSSH_HOST_PROFILE_KEYS", keys)
	t.Setenv("ADSSH_QUARANTINE", "1")
	if err := LiftQuarantine(path, body); err != nil {
		t.Fatal(err)
	}
	eng := policyEngine(t, allowAllPolicy)
	sid := planeID(t, "s")
	registerPlane(t, sid, "alice")
	equalErr(t, eng.AuthorizeCommand([]string{"id"}, sid), "admin plane: quarantine")
}

func TestAgentBudget(t *testing.T) {
	eng, _, sponsor := adminFix(t)
	worker := planeID(t, "w")
	registerPlane(t, worker, "alice")
	t.Cleanup(func() { ClearAgentBudget(worker) })

	equalErr(t, BindAgentBudget("", AgentBudget{Allow: []string{"why"}, Cmds: 1, Bytes: 10, Sponsor: sponsor}), "admin plane: agent budget")

	if err := BindAgentBudget(worker, AgentBudget{Allow: []string{"why"}, Cmds: 1, Bytes: 10, Sponsor: sponsor}); err != nil {
		t.Fatal(err)
	}
	if err := eng.AuthorizeCommand([]string{"why"}, worker); err != nil {
		t.Fatal(err)
	}
	equalErr(t, eng.AuthorizeCommand([]string{"why"}, worker), "admin plane: agent budget")
	ClearAgentBudget(worker)
	if err := eng.AuthorizeCommand([]string{"why"}, worker); err != nil {
		t.Fatal(err)
	}

	if err := BindAgentBudget(worker, AgentBudget{Allow: []string{"why"}, Cmds: 5, Bytes: 0, Sponsor: sponsor}); err != nil {
		t.Fatal(err)
	}
	equalErr(t, eng.AuthorizeCommand([]string{"why"}, worker), "admin plane: agent budget")

	if err := BindAgentBudget(worker, AgentBudget{Allow: []string{"id"}, Cmds: 5, Bytes: 10, Sponsor: sponsor}); err != nil {
		t.Fatal(err)
	}
	equalErr(t, eng.AuthorizeCommand([]string{"why"}, worker), "admin plane: agent budget")

	if err := BindAgentBudget(worker, AgentBudget{Allow: []string{"why"}, Cmds: 5, Bytes: 10, Sponsor: sponsor, Deadline: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	equalErr(t, eng.AuthorizeCommand([]string{"why"}, worker), "admin plane: agent budget")

	if err := BindAgentBudget(worker, AgentBudget{Allow: []string{"why"}, Cmds: 5, Bytes: 10, Sponsor: ""}); err != nil {
		t.Fatal(err)
	}
	equalErr(t, eng.AuthorizeCommand([]string{"why"}, worker), "admin plane: agent sponsor ended")

	if err := BindAgentBudget(worker, AgentBudget{Allow: []string{"why"}, Cmds: 5, Bytes: 10, Sponsor: sponsor}); err != nil {
		t.Fatal(err)
	}
	sys.GetSession(sponsor).Terminate()
	equalErr(t, eng.AuthorizeCommand([]string{"why"}, worker), "admin plane: agent sponsor ended")
}
