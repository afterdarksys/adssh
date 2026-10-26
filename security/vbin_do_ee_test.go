//go:build ee

package security

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

func doHappyArgs(user, argv0 string, rest ...string) []string {
	args := []string{"do", "--", "--user", user, "--reason", "box office", "--", argv0}
	return append(args, rest...)
}

func armDo(t *testing.T) {
	t.Helper()
	doEuid = func() int { return 0 }
	doLookup = func(name string) (doUser, error) {
		return doUser{Name: name, Uid: "10", Gid: "20", Home: "/home/" + name}, nil
	}
}

func TestDoHelpAndUsage(t *testing.T) {
	_, ctx, _ := adminFix(t)
	if err := (doBinary{}).Run(ctx, []string{"do", "--help"}); err != nil {
		t.Fatal(err)
	}
	usage := "do: usage: do --user NAME --reason TEXT -- argv"
	bad := [][]string{
		{"do"},
		{"do", "--", "id"},
		{"do", "--user", "alice", "--reason", "box", "id"},
		{"do", "--user", "", "--reason", "box", "--", "id"},
		{"do", "--user", "alice", "--reason", "", "--", "id"},
		{"do", "--user", "alice", "--reason", "box"},
		{"do", "--user", "alice", "--user", "bob", "--reason", "box", "--", "id"},
		{"do", "--user", "alice", "--reason", "a=b", "--", "id"},
		{"do", "--user", "alice", "--reason", "a\nb", "--", "id"},
		{"do", "--user", "alice", "--reason", "box", "--", "id\n"},
	}
	for _, args := range bad {
		equalErr(t, (doBinary{}).Run(ctx, args), usage)
	}
}

func TestDoRefusedBeforeSessionAndEuid(t *testing.T) {
	_, ctx, sid := adminFix(t)
	called := false
	doEuid = func() int { called = true; return 0 }
	equalErr(t, (doBinary{}).Run(WithRecover(ctx), doHappyArgs("alice", "id")), "do: refused")
	t.Setenv("ADSSH_QUARANTINE", "1")
	equalErr(t, (doBinary{}).Run(context.Background(), doHappyArgs("alice", "id")), "do: refused")
	if called {
		t.Fatal("euid ran")
	}
	t.Setenv("ADSSH_QUARANTINE", "")
	equalErr(t, (doBinary{}).Run(context.Background(), doHappyArgs("alice", "id")), "do: requires a session")
	if called {
		t.Fatal("euid ran")
	}
	sess := sys.GetSession(sid)
	sess.BindManagedAgent(&sys.ManagedAgent{ID: "agent-1", ExpiresAt: time.Now().Add(time.Hour)})
	equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", "id")), "do: agents cannot run do")
	if called {
		t.Fatal("euid ran")
	}
}

func TestDoRefusesNameBeforeLookup(t *testing.T) {
	_, ctx, _ := adminFix(t)
	euid, lookup := false, false
	doEuid = func() int { euid = true; return 0 }
	doLookup = func(name string) (doUser, error) { lookup = true; return doUser{}, nil }
	for _, name := range []string{"123", "a/b", "a b", "a=b"} {
		equalErr(t, (doBinary{}).Run(ctx, doHappyArgs(name, "id")), "do: user refused")
	}
	if euid || lookup {
		t.Fatal("name check reached euid or lookup")
	}
}

func TestDoEuidNotZeroDoesNotLookup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("euid is 0")
	}
	_, ctx, _ := adminFix(t)
	before := os.Geteuid()
	lookup, ran := false, false
	doLookup = func(name string) (doUser, error) { lookup = true; return doUser{}, nil }
	doRun = func(context.Context, []string, []string, *syscall.Credential) (string, int, error) {
		ran = true
		return "", 0, nil
	}
	equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", "id")), "do: euid is not 0")
	if lookup || ran || os.Geteuid() != before {
		t.Fatal("parent euid changed or lookup ran")
	}
}

func TestDoAccountAndShell(t *testing.T) {
	_, ctx, _ := adminFix(t)
	doEuid = func() int { return 0 }
	ran := false
	doRun = func(context.Context, []string, []string, *syscall.Credential) (string, int, error) {
		ran = true
		return "", 0, nil
	}
	doLookup = func(name string) (doUser, error) { return doUser{}, errors.New("missing") }
	equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", "id")), "do: user refused")
	doLookup = func(name string) (doUser, error) {
		return doUser{Name: name, Uid: "nope", Gid: "20", Home: "/home/alice"}, nil
	}
	equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", "id")), "do: user refused")
	doLookup = func(name string) (doUser, error) {
		return doUser{Name: name, Uid: "10", Gid: "20", Home: "/home/alice"}, nil
	}
	for _, argv0 := range []string{"bash", "/bin/sh", "/usr/bin/su"} {
		equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", argv0)), "do: shell is refused")
	}
	if ran {
		t.Fatal("runner called")
	}
}

func TestDoPolicyAndAuditDoNotExec(t *testing.T) {
	_, _, sid := adminFix(t)
	eng := denyEngine(t)
	ctx := planeCtx(eng, sid)
	armDo(t)
	ran := false
	doRun = func(context.Context, []string, []string, *syscall.Credential) (string, int, error) {
		ran = true
		return "", 0, nil
	}
	equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", "id")), "adssh: access denied for 'id' by policy")
	if ran {
		t.Fatal("runner called")
	}
	sys.UnregisterSession(sid)
	eng, ctx, _ = adminFix(t)
	armDo(t)
	breakAudit(t, eng)
	err := (doBinary{}).Run(ctx, doHappyArgs("alice", "id"))
	if err == nil || !strings.HasPrefix(err.Error(), "adssh: audit log failed:") || ran {
		t.Fatalf("audit: %v ran=%v", err, ran)
	}
}

func TestDoExecutesChildOnce(t *testing.T) {
	eng, ctx, sid := adminFix(t)
	armDo(t)
	t.Setenv("ADSSH_LEAK", "sekrit")
	before := os.Geteuid()
	var gotArgv, gotEnv []string
	var got syscall.Credential
	doRun = func(_ context.Context, argv []string, env []string, cred *syscall.Credential) (string, int, error) {
		gotArgv = append([]string(nil), argv...)
		gotEnv = append([]string(nil), env...)
		if cred != nil {
			got = *cred
		}
		return "uid=10", 0, nil
	}
	out, err := runVBin(t, eng, sid, doHappyArgs("alice", "id"))
	if err != nil {
		t.Fatal(err)
	}
	if out != "uid=10\n" || len(gotArgv) != 1 || gotArgv[0] != "id" {
		t.Fatalf("out %q argv %v", out, gotArgv)
	}
	if got.Uid != 10 || got.Gid != 20 || !got.NoSetGroups || os.Geteuid() != before {
		t.Fatalf("cred %+v euid %d", got, os.Geteuid())
	}
	for _, item := range gotEnv {
		if strings.Contains(item, "ADSSH_") || strings.Contains(item, "sekrit") {
			t.Fatalf("child env %q", item)
		}
	}
	doRun = func(context.Context, []string, []string, *syscall.Credential) (string, int, error) {
		return "nope", 7, nil
	}
	equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", "id")), "do: exit 7")
	doRun = func(context.Context, []string, []string, *syscall.Credential) (string, int, error) {
		return "", 0, errors.New("boom")
	}
	equalErr(t, (doBinary{}).Run(ctx, doHappyArgs("alice", "id")), "do: unavailable")
	var eq []string
	doRun = func(_ context.Context, argv []string, _ []string, _ *syscall.Credential) (string, int, error) {
		eq = append([]string(nil), argv...)
		return "", 0, nil
	}
	if err := (doBinary{}).Run(ctx, []string{"do", "--user", "alice", "--reason", "box", "--", "a=b"}); err != nil {
		t.Fatal(err)
	}
	if len(eq) != 1 || eq[0] != "a=b" {
		t.Fatalf("argv %v", eq)
	}
}
