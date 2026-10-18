//go:build ee

package security

import (
	"os"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestCMRequireIsSessionScoped(t *testing.T) {
	t.Setenv("ADSSH_CM_PATTERNS", "")
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runVBin(t, eng, "cm-a", []string{"cm", "require", "deploy*"}); err != nil {
		t.Fatal(err)
	}
	if !eng.CMRequiredForSession("cm-a", "deploy-prod") {
		t.Fatal("cm require did not apply to the caller's session")
	}
	if eng.CMRequiredForSession("cm-b", "deploy-prod") {
		t.Fatal("cm require in one session applied to another session")
	}
	if got := os.Getenv("ADSSH_CM_PATTERNS"); got != "" {
		t.Fatalf("cm require changed the process environment: %q", got)
	}
	t.Setenv("ADSSH_CM_STRICT", "1")
	if err := eng.CMSessionCheckForSession("cm-a", "deploy-prod", nil); err == nil {
		t.Fatal("strict check ignored the session's required pattern")
	}
	if err := eng.CMSessionCheckForSession("cm-b", "deploy-prod", nil); err != nil {
		t.Fatalf("another session was gated by the pattern: %v", err)
	}
}

func TestCMDefaultPatternsReadAtEngineStartup(t *testing.T) {
	t.Setenv("ADSSH_CM_PATTERNS", "rm, kubectl*")
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_CM_PATTERNS", "ls")
	for _, s := range []string{"", "any-session"} {
		if !eng.CMRequiredForSession(s, "/bin/rm") || !eng.CMRequiredForSession(s, "kubectl") {
			t.Fatalf("session %q lost the startup default", s)
		}
		if eng.CMRequiredForSession(s, "ls") {
			t.Fatalf("session %q read the environment after startup", s)
		}
	}
}

func TestSSHMonitorRunCMRequireScopedToBoundSession(t *testing.T) {
	t.Setenv("ADSSH_CM_PATTERNS", "")
	eng, _, _ := chainEngine(t)
	id := "run-cm-require"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	gate, run := listenerRun(eng, id)
	c := dialMonitorRun(t, id, gate, run)
	sendRun(t, c, 1, []string{"cm", "require", "deploy*"}, nil)
	res := readRun(t, c, 1)
	if res.exit.Code != 0 || !strings.Contains(res.stdout.String(), "deploy*") {
		t.Fatalf("cm require over Run: exit=%+v stdout=%q", res.exit, res.stdout.String())
	}
	if !eng.CMRequiredForSession(id, "deploy-prod") {
		t.Fatal("cm require over Run did not apply to the bound session")
	}
	if eng.CMRequiredForSession("other-session", "deploy-prod") || eng.CMRequiredForSession("", "deploy-prod") {
		t.Fatal("cm require over Run applied beyond the bound session")
	}
	if got := os.Getenv("ADSSH_CM_PATTERNS"); got != "" {
		t.Fatalf("cm require over Run changed the listener environment: %q", got)
	}
}
