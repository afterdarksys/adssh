package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every four-eyes test sandboxes HOME so FourEyesDir() (~/.adssh/foureyes)
// never touches the real home directory.

func TestFourEyes_RulesCRUD(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := AddFourEyesRule("rm *", "alice", 60); err != nil {
		t.Fatalf("AddFourEyesRule: %v", err)
	}
	rules, err := LoadFourEyesRules()
	if err != nil {
		t.Fatalf("LoadFourEyesRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d: %+v", len(rules), rules)
	}
	if rules[0].Pattern != "rm *" || rules[0].Approver != "alice" || rules[0].TTL != 60 {
		t.Errorf("unexpected rule: %+v", rules[0])
	}

	// Adding the same pattern again with a different approver/TTL replaces,
	// not duplicates.
	if err := AddFourEyesRule("rm *", "bob", 120); err != nil {
		t.Fatalf("AddFourEyesRule (replace): %v", err)
	}
	rules, err = LoadFourEyesRules()
	if err != nil {
		t.Fatalf("LoadFourEyesRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected replace not duplicate, got %d rules: %+v", len(rules), rules)
	}
	if rules[0].Approver != "bob" || rules[0].TTL != 120 {
		t.Errorf("expected replaced rule (bob, 120), got: %+v", rules[0])
	}

	if err := RemoveFourEyesRule("rm *"); err != nil {
		t.Fatalf("RemoveFourEyesRule: %v", err)
	}
	rules, err = LoadFourEyesRules()
	if err != nil {
		t.Fatalf("LoadFourEyesRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d: %+v", len(rules), rules)
	}
}

func TestFourEyes_DefaultTTL(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := AddFourEyesRule("x", "", 0); err != nil {
		t.Fatalf("AddFourEyesRule: %v", err)
	}
	rules, err := LoadFourEyesRules()
	if err != nil {
		t.Fatalf("LoadFourEyesRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].TTL != 300 {
		t.Errorf("expected default TTL 300 for ttl<=0, got %d", rules[0].TTL)
	}
}

func TestFourEyes_Match(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := AddFourEyesRule("rm *", "", 60); err != nil {
		t.Fatalf("AddFourEyesRule: %v", err)
	}

	// A command with no path separator matches the "rm *" glob directly.
	if rule, matched := MatchesFourEyes("rm -rf x"); !matched || rule == nil || rule.Pattern != "rm *" {
		t.Errorf("expected \"rm -rf x\" to match rule \"rm *\", got rule=%+v matched=%v", rule, matched)
	}

	// GAP CLOSED (Wave 2): MatchesFourEyes now translates the glob into an
	// anchored regexp where '*' matches any characters including spaces and
	// '/'. The textbook dangerous command "rm -rf /" therefore matches a
	// "rm *" rule — exactly the case a human author of that rule expects to
	// be guarded. (Previously filepath.Match's '*' would not cross the '/'
	// separator, so this silently failed to match — a real security gap.)
	if rule, matched := MatchesFourEyes("rm -rf /"); !matched || rule == nil || rule.Pattern != "rm *" {
		t.Errorf("expected \"rm -rf /\" to match rule \"rm *\", got rule=%+v matched=%v", rule, matched)
	}

	// Anchored matching: "rm *" must not match unrelated commands and must
	// not prefix-match a command that merely starts with the same letters.
	if _, matched := MatchesFourEyes("ls"); matched {
		t.Error("expected \"ls\" not to match rule \"rm *\"")
	}
	if _, matched := MatchesFourEyes("format"); matched {
		t.Error("expected \"format\" not to match rule \"rm *\" (no false prefix match)")
	}
}

func TestFourEyes_Match_SubstringGlob(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := AddFourEyesRule("*prod*", "", 60); err != nil {
		t.Fatalf("AddFourEyesRule: %v", err)
	}

	// A "*prod*" pattern must match a command containing "prod" anywhere,
	// including across spaces and hyphenated tokens.
	if rule, matched := MatchesFourEyes("kubectl delete pod --context prod-1"); !matched || rule == nil || rule.Pattern != "*prod*" {
		t.Errorf("expected \"kubectl delete pod --context prod-1\" to match rule \"*prod*\", got rule=%+v matched=%v", rule, matched)
	}
}

func TestCheckFourEyes_NoRules_NoOp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	start := time.Now()
	if err := CheckFourEyes("rm", []string{"rm", "-rf"}, nil); err != nil {
		t.Fatalf("expected nil error with no rules file, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("expected CheckFourEyes to return instantly with no rules, took %v", elapsed)
	}
}

func TestFourEyes_ApproveDenyMarkers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := ensureFourEyesDirs(); err != nil {
		t.Fatalf("ensureFourEyesDirs: %v", err)
	}

	// --- approve ---
	pendingFile1 := filepath.Join(fourEyesPendingDir(), "tok1.json")
	if err := os.WriteFile(pendingFile1, []byte(`{"token":"tok1"}`), 0600); err != nil {
		t.Fatalf("seed pending file: %v", err)
	}
	if err := ApproveRequest("tok1"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	approvedPath := filepath.Join(fourEyesApprovedDir(), "tok1")
	if _, err := os.Stat(approvedPath); err != nil {
		t.Errorf("expected approved marker at %s: %v", approvedPath, err)
	}
	if _, err := os.Stat(pendingFile1); !os.IsNotExist(err) {
		t.Errorf("expected pending file removed after approve, stat err=%v", err)
	}

	// --- deny ---
	pendingFile2 := filepath.Join(fourEyesPendingDir(), "tok2.json")
	if err := os.WriteFile(pendingFile2, []byte(`{"token":"tok2"}`), 0600); err != nil {
		t.Fatalf("seed pending file: %v", err)
	}
	if err := DenyRequest("tok2"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}
	deniedPath := filepath.Join(fourEyesDeniedDir(), "tok2")
	if _, err := os.Stat(deniedPath); err != nil {
		t.Errorf("expected denied marker at %s: %v", deniedPath, err)
	}
	if _, err := os.Stat(pendingFile2); !os.IsNotExist(err) {
		t.Errorf("expected pending file removed after deny, stat err=%v", err)
	}
}

func TestFourEyes_Timeout(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// TTL=1 second. Use a command with no path separator so it actually
	// matches "rm *" (see CHARACTERIZATION note in TestFourEyes_Match about
	// why "rm -rf /" would NOT match and would short-circuit before ever
	// reaching RequestApproval).
	if err := AddFourEyesRule("rm *", "", 1); err != nil {
		t.Fatalf("AddFourEyesRule: %v", err)
	}

	start := time.Now()
	err := CheckFourEyes("rm", []string{"rm", "-rf", "x"}, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected \"timed out\" in error, got: %v", err)
	}
	// RequestApproval's loop sleeps 2s between checks, so a TTL=1 request
	// still takes ~2s wall-clock to time out.
	if elapsed < time.Second {
		t.Errorf("expected timeout to take at least ~1s, took %v", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("expected timeout to take roughly ~2s, took %v", elapsed)
	}

	// Pending file must be cleaned up on timeout.
	entries, rerr := os.ReadDir(fourEyesPendingDir())
	if rerr != nil {
		t.Fatalf("ReadDir pending: %v", rerr)
	}
	for _, e := range entries {
		t.Errorf("expected pending dir empty after timeout cleanup, found: %s", e.Name())
	}
}
