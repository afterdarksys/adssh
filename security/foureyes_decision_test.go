package security

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runFourEyesVBin(t *testing.T, eng *Engine, sessionID string, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(WithSessionID(ctx, sessionID), fourEyesBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("foureyes-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func registerTestSession(t *testing.T, s *sys.Session) {
	t.Helper()
	if err := sys.RegisterSession(s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(s.ID) })
}

func TestFourEyesShellRefusesRenamedIdentity(t *testing.T) {
	eng, chain, _ := chainEngine(t)

	// alice renamed her session to bob with an unverified login.
	deviceLogin := &sys.Session{ID: "fe-device", User: "alice"}
	registerTestSession(t, deviceLogin)
	deviceLogin.SetIdentity("bob", nil)
	deviceLogin.SetIdentitySource(sys.IdentitySourceDeviceLogin)

	// SetIdentity alone (any runtime rename) is also refused.
	asserted := &sys.Session{ID: "fe-asserted", User: "alice"}
	registerTestSession(t, asserted)
	asserted.SetIdentity("bob", nil)

	agent := &sys.Session{ID: "fe-agent", User: "bob"}
	registerTestSession(t, agent)
	agent.BindManagedAgent(&sys.ManagedAgent{ID: "agent-1", ExpiresAt: time.Now().Add(time.Hour)})

	pendingPath := seedPending(t, eng, "req-shell", "alice", "bob")
	for _, sid := range []string{deviceLogin.ID, asserted.ID, agent.ID, "fe-unregistered", ""} {
		for _, verb := range []string{"approve", "deny"} {
			if _, err := runFourEyesVBin(t, eng, sid, []string{"4eyes", verb, "req-shell"}); err == nil {
				t.Fatalf("session %q %s accepted", sid, verb)
			}
		}
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("refused decision changed the request: %v", err)
	}
	if ledger, _ := os.ReadFile(chain); strings.Contains(string(ledger), "FOUREYES_DECISION") {
		t.Fatalf("refused decision reached the chain:\n%s", ledger)
	}

	// The registered SSH or local identity can approve.
	bob := &sys.Session{ID: "fe-bob", User: "bob"}
	registerTestSession(t, bob)
	if _, err := runFourEyesVBin(t, eng, bob.ID, []string{"4eyes", "approve", "req-shell"}); err != nil {
		t.Fatalf("registered approver refused: %v", err)
	}
	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ledger), "FOUREYES_DECISION request=req-shell approver=bob decision=approve surface=shell") {
		t.Fatalf("chain missing shell decision:\n%s", ledger)
	}
}

func TestFourEyesShellAllowsVerifiedOIDCIdentity(t *testing.T) {
	eng, _, _ := chainEngine(t)
	s := &sys.Session{ID: "fe-oidc", User: "alice"}
	registerTestSession(t, s)
	s.SetIdentity("bob", nil)
	s.SetIdentitySource(sys.IdentitySourceOIDCVerified)
	seedPending(t, eng, "req-oidc", "alice", "bob")
	if _, err := runFourEyesVBin(t, eng, s.ID, []string{"4eyes", "deny", "req-oidc"}); err != nil {
		t.Fatalf("verified identity refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(eng.fourEyesDeniedDir(), "req-oidc")); err != nil {
		t.Fatalf("denied marker missing: %v", err)
	}
}

func TestFourEyesDecisionAuditFailureWritesNoMarker(t *testing.T) {
	for _, approve := range []bool{true, false} {
		eng, chain, _ := chainEngine(t)
		pendingPath := seedPending(t, eng, "req-fail", "alice", "")
		breakChain(t, eng, chain)
		if err := eng.DecideRequest("req-fail", "bob", FourEyesSurfaceShell, approve); err == nil {
			t.Fatalf("approve=%v succeeded with a failing audit sink", approve)
		}
		for _, dir := range []string{eng.fourEyesApprovedDir(), eng.fourEyesDeniedDir()} {
			if _, err := os.Stat(filepath.Join(dir, "req-fail")); !os.IsNotExist(err) {
				t.Fatalf("marker in %s written without audit: %v", dir, err)
			}
		}
		if _, err := os.Stat(pendingPath); err != nil {
			t.Fatalf("pending request not restored: %v", err)
		}
	}
}

func TestFourEyesConcurrentApproveDenyExactlyOneWins(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	for i := 0; i < 50; i++ {
		id := "race-" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		seedPending(t, eng, id, "alice", "")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for j, approve := range []bool{true, false} {
			wg.Add(1)
			go func(j int, approve bool) {
				defer wg.Done()
				<-start
				errs[j] = eng.DecideRequest(id, "bob", FourEyesSurfaceShell, approve)
			}(j, approve)
		}
		close(start)
		wg.Wait()
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			}
		}
		_, approvedErr := os.Stat(filepath.Join(eng.fourEyesApprovedDir(), id))
		_, deniedErr := os.Stat(filepath.Join(eng.fourEyesDeniedDir(), id))
		markers := 0
		if approvedErr == nil {
			markers++
		}
		if deniedErr == nil {
			markers++
		}
		if wins != 1 || markers != 1 {
			t.Fatalf("iteration %d: wins=%d markers=%d errs=%v", i, wins, markers, errs)
		}
	}
	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(ledger), "FOUREYES_DECISION"); got != 50 {
		t.Fatalf("decisions in chain = %d, want 50", got)
	}
}

func TestFourEyesDecisionsForbiddenInProcess(t *testing.T) {
	eng, _, _ := chainEngine(t)
	seedPending(t, eng, "req-forbid", "alice", "")
	fourEyesDecisionsForbidden.Store(true)
	t.Cleanup(func() { fourEyesDecisionsForbidden.Store(false) })
	if err := eng.DecideRequest("req-forbid", "bob", FourEyesSurfaceShell, true); err == nil {
		t.Fatal("decision allowed in a forbidden process")
	}
	bob := &sys.Session{ID: "fe-forbid", User: "bob"}
	registerTestSession(t, bob)
	if _, err := shellApprover(bob.ID); err == nil {
		t.Fatal("shell approver allowed in a forbidden process")
	}
}

func TestFourEyesMarkerFailureRevertsClaim(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	pendingPath := seedPending(t, eng, "req-mfail", "alice", "")
	// A directory where the marker goes makes the exclusive create fail
	// after the decision is already in the chain.
	if err := os.Mkdir(filepath.Join(eng.fourEyesApprovedDir(), "req-mfail"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := eng.DecideRequest("req-mfail", "bob", FourEyesSurfaceShell, true); err == nil {
		t.Fatal("decision succeeded with a failing marker write")
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("claim not reverted to pending: %v", err)
	}
	if _, err := os.Stat(filepath.Join(eng.fourEyesPendingDir(), "req-mfail.claimed")); !os.IsNotExist(err) {
		t.Fatalf("claimed file left behind: %v", err)
	}
	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ledger), "FOUREYES_DECISION_REVERTED request=req-mfail approver=bob reason=") {
		t.Fatalf("chain missing revert:\n%s", ledger)
	}
}

func writeClaimed(t *testing.T, eng *Engine, id string, age time.Duration) string {
	t.Helper()
	path := seedPending(t, eng, id, "alice", "")
	claimed := filepath.Join(eng.fourEyesPendingDir(), id+".claimed")
	if err := os.Rename(path, claimed); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(claimed, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return claimed
}

func TestFourEyesStaleClaimSweptAndLogged(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	listStale := writeClaimed(t, eng, "req-stale-list", 2*time.Hour)
	if _, err := eng.ListPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(listStale); !os.IsNotExist(err) {
		t.Fatalf("stale claim not swept by ListPending: %v", err)
	}

	decideStale := writeClaimed(t, eng, "req-stale-decide", 2*time.Hour)
	seedPending(t, eng, "req-live", "alice", "")
	if err := eng.DecideRequest("req-live", "bob", FourEyesSurfaceShell, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(decideStale); !os.IsNotExist(err) {
		t.Fatalf("stale claim not swept by a decision: %v", err)
	}

	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"req-stale-list", "req-stale-decide"} {
		if !strings.Contains(string(ledger), "FOUREYES_CLAIM_EXPIRED request="+id) {
			t.Fatalf("chain missing expiry for %s:\n%s", id, ledger)
		}
	}
}

func TestFourEyesFreshClaimListedAsClaimed(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	claimed := writeClaimed(t, eng, "req-fresh", 0)
	seedPending(t, eng, "req-open", "alice", "")
	list, err := eng.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, p := range list {
		status[p.RequestID] = p.Status
	}
	if got, ok := status["req-fresh"]; !ok || got != FourEyesStatusClaimed {
		t.Fatalf("fresh claim status = %q (listed=%v), want %q", got, ok, FourEyesStatusClaimed)
	}
	if got := status["req-open"]; got != FourEyesStatusPending {
		t.Fatalf("open request status = %q, want %q", got, FourEyesStatusPending)
	}
	if _, err := os.Stat(claimed); err != nil {
		t.Fatalf("fresh claim removed: %v", err)
	}
	if ledger, _ := os.ReadFile(chain); strings.Contains(string(ledger), "FOUREYES_CLAIM_EXPIRED") {
		t.Fatalf("fresh claim logged as expired:\n%s", ledger)
	}
}
