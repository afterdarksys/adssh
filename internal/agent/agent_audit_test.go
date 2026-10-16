package agent

import (
	"context"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/afterdarksys/adssh/security"
)

// countingVBinRuns counts how many times countingVBin ran, so a test can prove
// an instrument request did not run its task.
var countingVBinRuns atomic.Int64

type countingVBin struct{}

func (countingVBin) Name() string        { return "counting-instrument" }
func (countingVBin) Description() string { return "counts runs" }
func (countingVBin) Usage() string       { return "counting-instrument" }
func (countingVBin) Run(context.Context, []string) error {
	countingVBinRuns.Add(1)
	return nil
}

// breakDefaultChain replaces the chain ledger with a directory so every later
// audit write through the default engine fails.
func breakDefaultChain(t *testing.T, chainPath string) {
	t.Helper()
	if err := security.LogEvent("TEST_SEED"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(chainPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(chainPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := security.LogEvent("TEST_PROBE"); err == nil {
		t.Fatal("broken chain still accepted an event")
	}
}

func TestInstrumentAuditFailureDoesNotRunTask(t *testing.T) {
	chainPath := setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"count": {VBin: "counting-instrument", Description: "d", Risk: "low"},
	}))
	breakDefaultChain(t, chainPath)
	before := countingVBinRuns.Load()
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, `{"task":"count"}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("instrument succeeded with a failing audit sink: %s", rec.Body.String())
	}
	if got := countingVBinRuns.Load(); got != before {
		t.Fatalf("task ran %d time(s) although the audit write failed", got-before)
	}
}

func TestInstrumentDenialAuditFailureIsReported(t *testing.T) {
	chainPath := setDefaultEngine(t, true)
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"count": {VBin: "counting-instrument", Description: "d", Risk: "low"},
	}))
	breakDefaultChain(t, chainPath)
	for _, body := range []string{`{"task":"count"}`, `{"task":"missing"}`} {
		rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, body)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s with a failing audit sink = %d, want 503", body, rec.Code)
		}
	}
}
