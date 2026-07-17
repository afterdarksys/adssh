package security

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

const denyAllRego = `package adssh.authz
default allow = false
deny_reason = "engine-deny" { input.command == "probe" }`

const allowAllRego = `package adssh.authz
default allow = true`

// TestEngine_IsolatedPolicies proves two engines evaluate the same command
// differently and that neither touches the package default engine.
func TestEngine_IsolatedPolicies(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)

	engA, err := NewEngine(EngineConfig{PolicySource: []byte(denyAllRego)})
	if err != nil {
		t.Fatalf("NewEngine A: %v", err)
	}
	engB, err := NewEngine(EngineConfig{PolicySource: []byte(allowAllRego)})
	if err != nil {
		t.Fatalf("NewEngine B: %v", err)
	}

	pctx := PolicyContext{User: "alice", Command: "probe", Args: []string{"x"}}

	allowedA, reasonA, err := engA.EvaluatePolicy(pctx)
	if err != nil {
		t.Fatalf("engA.EvaluatePolicy: %v", err)
	}
	if allowedA {
		t.Error("engine A (deny-all) allowed 'probe', expected deny")
	}
	if reasonA != "engine-deny" {
		t.Errorf("engine A deny reason = %q, want %q", reasonA, "engine-deny")
	}

	allowedB, _, err := engB.EvaluatePolicy(pctx)
	if err != nil {
		t.Fatalf("engB.EvaluatePolicy: %v", err)
	}
	if !allowedB {
		t.Error("engine B (allow-all) denied 'probe', expected allow")
	}

	// Package default engine had no policy loaded (resetPolicy) → allow-by-default.
	allowedDefault, _, err := EvaluatePolicy(pctx)
	if err != nil {
		t.Fatalf("default EvaluatePolicy: %v", err)
	}
	if !allowedDefault {
		t.Error("package default engine denied 'probe' — it should be unaffected (allow-by-default)")
	}
}

// TestEngine_IsolatedChains proves appends to engine A's ledger never appear in
// engine B's ledger and both chains verify independently.
func TestEngine_IsolatedChains(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	engA, err := NewEngine(EngineConfig{
		ChainPath:    filepath.Join(dirA, "ledger.jsonl"),
		ChainKeyPath: filepath.Join(dirA, "key"),
		SessionID:    "A",
	})
	if err != nil {
		t.Fatalf("NewEngine A: %v", err)
	}
	engB, err := NewEngine(EngineConfig{
		ChainPath:    filepath.Join(dirB, "ledger.jsonl"),
		ChainKeyPath: filepath.Join(dirB, "key"),
		SessionID:    "B",
	})
	if err != nil {
		t.Fatalf("NewEngine B: %v", err)
	}

	for i := 0; i < 5; i++ {
		engA.AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("a-cmd%d", i)})
	}
	engB.AppendChain(ChainEntry{Type: "cmd", Command: "b-only"})

	linesA := readChainLines(t, engA.chainPath)
	if len(linesA) != 5 {
		t.Fatalf("engine A ledger: expected 5 lines, got %d", len(linesA))
	}
	linesB := readChainLines(t, engB.chainPath)
	if len(linesB) != 1 {
		t.Fatalf("engine B ledger: expected 1 line, got %d", len(linesB))
	}
	for _, l := range linesB {
		if got := unmarshalEntry(t, l).Command; got == "a-cmd0" {
			t.Error("engine A's entry leaked into engine B's ledger")
		}
	}

	if ok, badSeq, err := engA.VerifyChain(engA.chainPath); err != nil || !ok {
		t.Fatalf("engine A chain did not verify: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
	if ok, badSeq, err := engB.VerifyChain(engB.chainPath); err != nil || !ok {
		t.Fatalf("engine B chain did not verify: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}

type isoVBin struct{ name string }

func (v isoVBin) Name() string                        { return v.name }
func (v isoVBin) Description() string                 { return "isolation test vbin" }
func (v isoVBin) Usage() string                       { return v.name }
func (v isoVBin) Run(context.Context, []string) error { return nil }

// TestEngine_IsolatedVBinRegistries proves registering a vbin on engine A is not
// visible on engine B or the package default registry.
func TestEngine_IsolatedVBinRegistries(t *testing.T) {
	engA, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine A: %v", err)
	}
	engB, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine B: %v", err)
	}

	const name = "engine-iso-vbin"
	engA.Register(isoVBin{name: name})

	if _, ok := engA.Lookup(name); !ok {
		t.Fatal("engine A should see its own registered vbin")
	}
	if _, ok := engB.Lookup(name); ok {
		t.Error("engine B saw a vbin registered only on engine A")
	}
	if _, ok := Lookup(name); ok {
		t.Error("package default registry saw a vbin registered only on engine A")
	}

	// Both engines still share the built-ins seeded from the package registry.
	if _, ok := engA.Lookup("jq"); !ok {
		t.Error("engine A missing built-in 'jq' seed")
	}
	if _, ok := engB.Lookup("jq"); !ok {
		t.Error("engine B missing built-in 'jq' seed")
	}
}

// TestNewEngine_FailClosed proves malformed Rego and RequirePolicy-with-no-policy
// both return errors from NewEngine.
func TestNewEngine_FailClosed(t *testing.T) {
	if _, err := NewEngine(EngineConfig{PolicySource: []byte("this is not valid rego { { {")}); err == nil {
		t.Error("expected error constructing engine with malformed Rego source, got nil")
	}

	if _, err := NewEngine(EngineConfig{RequirePolicy: true}); err == nil {
		t.Error("expected error when RequirePolicy is set but no policy configured, got nil")
	}

	if _, err := NewEngine(EngineConfig{
		RequirePolicy: true,
		PolicyPath:    filepath.Join(t.TempDir(), "does-not-exist.rego"),
	}); err == nil {
		t.Error("expected error when RequirePolicy is set but policy file is missing, got nil")
	}

	// Sanity: RequirePolicy false with no policy is fine (allow-by-default).
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatalf("zero-config engine should construct: %v", err)
	}
	allowed, _, err := eng.EvaluatePolicy(PolicyContext{Command: "anything"})
	if err != nil || !allowed {
		t.Errorf("zero-config engine should allow-by-default, got allowed=%v err=%v", allowed, err)
	}
}

// TestEngine_ConcurrentSessionsSmoke runs many goroutines against one engine
// doing policy eval + chain append; -race must stay silent and the chain must
// verify afterward.
func TestEngine_ConcurrentSessionsSmoke(t *testing.T) {
	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{
		PolicySource: []byte(allowAllRego),
		ChainPath:    filepath.Join(dir, "ledger.jsonl"),
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "smoke",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	const goroutines = 20
	const perGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if _, _, err := eng.EvaluatePolicy(PolicyContext{
					User:    fmt.Sprintf("u%d", g),
					Command: "run",
					Args:    []string{fmt.Sprintf("%d", i)},
				}); err != nil {
					t.Errorf("EvaluatePolicy: %v", err)
					return
				}
				eng.AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("g%d-c%d", g, i)})
			}
		}(g)
	}
	wg.Wait()

	ok, badSeq, err := eng.VerifyChain(eng.chainPath)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !ok {
		t.Fatalf("chain failed to verify after concurrent appends, badSeq=%d", badSeq)
	}
	if lines := readChainLines(t, eng.chainPath); len(lines) != goroutines*perGoroutine {
		t.Fatalf("expected %d chain lines, got %d", goroutines*perGoroutine, len(lines))
	}
}
