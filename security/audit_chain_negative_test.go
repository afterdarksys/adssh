package security

// Threats:
//   This file is the adversarial tamper-evidence suite for the HMAC audit chain
//   (audit_chain.go). It proves VerifyChain detects an attacker who: verifies
//   under the WRONG HMAC key, REORDERS entries, FORGES an appended entry without
//   the key, CORRUPTS a line into non-JSON, or RENUMBERS an entry's seq. It also
//   pins the well-defined behavior for EMPTY and MISSING ledgers (no panic).
//
//   Each test builds an isolated chain with NewEngine (no shared/global state),
//   so they are safe under -race and need no reset helpers. They reuse the ledger
//   read/write helpers from audit_chain_test.go (readChainLines, writeChainLines,
//   unmarshalEntry, marshalEntry).
//
//   NOT covered here (documented in audit_chain_test.go): TAIL truncation of the
//   most-recent entries is undetectable by VerifyChain alone (the surviving
//   prefix stays self-consistent) — it needs an externally-recorded expected
//   tail, which is out of scope. Detection of a mid-chain gap surfaces on the
//   entry AFTER the gap, not the missing seq.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// buildNegChain constructs an isolated engine with an HMAC chain at ledger/key
// and appends n cmd entries. Returns the engine (holding the chain key).
func buildNegChain(t *testing.T, ledger, key string, n int) *Engine {
	t.Helper()
	eng, err := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: key, SessionID: "neg"})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for i := 0; i < n; i++ {
		eng.AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("cmd%d", i)})
	}
	if ok, badSeq, err := eng.VerifyChain(ledger); err != nil || !ok {
		t.Fatalf("freshly-built chain failed to verify: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
	return eng
}

// D.1: a valid chain must NOT verify under a different HMAC key.
func TestChainNeg_WrongKeyFailsVerify(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	buildNegChain(t, ledger, filepath.Join(dir, "keyA"), 4)

	// A second engine with a DIFFERENT key file verifies the same ledger.
	engWrong, err := NewEngine(EngineConfig{
		ChainPath:    filepath.Join(dir, "other-ledger.jsonl"),
		ChainKeyPath: filepath.Join(dir, "keyB"), // freshly generated, != keyA
		SessionID:    "wrong",
	})
	if err != nil {
		t.Fatalf("NewEngine (wrong key): %v", err)
	}
	ok, badSeq, err := engWrong.VerifyChain(ledger)
	if err != nil {
		t.Fatalf("VerifyChain returned an unexpected error: %v", err)
	}
	if ok {
		t.Fatal("SECURITY: chain verified as intact under the WRONG HMAC key")
	}
	if badSeq != 0 {
		t.Errorf("expected first entry (seq 0) to fail under wrong key, got badSeq=%d", badSeq)
	}
}

// D.2: swapping two adjacent entries (keeping their stored hashes) is detected.
func TestChainNeg_ReorderDetected(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	eng := buildNegChain(t, ledger, filepath.Join(dir, "key"), 4)

	lines := readChainLines(t, ledger)
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d", len(lines))
	}
	// Swap the entries at index 1 and 2, verbatim (hashes untouched).
	lines[1], lines[2] = lines[2], lines[1]
	writeChainLines(t, ledger, lines)

	ok, badSeq, err := eng.VerifyChain(ledger)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if ok {
		t.Fatal("SECURITY: reordered chain verified as intact")
	}
	t.Logf("reorder detected at badSeq=%d", badSeq)
}

// D.3: an attacker without the key appends a plausible entry with a wrong Hash.
func TestChainNeg_ForgedAppendDetected(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	eng := buildNegChain(t, ledger, filepath.Join(dir, "key"), 3)

	lines := readChainLines(t, ledger)
	last := unmarshalEntry(t, lines[len(lines)-1])

	forged := ChainEntry{
		Seq:       last.Seq + 1,
		Timestamp: last.Timestamp,
		SessionID: last.SessionID,
		User:      last.User,
		Hostname:  last.Hostname,
		Type:      "cmd",
		Command:   "forged-privilege-escalation",
		PrevHash:  last.Hash,               // links correctly...
		Hash:      strings.Repeat("0", 64), // ...but the hash is fabricated
	}
	lines = append(lines, marshalEntry(t, forged))
	writeChainLines(t, ledger, lines)

	ok, badSeq, err := eng.VerifyChain(ledger)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if ok {
		t.Fatal("SECURITY: forged appended entry verified as intact")
	}
	if badSeq != forged.Seq {
		t.Errorf("expected detection at forged seq %d, got %d", forged.Seq, badSeq)
	}
}

// D.4: a non-JSON / truncated line mid-ledger yields a verification failure.
func TestChainNeg_CorruptJSONDetected(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	eng := buildNegChain(t, ledger, filepath.Join(dir, "key"), 3)

	lines := readChainLines(t, ledger)
	lines[1] = `{"seq":1,"type":"cmd","cmd":"truncated` // invalid JSON
	writeChainLines(t, ledger, lines)

	ok, _, err := eng.VerifyChain(ledger)
	if ok {
		t.Fatal("SECURITY: ledger with a corrupt JSON line verified as intact")
	}
	if err == nil {
		t.Error("expected a parse error from VerifyChain on corrupt JSON")
	}
}

// D.5: mutating only an entry's seq is detected (the hash covers seq).
func TestChainNeg_SeqRenumberDetected(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	eng := buildNegChain(t, ledger, filepath.Join(dir, "key"), 3)

	lines := readChainLines(t, ledger)
	e := unmarshalEntry(t, lines[1])
	oldHash := e.Hash
	e.Seq = 9999 // renumber only; keep the stored hash
	e.Hash = oldHash
	lines[1] = marshalEntry(t, e)
	writeChainLines(t, ledger, lines)

	ok, badSeq, err := eng.VerifyChain(ledger)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if ok {
		t.Fatal("SECURITY: seq-renumbered entry verified as intact (hash must cover seq)")
	}
	t.Logf("seq renumber detected at badSeq=%d", badSeq)
}

// D.6: empty and missing ledgers have well-defined, non-panicking behavior.
func TestChainNeg_EmptyAndMissingLedger(t *testing.T) {
	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{
		ChainPath:    filepath.Join(dir, "ledger.jsonl"),
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "empty",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Missing file => error, not a panic and not a false "ok".
	ok, _, err := eng.VerifyChain(filepath.Join(dir, "does-not-exist.jsonl"))
	if err == nil {
		t.Error("expected an error verifying a missing ledger")
	}
	if ok {
		t.Error("SECURITY: missing ledger reported as verified")
	}

	// Empty file => vacuously ok (no entries to break), no panic.
	empty := filepath.Join(dir, "empty.jsonl")
	writeChainLines(t, empty, nil)
	ok2, badSeq2, err2 := eng.VerifyChain(empty)
	if err2 != nil {
		t.Errorf("unexpected error verifying empty ledger: %v", err2)
	}
	if !ok2 {
		t.Errorf("expected empty ledger to verify ok (vacuously), got ok=%v badSeq=%d", ok2, badSeq2)
	}
}
