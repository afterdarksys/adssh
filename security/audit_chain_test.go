package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// resetChain resets the default engine's audit-chain state between tests.
// (Wave 2: chain state moved from package globals onto the Engine; this helper
// now resets defaultEngine's fields but its assertions are unchanged.)
func resetChain() {
	defaultEngine.chainMu.Lock()
	defer defaultEngine.chainMu.Unlock()
	defaultEngine.chainPath, defaultEngine.chainKey, defaultEngine.chainSession = "", nil, ""
}

// readChainLines reads the ledger file and returns its non-empty lines, in order.
func readChainLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func writeChainLines(t *testing.T, path string, lines []string) {
	t.Helper()
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write ledger: %v", err)
	}
}

func unmarshalEntry(t *testing.T, line string) ChainEntry {
	t.Helper()
	var e ChainEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	return e
}

func marshalEntry(t *testing.T, e ChainEntry) string {
	t.Helper()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return string(data)
}

func TestChain_AppendAndVerify(t *testing.T) {
	resetChain()
	t.Cleanup(resetChain)

	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	keyPath := filepath.Join(dir, "key")
	InitChain(ledgerPath, keyPath, "s1")

	for i := 0; i < 5; i++ {
		AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("cmd%d", i)})
	}

	ok, badSeq, err := VerifyChain(ledgerPath)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !ok {
		t.Fatalf("expected chain to verify ok, got badSeq=%d", badSeq)
	}

	lines := readChainLines(t, ledgerPath)
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	var prevHash string
	for i, line := range lines {
		e := unmarshalEntry(t, line)
		if e.Seq != int64(i) {
			t.Errorf("entry %d: expected Seq=%d, got %d", i, i, e.Seq)
		}
		if e.PrevHash != prevHash {
			t.Errorf("entry %d: expected PrevHash=%q, got %q", i, prevHash, e.PrevHash)
		}
		if e.Hash == "" {
			t.Errorf("entry %d: empty Hash", i)
		}
		prevHash = e.Hash
	}
}

func TestChain_TamperedEntryDetected(t *testing.T) {
	resetChain()
	t.Cleanup(resetChain)

	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	keyPath := filepath.Join(dir, "key")
	InitChain(ledgerPath, keyPath, "s1")

	for i := 0; i < 5; i++ {
		AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("cmd%d", i)})
	}

	lines := readChainLines(t, ledgerPath)
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	// Mutate the Command field of the entry with Seq==2, but keep its
	// stored Hash unchanged (as if an attacker edited the text in place).
	e := unmarshalEntry(t, lines[2])
	if e.Seq != 2 {
		t.Fatalf("expected lines[2] to have Seq==2, got %d", e.Seq)
	}
	oldHash := e.Hash
	e.Command = "tampered-command"
	e.Hash = oldHash
	lines[2] = marshalEntry(t, e)
	writeChainLines(t, ledgerPath, lines)

	ok, badSeq, err := VerifyChain(ledgerPath)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail after tampering with entry content")
	}
	if badSeq != 2 {
		t.Errorf("expected badSeq=2, got %d", badSeq)
	}
}

func TestChain_TamperedHashDetected(t *testing.T) {
	resetChain()
	t.Cleanup(resetChain)

	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	keyPath := filepath.Join(dir, "key")
	InitChain(ledgerPath, keyPath, "s1")

	for i := 0; i < 5; i++ {
		AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("cmd%d", i)})
	}

	lines := readChainLines(t, ledgerPath)
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	// Corrupt the Hash hex of the last line only.
	last := unmarshalEntry(t, lines[len(lines)-1])
	if last.Seq != 4 {
		t.Fatalf("expected last line to have Seq==4, got %d", last.Seq)
	}
	corrupted := []byte(last.Hash)
	// Flip a hex character so the hash no longer matches, without changing length.
	if corrupted[0] == 'f' {
		corrupted[0] = '0'
	} else {
		corrupted[0] = 'f'
	}
	last.Hash = string(corrupted)
	lines[len(lines)-1] = marshalEntry(t, last)
	writeChainLines(t, ledgerPath, lines)

	ok, badSeq, err := VerifyChain(ledgerPath)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail after tampering with stored hash")
	}
	if badSeq != 4 {
		t.Errorf("expected badSeq=4, got %d", badSeq)
	}
}

func TestChain_MiddleLineDeletionDetected(t *testing.T) {
	resetChain()
	t.Cleanup(resetChain)

	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	keyPath := filepath.Join(dir, "key")
	InitChain(ledgerPath, keyPath, "s1")

	for i := 0; i < 5; i++ {
		AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("cmd%d", i)})
	}

	original := readChainLines(t, ledgerPath)
	if len(original) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(original))
	}

	// Delete the middle line (Seq==2) entirely, leaving a gap in the chain.
	withGap := append(append([]string{}, original[:2]...), original[3:]...)
	writeChainLines(t, ledgerPath, withGap)

	ok, badSeq, err := VerifyChain(ledgerPath)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail after deleting a middle entry")
	}
	// CHARACTERIZATION: the mismatch surfaces on the entry immediately
	// following the gap (Seq==3), not on the missing entry's own Seq (2),
	// because VerifyChain detects breaks via prev-hash linkage on the next
	// surviving entry rather than by noticing an absent sequence number.
	t.Logf("middle deletion detected at badSeq=%d (expected on the entry after the gap, Seq==3)", badSeq)
	if badSeq != 3 {
		t.Errorf("CHARACTERIZATION: expected badSeq=3 (first entry after the gap), got %d", badSeq)
	}

	// CHARACTERIZATION: truncating from the TAIL is NOT detectable by
	// VerifyChain. If the missing entries are the most recent ones, the
	// remaining prefix of the chain is still fully self-consistent (every
	// surviving entry's PrevHash still matches the previous surviving
	// entry's Hash), so VerifyChain reports ok=true even though entries
	// are missing from the end of the ledger. Detecting tail truncation
	// would require an externally-recorded expected tail (seq/hash) —
	// out of scope for Wave 1; flagged for Wave 2+.
	truncated := original[:3] // drop the last two entries (Seq 3 and 4)
	writeChainLines(t, ledgerPath, truncated)

	ok2, badSeq2, err := VerifyChain(ledgerPath)
	if err != nil {
		t.Fatalf("VerifyChain error after tail truncation: %v", err)
	}
	t.Logf("CHARACTERIZATION: tail truncation ok=%v badSeq=%d (expected ok=true — undetectable)", ok2, badSeq2)
	if !ok2 {
		t.Errorf("CHARACTERIZATION assumption violated: tail truncation was detected (ok=%v badSeq=%d) — update this comment/test", ok2, badSeq2)
	}
}

func TestChain_ConcurrentAppends(t *testing.T) {
	resetChain()
	t.Cleanup(resetChain)

	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	keyPath := filepath.Join(dir, "key")
	InitChain(ledgerPath, keyPath, "s1")

	const goroutines = 20
	const perGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("g%d-cmd%d", g, i)})
			}
		}(g)
	}
	wg.Wait()

	ok, badSeq, err := VerifyChain(ledgerPath)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !ok {
		t.Fatalf("expected chain to verify ok after concurrent appends, got badSeq=%d", badSeq)
	}

	lines := readChainLines(t, ledgerPath)
	if len(lines) != goroutines*perGoroutine {
		t.Fatalf("expected %d lines, got %d", goroutines*perGoroutine, len(lines))
	}
}

func TestChain_NoInitIsNoOp(t *testing.T) {
	resetChain()
	t.Cleanup(resetChain)

	dir := t.TempDir()

	// AppendChain must not panic and must not write anything when InitChain
	// has never been called (chainPath/chainKey are zero-valued).
	AppendChain(ChainEntry{Type: "cmd", Command: "noop"})

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files created, found: %v", entries)
	}

	defaultEngine.chainMu.Lock()
	path, key := defaultEngine.chainPath, defaultEngine.chainKey
	defaultEngine.chainMu.Unlock()
	if path != "" || key != nil {
		t.Errorf("expected chain state to remain unset, got path=%q key=%v", path, key)
	}
}

func TestChain_KeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")

	key1, err := loadOrCreateChainKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateChainKey (create): %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key1))
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected key file perms 0600, got %o", perm)
	}

	key2, err := loadOrCreateChainKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateChainKey (reload): %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("expected second call to return the identical key")
	}
}
