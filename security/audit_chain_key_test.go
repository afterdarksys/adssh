package security

// Threats: adssh and adssh-mcp default to the same chain key path. If two
// processes start together on a fresh host and each writes its own key, one
// side signs with a key the ledger does not hold and every later append fails
// closed for good. A short or damaged key file must not be silently replaced,
// because that also orphans the existing ledger. These tests prove concurrent
// creators converge on one key, a wrong-size key is refused and left alone,
// and the errors name the remedy.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestChainKey_ConcurrentCreatorsAgree(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "sub", "chain.key")
	const goroutines = 8
	const procs = 2

	type result struct {
		key []byte
		err error
	}
	results := make([]result, goroutines)
	helperOut := make([][]byte, procs)
	helperErr := make([]error, procs)

	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	for i := 0; i < procs; i++ {
		cmd := chainHelperCmd(t, "key", "", keyPath, 0)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			helperOut[i], helperErr[i] = cmd.Output()
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			k, err := loadOrCreateChainKey(keyPath)
			results[i] = result{k, err}
		}(i)
	}
	start.Done()
	wg.Wait()

	onDisk, err := os.ReadFile(keyPath)
	if err != nil || len(onDisk) != 32 {
		t.Fatalf("key on disk: len=%d err=%v", len(onDisk), err)
	}
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("goroutine %d: %v", i, r.err)
		}
		if !bytes.Equal(r.key, onDisk) {
			t.Fatalf("goroutine %d read a different key", i)
		}
	}
	want := hex.EncodeToString(onDisk)
	for i := range helperOut {
		if helperErr[i] != nil {
			t.Fatalf("helper %d: %v", i, helperErr[i])
		}
		if got := strings.TrimSpace(string(helperOut[i])); !strings.Contains(got, want) {
			t.Fatalf("helper %d key %q, want %q", i, got, want)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("temp files left behind: %v", names)
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key perms: %v %v", info, err)
	}
}

func TestChainKey_WrongSizeRefusedNotReplaced(t *testing.T) {
	for _, size := range []int{0, 16, 33} {
		keyPath := filepath.Join(t.TempDir(), "chain.key")
		orig := bytes.Repeat([]byte{0xAB}, size)
		if err := os.WriteFile(keyPath, orig, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadOrCreateChainKey(keyPath)
		if err == nil {
			t.Fatalf("%d-byte key accepted", size)
		}
		want := "audit chain key " + keyPath + " is unreadable or the wrong size; restore it from backup or move it aside to start a new ledger"
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q, want %q", err, want)
		}
		after, rerr := os.ReadFile(keyPath)
		if rerr != nil || !bytes.Equal(after, orig) {
			t.Fatalf("%d-byte key was replaced", size)
		}
		if _, err := NewEngine(EngineConfig{ChainPath: filepath.Join(filepath.Dir(keyPath), "ledger"), ChainKeyPath: keyPath}); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("engine with %d-byte key: %v", size, err)
		}
	}
}

func TestChainKey_UnreadableRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	keyPath := filepath.Join(t.TempDir(), "chain.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{1}, 32), 0000); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrCreateChainKey(keyPath)
	if err == nil || !strings.Contains(err.Error(), "is unreadable or the wrong size") {
		t.Fatalf("unreadable key: %v", err)
	}
}

func TestChainTail_ErrorsNameRemedy(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	key := filepath.Join(dir, "key")
	eng := newSharedEngine(t, ledger, key, "remedy")
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "one"}); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	remedy := "the ledger tail does not verify; rotate the ledger (move " + ledger + " aside) to continue — do not edit it"

	// Tampered tail: HMAC fails.
	tampered := bytes.Replace(good, []byte(`"one"`), []byte(`"two"`), 1)
	if err := os.WriteFile(ledger, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "x"}); err == nil || !strings.Contains(err.Error(), remedy) || !strings.Contains(err.Error(), "fails HMAC check") {
		t.Fatalf("tampered tail: %v", err)
	}

	// Partial tail: a crash mid-write.
	partial := append(append([]byte{}, good...), []byte(`{"seq":1,"ts":"2026`)...)
	if err := os.WriteFile(ledger, partial, 0600); err != nil {
		t.Fatal(err)
	}
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "x"}); err == nil || !strings.Contains(err.Error(), remedy) {
		t.Fatalf("partial tail: %v", err)
	}
}
