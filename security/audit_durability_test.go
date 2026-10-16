package security

// Threats:
//   The flat audit log and the HMAC chain are the record a crash must not
//   lose. These tests reject a ledger path that is a directory, a forced
//   Sync failure on each sink, a corrupt or oversized tail, a closed audit
//   file, and a command gate that would otherwise allow when the audit write
//   cannot be synced. A failure does not start a new seq-0 chain and does
//   not authorize the command.
//
//   NOT covered: a disk that reports Sync success and then drops the sector,
//   and tail truncation of a still-valid prefix (VerifyChain cannot see it).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendChain_DirectoryLedgerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger")
	if err := os.Mkdir(ledger, 0700); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{
		ChainPath:    ledger,
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "dur",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "nope"}); err == nil {
		t.Fatal("directory ledger must fail closed")
	}
	entries, err := os.ReadDir(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory ledger gained files: %v", entries)
	}
}

func TestAppendChain_SyncFailureFailsClosed(t *testing.T) {
	orig := syncFile
	t.Cleanup(func() { syncFile = orig })
	syncFile = func(*os.File) error { return fmt.Errorf("sync forced") }

	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{
		ChainPath:    filepath.Join(dir, "ledger.jsonl"),
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "dur",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = eng.AppendChain(ChainEntry{Type: "cmd", Command: "nope"})
	if err == nil || !strings.Contains(err.Error(), "sync forced") {
		t.Fatalf("expected sync failure, got %v", err)
	}
}

func TestLogCommand_SyncFailureFailsClosed(t *testing.T) {
	orig := syncFile
	t.Cleanup(func() { syncFile = orig })
	syncFile = func(*os.File) error { return fmt.Errorf("sync forced") }

	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	err = eng.LogCommand("TEST", "ls")
	if err == nil || !strings.Contains(err.Error(), "sync forced") {
		t.Fatalf("expected sync failure, got %v", err)
	}
}

func TestAppendChain_CorruptTailFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	key := filepath.Join(dir, "key")
	eng, err := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: key, SessionID: "dur"})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "ok"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(ledger, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-json\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}

	next, err := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: key, SessionID: "dur"})
	if err != nil {
		t.Fatal(err)
	}
	if err := next.AppendChain(ChainEntry{Type: "cmd", Command: "after"}); err == nil {
		t.Fatal("corrupt tail must fail closed")
	}
	after, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("corrupt tail wrote a new entry:\n%s", after)
	}
	if strings.Contains(string(after), `"seq":0`) && strings.Count(string(after), "\n") > 2 {
		t.Fatal("corrupt tail started a genesis entry")
	}
}

func TestAppendChain_OversizedTailFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	if err := os.WriteFile(ledger, []byte(strings.Repeat("a", chainScanMax+8)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{
		ChainPath:    ledger,
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "dur",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "after"}); err == nil {
		t.Fatal("oversized tail must fail closed")
	}
	after, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("oversized tail was replaced with a genesis entry")
	}
}

func TestLogCommand_ClosedFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	eng.auditMu.Lock()
	if err := eng.auditFile.Close(); err != nil {
		eng.auditMu.Unlock()
		t.Fatal(err)
	}
	eng.auditMu.Unlock()
	if err := eng.LogCommand("TEST", "ls"); err == nil {
		t.Fatal("closed audit file must fail closed")
	}
}

func TestAuthorizeCommand_AuditSyncFailureDenies(t *testing.T) {
	orig := syncFile
	t.Cleanup(func() { syncFile = orig })
	syncFile = func(*os.File) error { return fmt.Errorf("sync forced") }

	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	err = eng.AuthorizeCommand([]string{"ls"}, "")
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("gate must deny when audit sync fails, got %v", err)
	}
}
