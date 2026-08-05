package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceBundleVerifiesAndFiltersChain(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		ChainPath:    ledger,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	eng.AppendChain(ChainEntry{SessionID: "session-a", ChangeID: "CHG-1", Type: "cmd", Command: "one"})
	eng.AppendChain(ChainEntry{SessionID: "session-b", ChangeID: "CHG-2", Type: "cmd", Command: "two"})

	bundle, err := eng.BuildEvidence(EvidenceFilter{SessionID: "session-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Verified || len(bundle.Entries) != 1 || bundle.Entries[0].Command != "one" || bundle.DigestSHA256 == "" {
		t.Fatalf("unexpected evidence bundle: %#v", bundle)
	}
}

func TestEvidenceRejectsTamperedLedger(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: filepath.Join(dir, "key")})
	if err != nil {
		t.Fatal(err)
	}
	eng.AppendChain(ChainEntry{Type: "cmd", Command: "safe"})
	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledger, []byte(strings.Replace(string(data), "safe", "evil", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.BuildEvidence(EvidenceFilter{}); err == nil || !strings.Contains(err.Error(), "verification") {
		t.Fatalf("tampered ledger produced evidence: %v", err)
	}
}

func TestEvidenceWritesPrivateBundleFile(t *testing.T) {
	dir := t.TempDir()
	eng, _ := NewEngine(EngineConfig{ChainPath: filepath.Join(dir, "chain"), ChainKeyPath: filepath.Join(dir, "key")})
	eng.AppendChain(ChainEntry{Type: "event", Command: "test"})
	path := filepath.Join(dir, "bundle.json")
	writer := evidenceBinary{}
	if err := writer.write(context.Background(), eng, EvidenceFilter{}, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %o, want 600", info.Mode().Perm())
	}
}

func TestEvidenceIncludesRecordingDigestForMatchingSession(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADSSH_RECORD_DIR", dir)
	ledger := filepath.Join(dir, "chain")
	eng, err := NewEngine(EngineConfig{
		ChainPath:    ledger,
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "recorded-session",
	})
	if err != nil {
		t.Fatal(err)
	}
	recordingPath := filepath.Join(dir, "recorded-session.jsonl")
	if err := os.WriteFile(recordingPath, []byte("{\"type\":\"start\"}\n{\"type\":\"end\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng.AppendChain(ChainEntry{SessionID: "recorded-session", Type: "cmd", Command: "whoami"})

	bundle, err := eng.BuildEvidence(EvidenceFilter{SessionID: "recorded-session"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Recordings) != 1 {
		t.Fatalf("recordings = %#v", bundle.Recordings)
	}
	ref := bundle.Recordings[0]
	if ref.SessionID != "recorded-session" || ref.Path != recordingPath || ref.EventCount != 2 || ref.SizeBytes == 0 || ref.DigestSHA256 == "" {
		t.Fatalf("recording ref = %#v", ref)
	}
}
