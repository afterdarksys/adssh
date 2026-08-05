package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactSensitiveTextCredentialShapes(t *testing.T) {
	input := strings.Join([]string{
		`password="correct-horse-battery-staple"`,
		"token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
		"aws=AKIA1234567890ABCDEF",
		"jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"-----BEGIN PRIVATE KEY-----\nsecret-key\n-----END PRIVATE KEY-----",
	}, "\n")

	redacted := RedactSensitiveText(input)
	for _, leaked := range []string{
		"correct-horse-battery-staple",
		"ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
		"AKIA1234567890ABCDEF",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"secret-key",
	} {
		if strings.Contains(redacted, leaked) {
			t.Fatalf("redacted text leaked %q in %q", leaked, redacted)
		}
	}
	if count := strings.Count(redacted, redactedSecret); count < 5 {
		t.Fatalf("redacted %d credential shapes, want at least 5: %q", count, redacted)
	}
}

func TestAuditCommandRedactsCredentialShapesBeforePersistence(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		AuditLogPath: auditPath,
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    "redaction-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	eng.LogCommand("TEST", "deploy token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ")
	eng.LogPolicyDecision("alice", "aws configure set aws_access_key_id AKIA1234567890ABCDEF", false, "secret=do-not-store")
	eng.LogEvent("operator pasted password=hunter2")

	for _, path := range []string{auditPath, chainPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, leaked := range []string{
			"ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
			"AKIA1234567890ABCDEF",
			"do-not-store",
			"hunter2",
		} {
			if strings.Contains(string(data), leaked) {
				t.Fatalf("%s leaked %q: %s", filepath.Base(path), leaked, data)
			}
		}
		if !strings.Contains(string(data), redactedSecret) {
			t.Fatalf("%s did not contain redaction marker: %s", filepath.Base(path), data)
		}
	}
}
