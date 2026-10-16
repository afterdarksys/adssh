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

	if err := eng.LogCommand("TEST", "deploy token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogPolicyDecision("alice", "aws configure set aws_access_key_id AKIA1234567890ABCDEF", false, "secret=do-not-store"); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("operator pasted password=hunter2"); err != nil {
		t.Fatal(err)
	}

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

// Governed Starlark calls audit keyword arguments as "key"="value"; a quoted
// credential key must redact the same as a bare one.
func TestRedactSensitiveTextQuotedKeys(t *testing.T) {
	input := `log.error "x" "token"="hunter2" 'api_key'='abc123' "password"="pw-plain"`
	redacted := RedactSensitiveText(input)
	for _, leaked := range []string{"hunter2", "abc123", "pw-plain"} {
		if strings.Contains(redacted, leaked) {
			t.Fatalf("quoted key leaked %q in %q", leaked, redacted)
		}
	}
	if !strings.Contains(RedactSensitiveText(`tokenizer=keep`), "keep") {
		t.Fatal("tokenizer= is not a credential key")
	}
}

func TestRedactSensitiveTextPrefixedKeys(t *testing.T) {
	for _, input := range []string{
		`db_password=hunter2`,
		`github_token=hunter2`,
		`API_TOKEN=hunter2`,
		`aws_secret_access_key=hunter2`,
		`"github_token"="hunter2"`,
		`export DB-PASSWD='hunter2'`,
		`x my_api_key = hunter2`,
	} {
		if got := RedactSensitiveText(input); strings.Contains(got, "hunter2") {
			t.Fatalf("%q leaked: %q", input, got)
		}
	}
}

func TestRedactSensitiveTextLeavesNonCredentialKeys(t *testing.T) {
	for _, input := range []string{
		`tokenizer=x`,
		`secretary=x`,
		`token_count=5`,
		`passwords_rotated=3`,
		`mytoken=x`,
	} {
		if got := RedactSensitiveText(input); got != input {
			t.Fatalf("%q was changed to %q", input, got)
		}
	}
}
