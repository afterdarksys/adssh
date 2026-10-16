package security

import (
	"strings"
	"testing"
)

// A webhook sink without a flat audit log would be silently ignored, so the
// engine refuses to construct instead.
func TestEngineRejectsWebhookWithoutAuditLog(t *testing.T) {
	_, err := NewEngine(EngineConfig{AuditLogURL: "https://siem.example.com/ingest"})
	if err == nil || !strings.Contains(err.Error(), "AuditLogPath is empty") {
		t.Fatalf("want rejection for webhook without audit log, got %v", err)
	}
}
