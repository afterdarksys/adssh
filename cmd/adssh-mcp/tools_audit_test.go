package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestAuditLogRejectsNegativeLimitWithoutPanicking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "audit_log",
		Arguments: map[string]any{"limit": float64(-1)},
	}}

	result, err := handleAuditLog(path)(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !result.IsError {
		t.Fatal("negative limit was not rejected")
	}
}

func TestAuditLogRejectsExcessiveLimit(t *testing.T) {
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "audit_log",
		Arguments: map[string]any{"limit": float64(10001)},
	}}
	result, err := handleAuditLog(filepath.Join(t.TempDir(), "audit.log"))(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("excessive audit limit was not rejected")
	}
}
