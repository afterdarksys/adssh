package security

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestAdminHTTPRequiresToken(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAdminHTTPHandler(eng, "secret")

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHTTPSessionsEndpoint(t *testing.T) {
	session := &sys.Session{ID: "admin-http-session", User: "alice", Principals: []string{"ops"}}
	sys.RegisterSession(session)
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAdminHTTPHandler(eng, "")

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "admin-http-session") || !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("session response missing registered session: %s", rec.Body.String())
	}
}

func TestAdminHTTPExplainEndpoint(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh
default allow = false
deny_reason = "no deletes" {
  input.command == "rm"
}
authz := {"allow": allow, "deny_reason": deny_reason}
`)})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"command":["rm","-rf","/tmp/x"]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/explain", body)
	rec := httptest.NewRecorder()
	NewAdminHTTPHandler(eng, "").ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no deletes") {
		t.Fatalf("explain response missing policy reason: %s", rec.Body.String())
	}
}

func TestAdminHTTPEvidenceEndpoint(t *testing.T) {
	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{
		ChainPath:    filepath.Join(dir, "chain"),
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "admin-http-evidence",
	})
	if err != nil {
		t.Fatal(err)
	}
	eng.AppendChain(ChainEntry{SessionID: "admin-http-evidence", Type: "cmd", Command: "whoami"})
	req := httptest.NewRequest(http.MethodPost, "/v1/evidence", bytes.NewBufferString(`{"session_id":"admin-http-evidence"}`))
	rec := httptest.NewRecorder()
	NewAdminHTTPHandler(eng, "").ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var bundle EvidenceBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if !bundle.Verified || len(bundle.Entries) != 1 || bundle.Entries[0].Command != "whoami" {
		t.Fatalf("bundle = %#v", bundle)
	}
}
