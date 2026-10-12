package security

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
	handler := NewAdminHTTPHandler(eng, "secret")

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer secret")
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
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	NewAdminHTTPHandler(eng, "secret").ServeHTTP(rec, req)
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
	req.Header.Set("Authorization", "Bearer secret")
	NewAdminHTTPHandler(eng, "secret").ServeHTTP(rec, req)
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

func TestAdminHTTPEmptyKeyRefused(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAdminHTTPHandler(eng, "")
	for _, hdr := range []struct{ name, value string }{
		{"Authorization", "Bearer secret"},
		{"X-ADSSH-API-Key", "secret"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
		req.Header.Set(hdr.name, hdr.value)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d body=%s", hdr.name, rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}
}

func TestAdminHTTPUnequalKeyRejected(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAdminHTTPHandler(eng, "secret")
	for _, bearer := range []string{"sec", "secret-extra", "SECRET"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bearer %q status = %d", bearer, rec.Code)
		}
	}
}

func TestFormatAdminHTTPStartRefusesEmptyKey(t *testing.T) {
	if got := formatAdminHTTPStart("127.0.0.1:0", ""); got != "admin: http listening on 127.0.0.1:0 auth=refused-empty-key" {
		t.Fatalf("empty key start = %q", got)
	}
	got := formatAdminHTTPStart("127.0.0.1:0", "secret")
	if !strings.Contains(got, "auth=token") || strings.Contains(got, "secret") {
		t.Fatalf("token start leaked or mislabeled: %q", got)
	}
}

func TestAdminHTTPApproveAndDeny(t *testing.T) {
	eng, err := NewEngine(EngineConfig{FourEyesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.ensureFourEyesDirs(); err != nil {
		t.Fatal(err)
	}
	seed := func(token, requester, approver string) {
		t.Helper()
		pending := FourEyesPending{Token: token, Requester: requester, Rule: FourEyesRule{Approver: approver}}
		data, err := json.Marshal(pending)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(eng.fourEyesPendingDir(), token+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seed("abcdef123456", "alice", "bob")
	handler := NewAdminHTTPHandler(eng, "secret")
	post := func(path, body string, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if auth {
			req.Header.Set("Authorization", "Bearer secret")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := post("/v1/approvals/approve", `{"token":"abcdef123456","approver":"bob"}`, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth approve = %d", rec.Code)
	}
	if rec := post("/v1/approvals/approve", `{"token":"../evil","approver":"bob"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal approve = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := post("/v1/approvals/approve", `{"token":"abcdef123456","approver":"alice"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("self approve = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := post("/v1/approvals/approve", `{"token":"abcdef123456","approver":"bob"}`, true); rec.Code != http.StatusOK {
		t.Fatalf("approve = %d body=%s", rec.Code, rec.Body.String())
	}
	seed("deniedtoken1", "alice", "bob")
	if rec := post("/v1/approvals/deny", `{"token":"deniedtoken1"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("deny without approver = %d", rec.Code)
	}
	if rec := post("/v1/approvals/deny", `{"token":"../evil","approver":"carol"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal deny = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := eng.DenyRequest("../evil"); err == nil {
		t.Fatal("DenyRequest accepted a path token")
	}
	if rec := post("/v1/approvals/deny", `{"token":"deniedtoken1","approver":"carol"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong approver deny = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := post("/v1/approvals/deny", `{"token":"deniedtoken1","approver":"alice"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("self deny = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := post("/v1/approvals/deny", `{"token":"deniedtoken1","approver":"bob"}`, true); rec.Code != http.StatusOK {
		t.Fatalf("deny = %d body=%s", rec.Code, rec.Body.String())
	}
}
