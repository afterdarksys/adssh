//go:build ee

package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestAdminOpenAPIListsHandlerPaths(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "docs", "openapi", "admin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, path := range AdminHTTPPaths() {
		if !strings.Contains(text, path) {
			t.Fatalf("openapi missing %s", path)
		}
	}
}

func TestAdminHTTPAuditsKeyFingerprintAndListRoutes(t *testing.T) {
	dir := t.TempDir()
	recordDir := filepath.Join(dir, "recordings")
	if err := os.MkdirAll(recordDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_RECORD_DIR", recordDir)
	if err := os.WriteFile(filepath.Join(recordDir, "sess-1.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sess-1.jsonl", filepath.Join(recordDir, "linked.jsonl")); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.log")
	chainPath := filepath.Join(dir, "chain")
	eng, err := NewEngine(EngineConfig{
		AuditLogPath: auditPath,
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent(`ELEVATE_REQUEST: session=sess-1 user=alice role=ops ttl=5m0s reason="ticket 1" expires_at=2099-01-01T00:00:00Z`); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("LEASE_REQUEST id=lease-old session=sess-1 source_type=file source=vaultfile as=TOKEN ttl=5m0s command=true"); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("LEASE_GRANT id=lease-old"); err != nil {
		t.Fatal(err)
	}

	handler := NewAdminHTTPHandler(eng, "secret")
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("healthz = %d", health.Code)
	}

	authed := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	recordings := authed("/v1/recordings")
	if recordings.Code != http.StatusOK || !strings.Contains(recordings.Body.String(), "sess-1") || strings.Contains(recordings.Body.String(), "linked.jsonl") {
		t.Fatalf("recordings = %d %s", recordings.Code, recordings.Body.String())
	}
	elevations := authed("/v1/elevations")
	if elevations.Code != http.StatusOK || !strings.Contains(elevations.Body.String(), `"action":"request"`) || !strings.Contains(elevations.Body.String(), "ops") {
		t.Fatalf("elevations = %d %s", elevations.Code, elevations.Body.String())
	}
	leases := authed("/v1/leases")
	if leases.Code != http.StatusOK || !strings.Contains(leases.Body.String(), `"delivery":"env"`) || !strings.Contains(leases.Body.String(), `"granted":true`) || strings.Contains(leases.Body.String(), "command") {
		t.Fatalf("leases = %d %s", leases.Code, leases.Body.String())
	}

	wrong := httptest.NewRecorder()
	wrongReq := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	wrongReq.Header.Set("Authorization", "Bearer nope")
	handler.ServeHTTP(wrong, wrongReq)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key = %d", wrong.Code)
	}

	logged, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(logged)
	sum := sha256.Sum256([]byte("secret"))
	fp := hex.EncodeToString(sum[:])
	if strings.Contains(text, "secret") || strings.Contains(text, "path=/healthz") {
		t.Fatalf("audit leaked the key or recorded healthz:\n%s", text)
	}
	if !strings.Contains(text, "ADMIN_HTTP method=GET path=/v1/recordings status=200 key_fp="+fp) {
		t.Fatalf("authorized audit missing fingerprint:\n%s", text)
	}
	nope := sha256.Sum256([]byte("nope"))
	if !strings.Contains(text, "path=/v1/sessions status=401 key_fp="+hex.EncodeToString(nope[:])) {
		t.Fatalf("rejected audit missing presented fingerprint:\n%s", text)
	}
}

func TestAdminListChainUnavailableAndMissingFile(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAdminHTTPHandler(eng, "secret")
	req := httptest.NewRequest(http.MethodGet, "/v1/leases", nil)
	req.Header.Set("X-ADSSH-API-Key", "secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "chain_unavailable") {
		t.Fatalf("leases without a chain = %d %s", rec.Code, rec.Body.String())
	}

	dir := t.TempDir()
	chained, err := NewEngine(EngineConfig{ChainPath: filepath.Join(dir, "missing-chain"), ChainKeyPath: filepath.Join(dir, "key")})
	if err != nil {
		t.Fatal(err)
	}
	session := &sys.Session{ID: "active-elev", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	session.ActivateElevation("ops", "ticket", time.Now().Add(time.Hour))
	items, err := chained.ListElevations()
	if err != nil || len(items) != 0 {
		t.Fatalf("missing chain file included active elevation: %v %#v", err, items)
	}
	if err := chained.LogEvent("ELEVATE_DROP: session=active-elev user=alice role=ops reason=\"done\""); err != nil {
		t.Fatal(err)
	}
	items, err = chained.ListElevations()
	if err != nil {
		t.Fatal(err)
	}
	foundActive := false
	for _, item := range items {
		if item.Action == "active" && item.SessionID == "active-elev" && item.Role == "ops" {
			foundActive = true
		}
	}
	if !foundActive {
		t.Fatalf("existing chain omitted the active elevation: %#v", items)
	}
}

func TestApprovalsPublicOmitsTokenAfterApproval(t *testing.T) {
	eng, err := NewEngine(EngineConfig{FourEyesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.ensureFourEyesDirs(); err != nil {
		t.Fatal(err)
	}
	session := &sys.Session{ID: "approve-session", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	pending, pendingFile, err := eng.createFourEyesPending("rm -rf /tmp/x", FourEyesRule{Approver: "bob"}, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	prompt := formatApprovalPrompt(pendingFile, pending.RequestID, "bob")
	if strings.Contains(prompt, pending.Token) || !strings.Contains(prompt, pending.RequestID) {
		t.Fatalf("prompt leaked the token or hid the request id: %q", prompt)
	}
	if err := eng.ApproveRequestAs(pending.Token, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(eng.fourEyesApprovedDir(), pending.RequestID)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pendingFile); !os.IsNotExist(err) {
		t.Fatalf("pending file remained: %v", err)
	}
	public, err := eng.ListApprovalsPublic()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(pending.Token)) {
		t.Fatalf("public approval list contained the token: %s", encoded)
	}
}
