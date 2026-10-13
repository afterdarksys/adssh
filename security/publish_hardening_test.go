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
	eng.LogEvent(`ELEVATE_REQUEST: session=sess-1 user=alice role=ops ttl=5m0s reason="ticket 1" expires_at=2099-01-01T00:00:00Z`)
	eng.LogEvent("LEASE_REQUEST id=lease-old session=sess-1 source_type=file source=vaultfile as=TOKEN ttl=5m0s command=true")
	eng.LogEvent("LEASE_GRANT id=lease-old")

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
	sys.RegisterSession(session)
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	session.ActivateElevation("ops", "ticket", time.Now().Add(time.Hour))
	items, err := chained.ListElevations()
	if err != nil || len(items) != 0 {
		t.Fatalf("missing chain file included active elevation: %v %#v", err, items)
	}
	chained.LogEvent("ELEVATE_DROP: session=active-elev user=alice role=ops reason=\"done\"")
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

func TestExplainUsesRequiredRoleFromPolicy(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
required_role := "ops"
`)})
	if err != nil {
		t.Fatal(err)
	}
	explanation, err := eng.ExplainCommand("", []string{"rm", "-rf", "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.RequiredRole != "ops" || explanation.Outcome != "denied" {
		t.Fatalf("explanation = %#v", explanation)
	}
	joined := strings.Join(explanation.NextSteps, "\n")
	if !strings.Contains(joined, "elevate request ops --for 10m") {
		t.Fatalf("next steps = %#v", explanation.NextSteps)
	}

	meta, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
metadata := {"required_role": "netops"}
`)})
	if err != nil {
		t.Fatal(err)
	}
	explanation, err = meta.ExplainCommand("", []string{"lease"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.RequiredRole != "netops" {
		t.Fatalf("metadata role = %#v", explanation)
	}

	invalid, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
required_role := "ops; drop"
`)})
	if err != nil {
		t.Fatal(err)
	}
	explanation, err = invalid.ExplainCommand("", []string{"elevate"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.RequiredRole != "" || !strings.Contains(strings.Join(explanation.NextSteps, "\n"), "elevate request <role>") {
		t.Fatalf("invalid role was accepted: %#v", explanation)
	}
}

func TestApprovalNoticeOmitsTokenAndRejectsMetadataURL(t *testing.T) {
	token := "super-secret-approval-token"
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(http.MaxBytesReader(w, r.Body, 1<<20))
		body = buf.Bytes()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	t.Setenv("ADSSH_4EYES_WEBHOOK", server.URL)
	t.Setenv("ADSSH_APPROVAL_LINK_BASE", "https://127.0.0.1/hooks")
	fingerprint := fingerprintSecret(token)
	if err := sendApprovalNotice(approvalNotice{
		Event:            "approval_required",
		Kind:             "foureyes",
		Command:          "rm",
		RequiredApprover: "bob",
		Fingerprint:      fingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(token)) || bytes.Contains(body, []byte(`"token"`)) {
		t.Fatalf("webhook body leaked the token: %s", body)
	}
	var notice approvalNotice
	if err := json.Unmarshal(body, &notice); err != nil {
		t.Fatal(err)
	}
	if notice.Fingerprint != fingerprint || !strings.Contains(notice.ApprovalLink, "/approvals/"+fingerprint) {
		t.Fatalf("notice = %#v", notice)
	}
	t.Setenv("ADSSH_4EYES_WEBHOOK", "http://169.254.169.254/hook")
	if err := sendApprovalNotice(approvalNotice{Event: "approval_required", Kind: "foureyes", Command: "rm", Fingerprint: fingerprint}); err == nil {
		t.Fatal("metadata webhook was dialed")
	}
}

func TestPolicyDenyNoticeForLeaseOnly(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
required_role := "ops"
`)})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan approvalNotice, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var notice approvalNotice
		if err := json.NewDecoder(r.Body).Decode(&notice); err == nil {
			got <- notice
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	t.Setenv("ADSSH_4EYES_WEBHOOK", server.URL)
	if err := eng.gateCommand(false, []string{"rm", "-rf", "/tmp/x"}, ""); err == nil {
		t.Fatal("rm was allowed")
	}
	select {
	case notice := <-got:
		t.Fatalf("rm denial sent a notice: %#v", notice)
	case <-time.After(200 * time.Millisecond):
	}
	if err := eng.gateCommand(false, []string{"lease", "--from", "env:TOKEN"}, ""); err == nil {
		t.Fatal("lease was allowed")
	}
	select {
	case notice := <-got:
		if notice.Event != "policy_denied" || notice.Kind != "lease" || notice.RequiredApprover != "ops" {
			t.Fatalf("notice = %#v", notice)
		}
		if notice.Fingerprint != fingerprintSecret("lease") {
			t.Fatalf("fingerprint = %s", notice.Fingerprint)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lease denial did not send a notice")
	}
}

func TestFourEyesApproveBySecretUsesRequestIDMarker(t *testing.T) {
	eng, err := NewEngine(EngineConfig{FourEyesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.ensureFourEyesDirs(); err != nil {
		t.Fatal(err)
	}
	session := &sys.Session{ID: "approve-session", User: "alice"}
	sys.RegisterSession(session)
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

func TestLeaseDeliveryPathsAndEvidenceDigest(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("super-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	nulPath := filepath.Join(t.TempDir(), "nul-secret")
	if err := os.WriteFile(nulPath, []byte("super-\x00secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runLeaseVBin(t, eng, []string{"lease", "--from", "file:" + nulPath, "--via", "env", "--as", "TOKEN", "--", "/usr/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("env NUL secret was accepted: %v", err)
	}
	_, err = runLeaseVBin(t, eng, []string{"lease", "--from", "file:" + secretPath, "--via", "stdin", "--as", "TOKEN", "--", "/usr/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "--as is only valid with --via env") {
		t.Fatalf("stdin accepted --as: %v", err)
	}

	t.Setenv("ADSSH_LEASE_HELPER", "1")
	t.Setenv("ADSSH_LEASE_HELPER_MODE", "stdin")
	t.Setenv("ADSSH_LEASE_EXPECT_NUL", "1")
	_, err = runLeaseVBin(t, eng, []string{
		"lease", "--from", "file:" + nulPath, "--via", "stdin", "--", binary, "-test.run=^TestLeaseHelperProcess$",
	})
	if err != nil {
		t.Fatal(err)
	}

	wide := bytes.Repeat([]byte("a"), 128*1024)
	widePath := filepath.Join(t.TempDir(), "wide-secret")
	if err := os.WriteFile(widePath, wide, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_LEASE_HELPER_MODE", "fd")
	t.Setenv("ADSSH_LEASE_EXPECT_NUL", "")
	t.Setenv("ADSSH_LEASE_EXPECT_LEN", "131072")
	_, err = runLeaseVBin(t, eng, []string{
		"lease", "--from", "file:" + widePath, "--via", "fd", "--ttl", "20s", "--", binary, "-test.run=^TestLeaseHelperProcess$",
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ledger := filepath.Join(dir, "chain")
	chained, err := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: filepath.Join(dir, "key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_LEASE_HELPER_MODE", "stdin")
	t.Setenv("ADSSH_LEASE_EXPECT_LEN", "")
	t.Setenv("ADSSH_LEASE_EXPECT_NUL", "")
	_, err = runLeaseVBin(t, chained, []string{
		"lease", "--from", "file:" + secretPath, "--via", "stdin", "--", binary, "-test.run=^TestLeaseHelperProcess$",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := chained.BuildEvidence(EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(bundle.Entries)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != bundle.DigestSHA256 {
		t.Fatal("evidence digest changed when lease metadata was attached")
	}
	if len(bundle.Leases) != 1 || bundle.Leases[0].Delivery != "stdin" || !bundle.Leases[0].Granted || bundle.Leases[0].Destination != "stdin" {
		t.Fatalf("leases = %#v", bundle.Leases)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("super-secret")) {
		t.Fatal("evidence bundle contained the leased secret")
	}
	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("delivery=stdin")) || !bytes.Contains(raw, []byte("as=stdin")) {
		t.Fatalf("lease audit missing delivery: %s", raw)
	}
}
