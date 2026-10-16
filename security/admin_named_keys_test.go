package security

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAdminKey(name string) string {
	return name + "-" + strings.Repeat("0123456789abcdef", 3)
}

// chainEngine returns an engine with a flat audit log and an HMAC chain, plus
// the chain path.
func chainEngine(t *testing.T) (*Engine, string, string) {
	t.Helper()
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain")
	auditLog := filepath.Join(dir, "audit.log")
	eng, err := NewEngine(EngineConfig{
		AuditLogPath: auditLog,
		ChainPath:    chain,
		ChainKeyPath: filepath.Join(dir, "key"),
		FourEyesDir:  filepath.Join(dir, "foureyes"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.ensureFourEyesDirs(); err != nil {
		t.Fatal(err)
	}
	return eng, chain, auditLog
}

func seedPending(t *testing.T, eng *Engine, id, requester, approver string) string {
	t.Helper()
	data, err := json.Marshal(FourEyesPending{Token: "tok-" + id, RequestID: id, Requester: requester, Command: "rm -rf /srv", Rule: FourEyesRule{Approver: approver}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(eng.fourEyesPendingDir(), id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func adminDo(t *testing.T, h http.Handler, method, path, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdminHTTPLegacyKeyCannotDecide(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	pendingPath := seedPending(t, eng, "req-legacy", "alice", "")
	h := NewAdminHTTPHandlerWithKeys(eng, "legacy-secret", []AdminKey{{Name: "bob", Key: testAdminKey("bob")}})

	for _, path := range []string{"/v1/approvals/approve", "/v1/approvals/deny"} {
		if rec := adminDo(t, h, http.MethodPost, path, `{"token":"req-legacy"}`, "legacy-secret"); rec.Code != http.StatusForbidden {
			t.Fatalf("legacy %s = %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := adminDo(t, h, http.MethodPost, "/v1/guard/unban", `{"addr":"192.0.2.1"}`, "legacy-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("legacy unban = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("legacy key changed the pending request: %v", err)
	}
	// The legacy key still reads.
	if rec := adminDo(t, h, http.MethodGet, "/v1/approvals", "", "legacy-secret"); rec.Code != http.StatusOK {
		t.Fatalf("legacy read = %d", rec.Code)
	}
	ledger, _ := os.ReadFile(chain)
	if strings.Contains(string(ledger), "FOUREYES_DECISION") {
		t.Fatalf("legacy key produced a decision:\n%s", ledger)
	}
	if !strings.Contains(string(ledger), "status=403") || !strings.Contains(string(ledger), "principal=legacy") {
		t.Fatalf("admin audit missing legacy principal:\n%s", ledger)
	}
}

func TestAdminHTTPNamedKeyApprovesAndChainRecordsPrincipal(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	seedPending(t, eng, "req-named", "alice", "bob")
	h := NewAdminHTTPHandlerWithKeys(eng, "", []AdminKey{
		{Name: "alice", Key: testAdminKey("alice")},
		{Name: "bob", Key: testAdminKey("bob")},
	})
	rec := adminDo(t, h, http.MethodPost, "/v1/approvals/approve", `{"request_id":"req-named"}`, testAdminKey("bob"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"approver":"bob"`) {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(eng.fourEyesApprovedDir(), "req-named")); err != nil {
		t.Fatalf("approved marker missing: %v", err)
	}
	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	text := string(ledger)
	if !strings.Contains(text, "FOUREYES_DECISION request=req-named approver=bob decision=approve surface=http") {
		t.Fatalf("chain missing decision:\n%s", text)
	}
	if !strings.Contains(text, "principal=bob") {
		t.Fatalf("admin audit missing principal:\n%s", text)
	}
	if strings.Contains(text, testAdminKey("bob")) {
		t.Fatal("chain contains the raw admin key")
	}
	if ok, bad, err := eng.VerifyChain(chain); err != nil || !ok {
		t.Fatalf("chain verify = %v %d %v", ok, bad, err)
	}
}

func TestAdminHTTPApproverFieldRejected(t *testing.T) {
	eng, _, _ := chainEngine(t)
	pendingPath := seedPending(t, eng, "req-body", "alice", "")
	h := NewAdminHTTPHandlerWithKeys(eng, "", []AdminKey{{Name: "bob", Key: testAdminKey("bob")}})
	for _, body := range []string{
		`{"token":"req-body","approver":"bob"}`,
		`{"token":"req-body","approver":"carol"}`,
		`{"token":"req-body","extra":1}`,
		`{"token":"req-body"} {"token":"x"}`,
	} {
		for _, path := range []string{"/v1/approvals/approve", "/v1/approvals/deny"} {
			if rec := adminDo(t, h, http.MethodPost, path, body, testAdminKey("bob")); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %s = %d %s", path, body, rec.Code, rec.Body.String())
			}
		}
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("rejected body changed the request: %v", err)
	}
}

func TestAdminHTTPApprovalsOmitToken(t *testing.T) {
	eng, _, _ := chainEngine(t)
	seedPending(t, eng, "req-list", "alice", "")
	h := NewAdminHTTPHandler(eng, "legacy-secret")
	rec := adminDo(t, h, http.MethodGet, "/v1/approvals", "", "legacy-secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"token"`) || strings.Contains(body, "tok-req-list") || !strings.Contains(body, `"request_id":"req-list"`) {
		t.Fatalf("approval list leaked the token or hid the id: %s", body)
	}
}

func TestAdminHTTPDecisionFailsClosedWhenAuditFails(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	pendingPath := seedPending(t, eng, "req-audit", "alice", "")
	breakChain(t, eng, chain)
	h := NewAdminHTTPHandlerWithKeys(eng, "", []AdminKey{{Name: "bob", Key: testAdminKey("bob")}})
	rec := adminDo(t, h, http.MethodPost, "/v1/approvals/approve", `{"token":"req-audit"}`, testAdminKey("bob"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("approve with broken audit = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(eng.fourEyesApprovedDir(), "req-audit")); !os.IsNotExist(err) {
		t.Fatalf("marker written without audit: %v", err)
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("pending request was not restored: %v", err)
	}
}

// breakChain makes every later chain append fail by replacing the ledger file
// with a directory.
func breakChain(t *testing.T, eng *Engine, chain string) {
	t.Helper()
	if err := eng.LogEvent("TEST_SEED"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(chain); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("TEST_PROBE"); err == nil {
		t.Fatal("broken chain still accepted an event")
	}
}

func writeKeysFile(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.keys")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAdminKeysFile(t *testing.T) {
	good := "# approvers\n\nbob=" + testAdminKey("bob") + "\ncarol.ops=" + testAdminKey("carol") + "\n"
	keys, err := LoadAdminKeysFile(writeKeysFile(t, good, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Name != "bob" || keys[1].Name != "carol.ops" {
		t.Fatalf("keys = %#v", keys)
	}

	cases := map[string]struct {
		body string
		mode os.FileMode
	}{
		"group readable": {good, 0o640},
		"world readable": {good, 0o604},
		"duplicate name": {"bob=" + testAdminKey("bob") + "\nbob=" + testAdminKey("bob2") + "\n", 0o600},
		"duplicate key":  {"bob=" + testAdminKey("x") + "\ncarol=" + testAdminKey("x") + "\n", 0o600},
		"short key":      {"bob=short\n", 0o600},
		"bad name":       {"bob smith=" + testAdminKey("bob") + "\n", 0o600},
		"long name":      {strings.Repeat("a", 65) + "=" + testAdminKey("bob") + "\n", 0o600},
		"reserved name":  {"legacy=" + testAdminKey("bob") + "\n", 0o600},
		"no equals":      {testAdminKey("bob") + "\n", 0o600},
		"empty":          {"# nothing\n", 0o600},
		"space in key":   {"bob=" + testAdminKey("b") + " " + testAdminKey("c") + "\n", 0o600},
	}
	for name, tc := range cases {
		path := writeKeysFile(t, tc.body, tc.mode)
		_, err := LoadAdminKeysFile(path)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if strings.Contains(err.Error(), "0123456789abcdef") {
			t.Fatalf("%s: error leaked key material: %v", name, err)
		}
	}

	target := writeKeysFile(t, good, 0o600)
	link := filepath.Join(t.TempDir(), "link.keys")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdminKeysFile(link); err == nil {
		t.Fatal("symlinked keys file accepted")
	}
	if _, err := LoadAdminKeysFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing keys file accepted")
	}
	big := writeKeysFile(t, "#"+strings.Repeat("x", adminKeysFileMax+1)+"\n"+good, 0o600)
	if _, err := LoadAdminKeysFile(big); err == nil {
		t.Fatal("oversized keys file accepted")
	}
}

func TestAdminHTTPWrongKeyRejectedWithNamedKeys(t *testing.T) {
	eng, _, _ := chainEngine(t)
	h := NewAdminHTTPHandlerWithKeys(eng, "", []AdminKey{{Name: "bob", Key: testAdminKey("bob")}})
	for _, key := range []string{testAdminKey("bob") + "x", testAdminKey("bob")[:31], "bob", ""} {
		if rec := adminDo(t, h, http.MethodGet, "/v1/sessions", "", key); rec.Code != http.StatusUnauthorized {
			t.Fatalf("key %q = %d", key, rec.Code)
		}
	}
}

func TestAdminListenRefusesNonLoopback(t *testing.T) {
	for _, spec := range []string{"0.0.0.0:0", "[::]:0", ":0", "192.0.2.10:0", "unix:relative.sock"} {
		if ln, err := adminListen(context.Background(), spec); err == nil {
			ln.Close()
			t.Fatalf("%s accepted", spec)
		}
	}
	orig := adminLookupIPAddr
	t.Cleanup(func() { adminLookupIPAddr = orig })
	adminLookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("203.0.113.5")}}, nil
	}
	if ln, err := adminListen(context.Background(), "admin.example:0"); err == nil {
		ln.Close()
		t.Fatal("hostname with a public address accepted")
	}
	adminLookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	ln, err := adminListen(context.Background(), "admin.example:0")
	if err != nil {
		t.Fatalf("loopback hostname refused: %v", err)
	}
	ln.Close()
}

func TestAdminListenAcceptsLoopback(t *testing.T) {
	for _, spec := range []string{"127.0.0.1:0", "[::1]:0"} {
		ln, err := adminListen(context.Background(), spec)
		if err != nil {
			if spec == "[::1]:0" && strings.Contains(err.Error(), "assign requested address") {
				continue
			}
			t.Fatalf("%s refused: %v", spec, err)
		}
		ln.Close()
	}
}

// shortTempDir keeps Unix socket paths under the 104-byte sun_path limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "as")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAdminListenUnixSocket(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "a.sock")
	ln, err := adminListen(context.Background(), "unix:"+sock)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v", info.Mode())
	}
	// A live socket is refused.
	if ln2, err := adminListen(context.Background(), "unix:"+sock); err == nil {
		ln2.Close()
		t.Fatal("in-use socket replaced")
	}
	ln.Close()

	// A stale socket is replaced.
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	ln, err = adminListen(context.Background(), "unix:"+sock)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln.Close()

	// A regular file is refused.
	regular := filepath.Join(dir, "r.sock")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := adminListen(context.Background(), "unix:"+regular); err == nil {
		ln.Close()
		t.Fatal("regular file replaced")
	}

	// A directory that grants group or other access is refused.
	open := shortTempDir(t)
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if ln, err := adminListen(context.Background(), "unix:"+filepath.Join(open, "a.sock")); err == nil {
		ln.Close()
		t.Fatal("socket in a 0755 directory accepted")
	}
}

func TestAdminHTTPServerTimeoutsSet(t *testing.T) {
	srv := adminHTTPServerTimeouts(http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("timeouts = %+v", srv)
	}
	if srv.ReadTimeout > time.Minute {
		t.Fatalf("read timeout too long: %v", srv.ReadTimeout)
	}
}
