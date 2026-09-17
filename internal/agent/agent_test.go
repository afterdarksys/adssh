package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"

	"mvdan.cc/sh/v3/interp"
)

// fakeVBin is a no-op, allowlisted virtual binary used by the happy-path test.
// It writes fixed output to the interp HandlerContext's Stdout, exactly as real
// virtual binaries do.
type fakeVBin struct{}

func (fakeVBin) Name() string        { return "noop-instrument" }
func (fakeVBin) Description() string { return "no-op test instrumentation vbin" }
func (fakeVBin) Usage() string       { return "noop-instrument" }
func (fakeVBin) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintf(hc.Stdout, "instrumented: %s\n", strings.Join(args, " "))
	return nil
}

const testToken = "correct-horse-battery-staple"

// TestMain registers the fake virtual binary into the process registry once,
// before any engine is constructed, so every engine built via NewEngine (which
// seeds its registry from the default) can find it.
func TestMain(m *testing.M) {
	security.Register(fakeVBin{})
	os.Exit(m.Run())
}

// setDefaultEngine builds an isolated engine (optionally with a deny policy and
// an audit chain) and installs it as the process default so the package-level
// security functions the agent calls route through it. It returns the chain
// ledger path for audit assertions.
func setDefaultEngine(t *testing.T, denyPolicy bool) string {
	t.Helper()
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain")
	cfg := security.EngineConfig{
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "key"),
		SessionID:    "test-session",
	}
	if denyPolicy {
		cfg.PolicySource = []byte(`package adssh.authz
default allow = false
default deny_reason = "instrumentation denied by test policy"
`)
	}
	eng, err := security.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	security.SetDefaultEngine(eng)
	return chainPath
}

func newTestServer(t *testing.T, tasks *TaskSet) *Server {
	t.Helper()
	s, err := New(testToken, tasks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func tasksWith(_ *testing.T, entries map[string]Task) *TaskSet {
	if entries == nil {
		entries = map[string]Task{}
	}
	return &TaskSet{tasks: entries}
}

func do(t *testing.T, s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestNewRefusesEmptyToken(t *testing.T) {
	if _, err := New("", nil); err == nil {
		t.Fatal("expected New to refuse an empty token (fail closed)")
	}
	if _, err := New("   ", nil); err == nil {
		t.Fatal("expected New to refuse a whitespace-only token (fail closed)")
	}
}

func TestHealthNeedsNoAuth(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, nil))
	rec := do(t, s, http.MethodGet, "/v1/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health body = %v, want status=ok", body)
	}
}

func TestMissingTokenIs401(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, nil))
	for _, path := range []string{"/v1/tasks", "/v1/instrument"} {
		method := http.MethodGet
		if path == "/v1/instrument" {
			method = http.MethodPost
		}
		rec := do(t, s, method, path, "", `{"task":"whatever"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without token = %d, want 401", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), testToken) {
			t.Fatal("error body leaked the token")
		}
	}
}

func TestWrongTokenIs401(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, nil))
	// A wrong token of the SAME length and one of a DIFFERENT length must both
	// 401. The auth path SHA-256s both sides before crypto/subtle's constant-time
	// compare, so the decision is independent of the presented token's length.
	sameLen := strings.Repeat("x", len(testToken))
	for _, tok := range []string{sameLen, "short", sameLen + "-and-then-much-longer"} {
		rec := do(t, s, http.MethodPost, "/v1/instrument", tok, `{"task":"noop"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong token %q = %d, want 401", tok, rec.Code)
		}
	}
}

func TestUnknownTaskIs404(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"noop": {VBin: "noop-instrument", Description: "d", Risk: "low"},
	}))
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, `{"task":"does-not-exist"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown task = %d, want 404", rec.Code)
	}
}

// TestTaskNotInAllowlistIsNotRunnable proves the network cannot invoke a real,
// registered virtual binary unless an operator allowlisted it as a task: the
// vbin "noop-instrument" exists in the registry, but with an empty allowlist the
// request that names it (as a task) is 404 and never dispatched.
func TestTaskNotInAllowlistIsNotRunnable(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, nil)) // empty allowlist
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, `{"task":"noop-instrument"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("naming a registered vbin as a task with empty allowlist = %d, want 404", rec.Code)
	}
}

func TestPolicyDenyIs403AndAudited(t *testing.T) {
	chainPath := setDefaultEngine(t, true) // deny-all policy
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"noop": {VBin: "noop-instrument", Args: []string{"a"}, Description: "d", Risk: "low"},
	}))
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, `{"task":"noop"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("policy-denied task = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), testToken) {
		t.Fatal("error body leaked the token")
	}
	data, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read audit chain: %v", err)
	}
	if !strings.Contains(string(data), "denied") || !strings.Contains(string(data), "noop") {
		t.Fatalf("audit chain missing denial entry, got:\n%s", data)
	}
}

func TestOversizedBodyIs413(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, nil))
	big := `{"task":"` + strings.Repeat("A", int(maxRequestBody)+1024) + `"}`
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, want 413", rec.Code)
	}
}

func TestHappyPath(t *testing.T) {
	setDefaultEngine(t, false) // allow-by-default (no policy)
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"noop": {VBin: "noop-instrument", Args: []string{"get", "x"}, Description: "d", Risk: "low"},
	}))
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, `{"task":"noop","dry_run":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("happy path = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp instrumentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Exit != 0 {
		t.Fatalf("resp = %+v, want ok=true exit=0", resp)
	}
	if !strings.Contains(resp.Output, "instrumented: noop-instrument get x") {
		t.Fatalf("output = %q, want captured vbin output including fixed args", resp.Output)
	}
	if resp.Task != "noop" {
		t.Fatalf("task = %q, want noop", resp.Task)
	}
}

func TestDryRunDefaultsTrueWhenOmitted(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"noop": {VBin: "noop-instrument", Description: "d", Risk: "low"},
	}))
	// Body omits dry_run entirely — request must still succeed (defaults true).
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, `{"task":"noop"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("omitted dry_run = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestUnknownVBinIs500(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"broken": {VBin: "vbin-that-does-not-exist", Description: "d", Risk: "low"},
	}))
	rec := do(t, s, http.MethodPost, "/v1/instrument", testToken, `{"task":"broken"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("task mapping to unknown vbin = %d, want 500", rec.Code)
	}
}

func TestTasksListing(t *testing.T) {
	setDefaultEngine(t, false)
	s := newTestServer(t, tasksWith(t, map[string]Task{
		"noop": {VBin: "noop-instrument", Description: "the description", Risk: "low"},
	}))
	rec := do(t, s, http.MethodGet, "/v1/tasks", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("tasks listing = %d, want 200", rec.Code)
	}
	var resp tasksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Tasks) != 1 || resp.Tasks[0].Name != "noop" || resp.Tasks[0].Description != "the description" {
		t.Fatalf("tasks listing = %+v, want the single noop task", resp.Tasks)
	}
}

func TestParseTasksRejectsMissingVBin(t *testing.T) {
	_, err := ParseTasks([]byte("tasks:\n  bad:\n    description: no vbin\n"))
	if err == nil {
		t.Fatal("expected ParseTasks to reject a task with no vbin")
	}
}

func TestLoadTasksMissingFileIsEmpty(t *testing.T) {
	ts, err := LoadTasks(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("LoadTasks on missing file = %v, want empty allowlist", err)
	}
	if ts.Len() != 0 {
		t.Fatalf("missing file yielded %d tasks, want 0", ts.Len())
	}
}

// --- readiness additions: identity, /v1/info ---

func TestAgentIDFromEnv(t *testing.T) {
	t.Setenv("ADSSH_AGENT_ID", "host-42")
	s, err := New("tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.agentID != "host-42" {
		t.Fatalf("agentID = %q; want host-42", s.agentID)
	}
}

func TestAgentIDDefaultsToHostnameNotConstant(t *testing.T) {
	t.Setenv("ADSSH_AGENT_ID", "")
	s, err := New("tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.agentID == "" {
		t.Fatal("agentID must not be empty")
	}
	// It should be the hostname, not the old hardcoded placeholder (unless the
	// machine is literally named that, which no fleet host is).
	if h, err := os.Hostname(); err == nil && h != "" && s.agentID != h {
		t.Fatalf("agentID = %q; want hostname %q", s.agentID, h)
	}
}

func TestInfoRequiresAuthAndReportsIdentity(t *testing.T) {
	t.Setenv("ADSSH_AGENT_ID", "host-info")
	s, err := New("sekret", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// no auth -> 401
	resp, err := http.Get(srv.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-auth /v1/info = %d; want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// with auth -> 200 and our identity
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/info", nil)
	req.Header.Set("Authorization", "Bearer sekret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth /v1/info = %d; want 200", resp.StatusCode)
	}
	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info["agent_id"] != "host-info" {
		t.Fatalf("info.agent_id = %v; want host-info", info["agent_id"])
	}
	if _, ok := info["uptime_seconds"]; !ok {
		t.Fatal("info missing uptime_seconds")
	}
}
