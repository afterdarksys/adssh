package security

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/attachproto"
	"github.com/afterdarksys/adssh/internal/sys"
)

// lockedBuffer is the session's primary terminal: the broadcaster writes it
// while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type attachFixture struct {
	eng      *Engine
	srv      *httptest.Server
	chain    string
	auditLog string
	session  *sys.Session
	primary  *lockedBuffer
	ptyRead  *os.File
}

type attachOptions struct {
	policy string
}

func newAttachFixture(t *testing.T, id string, opts attachOptions) *attachFixture {
	t.Helper()
	t.Setenv("ADSSH_RECORD_DIR", t.TempDir())
	t.Setenv("ADSSH_SNOOP_NOTIFY_LOCK", "")
	t.Setenv("ADSSH_SNOOP_NOTIFY", "")
	dir := t.TempDir()
	ents := filepath.Join(dir, "entitlements.yaml")
	if err := os.WriteFile(ents, []byte("users:\n  alice: [\"*\"]\n  ops: [admin.snoop.rw]\n  ops2: [admin.snoop.rw]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := EngineConfig{
		AuditLogPath:     filepath.Join(dir, "audit.log"),
		ChainPath:        filepath.Join(dir, "chain"),
		ChainKeyPath:     filepath.Join(dir, "key"),
		FourEyesDir:      filepath.Join(dir, "foureyes"),
		EntitlementsPath: ents,
	}
	if opts.policy != "" {
		cfg.PolicySource = []byte(opts.policy)
	}
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.ensureFourEyesDirs(); err != nil {
		t.Fatal(err)
	}
	ptyRead, ptyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ptyRead.Close(); ptyWrite.Close() })
	primary := &lockedBuffer{}
	session := &sys.Session{ID: id, User: "alice", Out: sys.NewOutputBroadcaster(primary), PTYMaster: ptyWrite}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	keys := []AdminKey{}
	for _, name := range []string{"ops", "ops2", "carol", "viewer"} {
		keys = append(keys, AdminKey{Name: name, Key: testAdminKey(name)})
	}
	srv := httptest.NewServer(NewAdminHTTPHandlerWithKeys(eng, "legacy-secret-legacy-secret-legacy", keys))
	t.Cleanup(srv.Close)
	// Runs after the test's connections close: every attach must have
	// written its detach before the temp directories go away.
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			chain, _ := os.ReadFile(cfg.ChainPath)
			if strings.Count(string(chain), "MIRROR_ATTACH key=") == strings.Count(string(chain), "MIRROR_DETACH key=") {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("an attach did not write its detach")
	})
	return &attachFixture{eng: eng, srv: srv, chain: cfg.ChainPath, auditLog: cfg.AuditLogPath,
		session: session, primary: primary, ptyRead: ptyRead}
}

func (f *attachFixture) ledger(t *testing.T) string {
	t.Helper()
	chain, err := os.ReadFile(f.chain)
	if err != nil {
		t.Fatal(err)
	}
	flat, err := os.ReadFile(f.auditLog)
	if err != nil {
		t.Fatal(err)
	}
	return string(chain) + "\n" + string(flat)
}

func attachQuery(user, mode, purpose, reason string) url.Values {
	q := url.Values{}
	q.Set("user", user)
	q.Set("mode", mode)
	q.Set("purpose", purpose)
	q.Set("reason", reason)
	return q
}

type attachResult struct {
	status int
	body   string
	conn   net.Conn
	br     *bufio.Reader
}

// attachDial sends the upgrade request on a raw connection. upgrade=false
// leaves out the Upgrade header.
func (f *attachFixture) attachDial(t *testing.T, key, id string, q url.Values, upgrade bool) attachResult {
	t.Helper()
	conn, err := net.Dial("tcp", f.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, f.srv.URL+"/v1/sessions/"+url.PathEscape(id)+"/attach?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if upgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", attachproto.AttachProtocol)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		conn.Close()
		return attachResult{status: resp.StatusCode, body: string(body)}
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), attachproto.AttachProtocol) {
		t.Fatalf("101 without Upgrade: %v", resp.Header)
	}
	_ = conn.SetDeadline(time.Time{})
	t.Cleanup(func() { conn.Close() })
	return attachResult{status: resp.StatusCode, conn: conn, br: br}
}

func (f *attachFixture) attachOK(t *testing.T, key string, q url.Values) attachResult {
	t.Helper()
	res := f.attachDial(t, key, f.session.ID, q, true)
	if res.status != http.StatusSwitchingProtocols {
		t.Fatalf("attach = %d %s", res.status, res.body)
	}
	return res
}

func errorCode(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	return e.Error
}

// readUntil reads frames until the Out stream contains want or a Close
// arrives. It returns the output and the close reason ("" when want was seen).
func readUntil(t *testing.T, res attachResult, want string, timeout time.Duration) (string, string) {
	t.Helper()
	_ = res.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = res.conn.SetReadDeadline(time.Time{}) }()
	var out strings.Builder
	for {
		typ, payload, err := attachproto.ReadAttachFrame(res.br)
		if err != nil {
			t.Fatalf("read frame (have %q): %v", out.String(), err)
		}
		switch typ {
		case attachproto.AttachFrameOut:
			out.Write(payload)
			if want != "" && strings.Contains(out.String(), want) {
				return out.String(), ""
			}
		case attachproto.AttachFrameClose:
			var c struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(payload, &c); err != nil {
				t.Fatalf("close payload %q: %v", payload, err)
			}
			return out.String(), c.Reason
		default:
			t.Fatalf("unexpected frame 0x%02x", typ)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAttachErrorCodes(t *testing.T) {
	f := newAttachFixture(t, "attach-errors", attachOptions{})
	view := attachQuery("alice", "view", "support", "ticket 42")
	with := func(k, v string) url.Values {
		q := attachQuery("alice", "view", "support", "ticket 42")
		q.Set(k, v)
		return q
	}
	cases := []struct {
		name    string
		key     string
		id      string
		q       url.Values
		upgrade bool
		status  int
		code    string
	}{
		{"no upgrade header", testAdminKey("viewer"), f.session.ID, view, false, 400, "bad_upgrade"},
		{"bad mode", testAdminKey("viewer"), f.session.ID, with("mode", "write"), true, 400, "bad_mode"},
		{"missing purpose", testAdminKey("viewer"), f.session.ID, with("purpose", ""), true, 400, "purpose_required"},
		{"unknown purpose", testAdminKey("viewer"), f.session.ID, with("purpose", "curiosity"), true, 400, "purpose_required"},
		{"missing reason", testAdminKey("viewer"), f.session.ID, with("reason", "  "), true, 400, "reason_required"},
		{"control in reason", testAdminKey("viewer"), f.session.ID, with("reason", "a\x1b[2Jb"), true, 400, "reason_required"},
		{"long reason", testAdminKey("viewer"), f.session.ID, with("reason", strings.Repeat("r", 513)), true, 400, "reason_required"},
		{"read-only key", "legacy-secret-legacy-secret-legacy", f.session.ID, view, true, 403, "attach_forbidden"},
		{"no session", testAdminKey("viewer"), "no-such-session", view, true, 404, "session_not_found"},
		{"wrong user", testAdminKey("viewer"), f.session.ID, with("user", "bob"), true, 409, "user_mismatch"},
		{"rw without entitlement", testAdminKey("carol"), f.session.ID, with("mode", "rw"), true, 403, "attach_forbidden"},
	}
	for _, c := range cases {
		res := f.attachDial(t, c.key, c.id, c.q, c.upgrade)
		if res.status != c.status {
			t.Fatalf("%s: status %d %s, want %d", c.name, res.status, res.body, c.status)
		}
		if want := `{"error":"` + c.code + `"}` + "\n"; res.body != want {
			t.Fatalf("%s: body %q, want %q", c.name, res.body, want)
		}
	}
	if strings.Contains(f.primary.String(), "[adssh]") {
		t.Fatalf("a refused attach wrote a notice: %q", f.primary.String())
	}
	if strings.Contains(f.ledger(t), "MIRROR_ATTACH") {
		t.Fatal("a refused attach was recorded as an attach")
	}
	// An unauthenticated attach is the router's 401, never "not found".
	if res := f.attachDial(t, "", f.session.ID, view, true); res.status != http.StatusUnauthorized {
		t.Fatalf("no key = %d %s", res.status, res.body)
	}
}

func TestAttachViewStreamsOutputAndAudits(t *testing.T) {
	f := newAttachFixture(t, "attach-view", attachOptions{})
	res := f.attachOK(t, testAdminKey("viewer"), attachQuery("alice", "view", "support", "ticket 42"))
	waitFor(t, "attach notice", func() bool {
		return strings.Contains(f.primary.String(), "[adssh] viewer is viewing this session")
	})
	// The listener joins just after the notice; keep writing until it shows.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				_, _ = f.session.Out.Write([]byte("hello-from-session\r\n"))
			}
		}
	}()
	_, reason := readUntil(t, res, "hello-from-session", 5*time.Second)
	close(stop)
	if reason != "" {
		t.Fatalf("closed early: %s", reason)
	}
	if err := attachproto.WriteAttachFrame(res.conn, attachproto.AttachFrameClose, []byte(`{"reason":"detach"}`)); err != nil {
		t.Fatal(err)
	}
	if _, reason := readUntil(t, res, "", 5*time.Second); reason != "detach" {
		t.Fatalf("close reason %q, want detach", reason)
	}
	waitFor(t, "detach notice", func() bool {
		return strings.Contains(f.primary.String(), "[adssh] viewer has detached")
	})
	waitFor(t, "MIRROR_DETACH", func() bool { return strings.Contains(f.ledger(t), "MIRROR_DETACH") })
	ledger := f.ledger(t)
	for _, want := range []string{
		`MIRROR_ATTACH key=viewer mode=view purpose=support reason=\"ticket 42\" session=attach-view user=alice notify=true`,
		`MIRROR_DETACH key=viewer mode=view purpose=support reason=\"ticket 42\" session=attach-view user=alice notify=true`,
		"status=101",
	} {
		if !strings.Contains(ledger, want) && !strings.Contains(ledger, strings.ReplaceAll(want, `\"`, `"`)) {
			t.Fatalf("ledger lacks %s:\n%s", want, ledger)
		}
	}
}

func TestAttachViewRefusesInput(t *testing.T) {
	f := newAttachFixture(t, "attach-view-in", attachOptions{})
	for _, typ := range []byte{attachproto.AttachFrameIn, attachproto.AttachFrameResize} {
		res := f.attachOK(t, testAdminKey("viewer"), attachQuery("alice", "view", "support", "look"))
		payload := []byte("view-keystroke")
		if typ == attachproto.AttachFrameResize {
			payload = []byte(`{"cols":100,"rows":30}`)
		}
		if err := attachproto.WriteAttachFrame(res.conn, typ, payload); err != nil {
			t.Fatal(err)
		}
		if _, reason := readUntil(t, res, "", 5*time.Second); reason != "view_only" {
			t.Fatalf("type 0x%02x: close reason %q, want view_only", typ, reason)
		}
	}
	// Nothing reached the terminal.
	_ = f.ptyRead.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 64)
	if n, _ := f.ptyRead.Read(buf); n > 0 {
		t.Fatalf("view attach wrote %q to the session", buf[:n])
	}
}

// attachPending asks for rw and expects 428 with a request id.
func (f *attachFixture) attachPending(t *testing.T, key string, q url.Values) string {
	t.Helper()
	res := f.attachDial(t, key, f.session.ID, q, true)
	if res.status != http.StatusPreconditionRequired {
		t.Fatalf("rw attach = %d %s, want 428", res.status, res.body)
	}
	var body struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal([]byte(res.body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "approval_required" || body.RequestID == "" {
		t.Fatalf("428 body %s", res.body)
	}
	return body.RequestID
}

func TestAttachRWSupportNeedsOwnerApproval(t *testing.T) {
	f := newAttachFixture(t, "attach-rw-support", attachOptions{})
	q := attachQuery("alice", "rw", "support", "help alice with vim")
	id := f.attachPending(t, testAdminKey("ops"), q)
	if again := f.attachPending(t, testAdminKey("ops"), q); again != id {
		t.Fatalf("second try opened a new request %s, want %s", again, id)
	}
	// Only the owner may approve a support attach.
	if err := f.eng.DecideRequest(id, "ops", FourEyesSurfaceHTTP, true); err == nil {
		t.Fatal("the requesting key approved its own attach")
	}
	if err := f.eng.DecideRequest(id, "carol", FourEyesSurfaceHTTP, true); err == nil {
		t.Fatal("a non-owner approved a support attach")
	}
	if err := f.eng.DecideRequest(id, "alice", FourEyesSurfaceShell, true); err != nil {
		t.Fatalf("owner approval: %v", err)
	}
	res := f.attachOK(t, testAdminKey("ops"), q)
	waitFor(t, "controlling notice", func() bool {
		return strings.Contains(f.primary.String(), "[adssh] ops is controlling this session")
	})

	// Keystrokes reach the session's terminal.
	const keys = "secret-keystroke-xyzzy\r"
	if err := attachproto.WriteAttachFrame(res.conn, attachproto.AttachFrameIn, []byte(keys)); err != nil {
		t.Fatal(err)
	}
	_ = f.ptyRead.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(keys))
	if _, err := io.ReadFull(f.ptyRead, got); err != nil || string(got) != keys {
		t.Fatalf("pty got %q (%v), want %q", got, err, keys)
	}
	// A resize is accepted in rw (the pipe cannot be resized; the attach stays up).
	if err := attachproto.WriteAttachFrame(res.conn, attachproto.AttachFrameResize, []byte(`{"cols":100,"rows":30}`)); err != nil {
		t.Fatal(err)
	}

	// A command the session runs during the rw attach names the controller.
	if err := f.eng.gateCommand(false, []string{"echo", "during-rw"}, f.session.ID); err != nil {
		t.Fatalf("gate: %v", err)
	}
	// A second controller is refused; the approval was consumed.
	if res2 := f.attachDial(t, testAdminKey("ops2"), f.session.ID, q, true); res2.status != http.StatusConflict ||
		res2.body != `{"error":"controller_present"}`+"\n" {
		t.Fatalf("second rw = %d %s", res2.status, res2.body)
	}

	if err := attachproto.WriteAttachFrame(res.conn, attachproto.AttachFrameClose, []byte(`{"reason":"detach"}`)); err != nil {
		t.Fatal(err)
	}
	if _, reason := readUntil(t, res, "", 5*time.Second); reason != "detach" {
		t.Fatalf("close reason %q", reason)
	}
	waitFor(t, "controller released", func() bool { return f.session.Controller() == "" })
	if err := f.eng.gateCommand(false, []string{"echo", "after-rw"}, f.session.ID); err != nil {
		t.Fatalf("gate: %v", err)
	}
	waitFor(t, "MIRROR_DETACH", func() bool { return strings.Contains(f.ledger(t), "MIRROR_DETACH key=ops") })
	ledger := f.ledger(t)
	if !strings.Contains(ledger, "echo during-rw via=ops") {
		t.Fatalf("rw command lacks via=ops:\n%s", ledger)
	}
	if strings.Contains(ledger, "after-rw via=") {
		t.Fatalf("command after detach still tagged:\n%s", ledger)
	}
	if strings.Contains(ledger, "xyzzy") {
		t.Fatalf("keystrokes reached the audit record:\n%s", ledger)
	}
	if !strings.Contains(ledger, "MIRROR_ATTACH key=ops mode=rw purpose=support") {
		t.Fatalf("ledger lacks the rw attach:\n%s", ledger)
	}
	// The approval is single use.
	f.attachPending(t, testAdminKey("ops"), q)
}

func TestAttachRWInvestigationNeedsSecondKey(t *testing.T) {
	f := newAttachFixture(t, "attach-rw-invest", attachOptions{})
	q := attachQuery("alice", "rw", "investigation", "IR-7")
	id := f.attachPending(t, testAdminKey("ops"), q)
	if err := f.eng.DecideRequest(id, "alice", FourEyesSurfaceShell, true); err == nil {
		t.Fatal("the session owner approved an investigation attach")
	}
	if err := f.eng.DecideRequest(id, "alice", FourEyesSurfaceHTTP, true); err == nil {
		t.Fatal("a key named for the owner approved an investigation attach")
	}
	h := NewAdminHTTPHandlerWithKeys(f.eng, "", []AdminKey{{Name: "ops", Key: testAdminKey("ops")}, {Name: "carol", Key: testAdminKey("carol")}})
	if rec := adminDo(t, h, http.MethodPost, "/v1/approvals/approve", `{"request_id":"`+id+`"}`, testAdminKey("ops")); rec.Code == http.StatusOK {
		t.Fatal("the requesting key approved its own investigation")
	}
	f.attachPending(t, testAdminKey("ops"), q)
	if rec := adminDo(t, h, http.MethodPost, "/v1/approvals/approve", `{"request_id":"`+id+`"}`, testAdminKey("carol")); rec.Code != http.StatusOK {
		t.Fatalf("second key approval = %d %s", rec.Code, rec.Body.String())
	}
	res := f.attachOK(t, testAdminKey("ops"), q)
	if err := attachproto.WriteAttachFrame(res.conn, attachproto.AttachFrameClose, []byte(`{"reason":"detach"}`)); err != nil {
		t.Fatal(err)
	}
	if _, reason := readUntil(t, res, "", 5*time.Second); reason != "detach" {
		t.Fatalf("close reason %q", reason)
	}
}

func TestAttachRWRefusedForAssertedIdentity(t *testing.T) {
	for _, source := range []string{sys.IdentitySourceAsserted, sys.IdentitySourceDeviceLogin} {
		f := newAttachFixture(t, "attach-rw-"+source, attachOptions{})
		f.session.SetIdentitySource(source)
		res := f.attachDial(t, testAdminKey("ops"), f.session.ID, attachQuery("alice", "rw", "support", "x"), true)
		if res.status != http.StatusForbidden || res.body != `{"error":"attach_forbidden"}`+"\n" {
			t.Fatalf("%s: rw = %d %s", source, res.status, res.body)
		}
		// View stays possible.
		f.attachOK(t, testAdminKey("viewer"), attachQuery("alice", "view", "support", "x"))
	}
}

func TestSnoopNotifyResolution(t *testing.T) {
	no, yes := false, true
	cases := []struct {
		lock, def, purpose string
		policy             *bool
		want               bool
	}{
		{"", "", "support", nil, true},
		{"", "on", "support", nil, true},
		{"", "off", "support", nil, false},
		{"", "off", "investigation", nil, true},
		{"", "on", "investigation", &no, false},
		{"", "on", "support", &no, false},
		{"", "off", "support", &yes, true},
		{"on", "off", "investigation", &no, true},
		{"on", "off", "support", &no, true},
		{"garbage", "off", "support", &no, true},
		{"off", "off", "support", nil, false},
		{"", "garbage", "support", nil, true},
	}
	for _, c := range cases {
		if got := resolveSnoopNotify(c.lock, c.def, c.purpose, c.policy); got != c.want {
			t.Fatalf("lock=%q default=%q purpose=%s policy=%v: got %v want %v", c.lock, c.def, c.purpose, c.policy, got, c.want)
		}
	}
}

const silentInvestigationPolicy = `package adssh.authz
default allow = true
notify = false {
	input.command == "snoop"
	input.snoop.purpose == "investigation"
	input.snoop.mode == "view"
	input.snoop.user == "alice"
}
`

func TestSnoopNotifyPolicyAndLock(t *testing.T) {
	cases := []struct {
		name, lock, def, purpose string
		policy                   string
		notice                   bool
	}{
		{"policy silences investigation", "", "on", "investigation", silentInvestigationPolicy, false},
		{"lock overrides policy", "on", "on", "investigation", silentInvestigationPolicy, true},
		{"no rule keeps investigation visible", "", "off", "investigation", "", true},
		{"default off silences support", "", "off", "support", "", false},
		{"default on shows support", "", "on", "support", "", true},
	}
	for i, c := range cases {
		f := newAttachFixture(t, "attach-notify-"+string(rune('a'+i)), attachOptions{policy: c.policy})
		t.Setenv("ADSSH_SNOOP_NOTIFY_LOCK", c.lock)
		t.Setenv("ADSSH_SNOOP_NOTIFY", c.def)
		res := f.attachOK(t, testAdminKey("viewer"), attachQuery("alice", "view", c.purpose, "case"))
		if err := attachproto.WriteAttachFrame(res.conn, attachproto.AttachFrameClose, []byte(`{"reason":"detach"}`)); err != nil {
			t.Fatal(err)
		}
		readUntil(t, res, "", 5*time.Second)
		waitFor(t, "MIRROR_DETACH", func() bool { return strings.Contains(f.ledger(t), "MIRROR_DETACH") })
		shown := strings.Contains(f.primary.String(), "[adssh] viewer")
		if shown != c.notice {
			t.Fatalf("%s: notice shown=%v want %v (%q)", c.name, shown, c.notice, f.primary.String())
		}
		wantField := "notify=false"
		if c.notice {
			wantField = "notify=true"
		}
		if !strings.Contains(f.ledger(t), wantField) {
			t.Fatalf("%s: ledger lacks %s", c.name, wantField)
		}
	}
}

func TestAttachPolicyDenyForbids(t *testing.T) {
	f := newAttachFixture(t, "attach-policy-deny", attachOptions{policy: `package adssh.authz
default allow = true
allow = false { input.command == "snoop" }
`})
	res := f.attachDial(t, testAdminKey("viewer"), f.session.ID, attachQuery("alice", "view", "support", "x"), true)
	if res.status != http.StatusForbidden || res.body != `{"error":"attach_forbidden"}`+"\n" {
		t.Fatalf("policy-denied attach = %d %s", res.status, res.body)
	}
}

func TestAttachIdleTimeout(t *testing.T) {
	restore := setAttachIdleTimeout(200 * time.Millisecond)
	defer restore()
	f := newAttachFixture(t, "attach-idle", attachOptions{})
	res := f.attachOK(t, testAdminKey("viewer"), attachQuery("alice", "view", "support", "x"))
	if _, reason := readUntil(t, res, "", 5*time.Second); reason != "idle" {
		t.Fatalf("close reason %q, want idle", reason)
	}
}

func TestAttachSessionEndClosesAttach(t *testing.T) {
	f := newAttachFixture(t, "attach-session-end", attachOptions{})
	res := f.attachOK(t, testAdminKey("viewer"), attachQuery("alice", "view", "support", "x"))
	waitFor(t, "attach notice", func() bool { return strings.Contains(f.primary.String(), "is viewing") })
	sys.UnregisterSession(f.session.ID)
	if _, reason := readUntil(t, res, "", 5*time.Second); reason != "session_ended" {
		t.Fatalf("close reason %q, want session_ended", reason)
	}
}

func TestAttachViewerCap(t *testing.T) {
	f := newAttachFixture(t, "attach-cap", attachOptions{})
	q := attachQuery("alice", "view", "support", "x")
	for i := 0; i < attachMaxViewers; i++ {
		f.attachOK(t, testAdminKey("viewer"), q)
	}
	res := f.attachDial(t, testAdminKey("viewer"), f.session.ID, q, true)
	if res.status != http.StatusConflict || res.body != `{"error":"viewer_limit"}`+"\n" {
		t.Fatalf("ninth viewer = %d %s", res.status, res.body)
	}
}

func TestAttachFailsClosedWhenAuditFails(t *testing.T) {
	f := newAttachFixture(t, "attach-audit-fail", attachOptions{})
	breakChain(t, f.eng, f.chain)
	res := f.attachDial(t, testAdminKey("viewer"), f.session.ID, attachQuery("alice", "view", "support", "x"), true)
	if res.status != http.StatusServiceUnavailable || res.body != `{"error":"audit_unavailable"}`+"\n" {
		t.Fatalf("attach with broken audit = %d %s", res.status, res.body)
	}
	if strings.Contains(f.primary.String(), "[adssh]") {
		t.Fatal("an unaudited attach notified the session")
	}
}

// A "*" entitlement does not grant rw snoop; the key must be named explicitly.
func TestSnoopRWEntitlementMustBeExplicit(t *testing.T) {
	eng := &Engine{entitlements: EntitlementsConfig{Users: map[string][]string{
		"wild": {"*"}, "ops": {"admin.snoop.rw"}, "both": {"*", "admin.snoop.rw"},
	}}}
	if eng.HasExplicitEntitlement("wild", snoopRWEntitlement) {
		t.Fatal("wildcard must not grant admin.snoop.rw")
	}
	if !eng.HasExplicitEntitlement("ops", snoopRWEntitlement) || !eng.HasExplicitEntitlement("both", snoopRWEntitlement) {
		t.Fatal("explicit grant must be honored")
	}
	if eng.HasExplicitEntitlement("ops", "*") || eng.HasExplicitEntitlement("", snoopRWEntitlement) {
		t.Fatal("empty user or wildcard command must not match")
	}
}
