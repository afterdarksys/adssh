//go:build ee

package security

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/afterdarksys/adssh/internal/attachproto"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/creack/pty"
)

// Threats: GET /v1/sessions/{id}/attach puts an admin on another user's live
// terminal. The read-only legacy key never attaches; view needs a named key;
// rw also needs the admin.snoop.rw entitlement for the key name and a
// four-eyes approval that is answered asynchronously (428 until approved, so
// no HTTP request is held open). A support attach is approved by the session
// owner; an investigation attach is approved by a second named admin key
// over HTTP and never by the owner or the requesting key. rw is refused for a
// session whose user was renamed without verification (asserted or
// device-login), and only one rw controller may hold a session. Every attach
// passes the snoop policy gate and is written to the audit chain before the
// 101 is sent; a failed write refuses the attach. The detach is audited
// too. Keystrokes are never written to the chain: commands the session runs
// during an rw attach are audited with via=<key>, and the session recording
// sees the terminal's echo as for any typing. The session owner is told of
// every attach unless the operator lets policy silence it
// (ADSSH_SNOOP_NOTIFY_LOCK). The stream is bounded: frames are capped, a
// stalled client is cut by a per-frame write deadline and a bounded output
// queue (the session's own output is never blocked), an idle attach closes
// after 10 minutes, and the attach closes when the session ends. This does
// not stop a named key holder who holds the entitlement and an approval from
// typing anything the session user could type, and it does not protect a
// key that leaks from its holder.

const (
	attachMaxViewers   = 8
	attachMaxReason    = 512
	attachWriteTimeout = 10 * time.Second
	attachOutQueue     = 256
	snoopRWEntitlement = "admin.snoop.rw"
	snoopDefaultTTL    = 300
	attachMaxPTYDim    = 1000

	snoopNotifyLockEnv = "ADSSH_SNOOP_NOTIFY_LOCK"
	snoopNotifyEnv     = "ADSSH_SNOOP_NOTIFY"
)

var attachIdleNanos atomic.Int64

func init() {
	attachIdleNanos.Store(int64(10 * time.Minute))
	sys.OnSessionUnregister(endSessionAttaches)
}

func attachIdleTimeout() time.Duration { return time.Duration(attachIdleNanos.Load()) }

// setAttachIdleTimeout replaces the idle timeout. Tests only.
func setAttachIdleTimeout(d time.Duration) (restore func()) {
	prev := attachIdleNanos.Swap(int64(d))
	return func() { attachIdleNanos.Store(prev) }
}

// attachEntry is one live attach. end records the first close reason and
// stops the stream.
type attachEntry struct {
	key    string
	rw     bool
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	reason string
}

func (a *attachEntry) end(reason string) {
	a.once.Do(func() {
		a.reason = reason
		a.cancel()
	})
}

type snoopApproval struct {
	sessionID   string
	requestID   string
	pendingFile string
	deadline    time.Time
}

var (
	attachMu sync.Mutex
	// attachSessions maps a session ID to its live attaches.
	attachSessions = map[string]map[*attachEntry]struct{}{}
	// snoopApprovals maps key, session, and purpose to the open rw request.
	snoopApprovals = map[string]*snoopApproval{}
)

// endSessionAttaches closes every attach on a session that unregistered and
// drops its open rw requests.
func endSessionAttaches(sessionID string) {
	attachMu.Lock()
	entries := make([]*attachEntry, 0, len(attachSessions[sessionID]))
	for a := range attachSessions[sessionID] {
		entries = append(entries, a)
	}
	for k, ap := range snoopApprovals {
		if ap.sessionID == sessionID {
			delete(snoopApprovals, k)
			_ = os.Remove(ap.pendingFile) // best-effort: the request expires with its TTL anyway
		}
	}
	attachMu.Unlock()
	for _, a := range entries {
		a.end("session_ended")
	}
}

// attachSessionID returns the session ID of an attach request target.
func attachSessionID(r *http.Request) (string, bool) {
	if r.Method != http.MethodGet {
		return "", false
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/sessions/")
	if !ok {
		return "", false
	}
	id, ok := strings.CutSuffix(rest, "/attach")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// validSnoopReason accepts 1..512 bytes of UTF-8 without control or bidi
// characters, so the reason cannot rewrite an audit line or a terminal.
func validSnoopReason(reason string) bool {
	if reason == "" || len(reason) > attachMaxReason || !utf8.ValidString(reason) {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return false
		}
	}
	return true
}

func (h *adminHTTPHandler) logAdminHTTP(r *http.Request, status int, principal string) error {
	return h.engine.LogEvent(fmt.Sprintf("ADMIN_HTTP method=%s path=%s status=%d key_fp=%s principal=%s",
		r.Method, r.URL.Path, status, presentedKeyFingerprint(r), principal))
}

// serveAttach answers an authenticated attach request. Refusals are audited
// as ADMIN_HTTP before they are sent; a failed write answers 503.
func (h *adminHTTPHandler) serveAttach(w http.ResponseWriter, r *http.Request, principal adminPrincipal, sessionID string) {
	refuse := func(status int, body map[string]any) {
		if err := h.logAdminHTTP(r, status, principal.Name); err != nil {
			writeAdminJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "audit_unavailable"})
			return
		}
		writeAdminJSON(w, status, body)
	}
	fail := func(status int, code string) { refuse(status, map[string]any{"error": code}) }

	if !headerHasToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), attachproto.AttachProtocol) {
		fail(http.StatusBadRequest, "bad_upgrade")
		return
	}
	q := r.URL.Query()
	mode := q.Get("mode")
	if mode != "view" && mode != "rw" {
		fail(http.StatusBadRequest, "bad_mode")
		return
	}
	purpose := q.Get("purpose")
	if purpose != "support" && purpose != "investigation" {
		fail(http.StatusBadRequest, "purpose_required")
		return
	}
	reason := strings.TrimSpace(q.Get("reason"))
	if !validSnoopReason(reason) {
		fail(http.StatusBadRequest, "reason_required")
		return
	}
	if !principal.Named || principal.Name == "" {
		fail(http.StatusForbidden, "attach_forbidden")
		return
	}
	session := sys.GetSession(sessionID)
	if session == nil || session.Info().Terminated {
		fail(http.StatusNotFound, "session_not_found")
		return
	}
	user := q.Get("user")
	owner := session.Info().User
	if user == "" || owner != user {
		fail(http.StatusConflict, "user_mismatch")
		return
	}
	rw := mode == "rw"
	if rw {
		switch session.IdentitySource() {
		case "", sys.IdentitySourceOIDCVerified:
		default:
			fail(http.StatusForbidden, "attach_forbidden")
			return
		}
		if !h.engine.HasExplicitEntitlement(principal.Name, snoopRWEntitlement) {
			fail(http.StatusForbidden, "attach_forbidden")
			return
		}
	}
	if err := mirrorStreamable(session, rw, strings.NewReader("")); err != nil {
		fail(http.StatusConflict, "no_terminal")
		return
	}
	notify, allowed, err := h.engine.snoopGate(principal.Name, purpose, mode, user, sessionID)
	if err != nil {
		writeAdminJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "audit_unavailable"})
		return
	}
	if !allowed {
		fail(http.StatusForbidden, "attach_forbidden")
		return
	}
	if code := attachCapacity(session, rw); code != "" {
		fail(http.StatusConflict, code)
		return
	}
	if rw {
		state, requestID, err := h.engine.snoopApprovalState(principal.Name, session, owner, purpose)
		if err != nil {
			if errors.Is(err, errSnoopAudit) {
				writeAdminJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "audit_unavailable"})
				return
			}
			fail(http.StatusInternalServerError, "approval_unavailable")
			return
		}
		switch state {
		case snoopPending:
			refuse(http.StatusPreconditionRequired, map[string]any{"error": "approval_required", "request_id": requestID})
			return
		case snoopDenied:
			fail(http.StatusForbidden, "attach_forbidden")
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	entry := &attachEntry{key: principal.Name, rw: rw, ctx: ctx, cancel: cancel}
	if code := reserveAttach(session, entry); code != "" {
		cancel()
		status := http.StatusConflict
		if code == "session_not_found" {
			status = http.StatusNotFound
		}
		fail(status, code)
		return
	}
	if rw {
		h.engine.consumeSnoopApproval(principal.Name, sessionID, purpose)
	}
	fields := fmt.Sprintf("key=%s mode=%s purpose=%s reason=%q session=%s user=%s notify=%t",
		principal.Name, mode, purpose, reason, sessionID, user, notify)
	detach := func(closeReason string) {
		releaseAttach(session, entry)
		if notify {
			fmt.Fprintf(session.Out, "\r\n[adssh] %s has detached\r\n", principal.Name)
		}
		if err := h.engine.LogEvent(fmt.Sprintf("MIRROR_DETACH %s close=%s", fields, closeReason)); err != nil {
			warnUnrecordedRevocation("MIRROR_DETACH", err)
		}
	}
	// Log before attach; a failed write refuses it.
	if err := h.engine.LogEvent("MIRROR_ATTACH " + fields); err != nil {
		entry.end("audit_unavailable")
		releaseAttach(session, entry)
		writeAdminJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "audit_unavailable"})
		return
	}
	if err := h.logAdminHTTP(r, http.StatusSwitchingProtocols, principal.Name); err != nil {
		entry.end("audit_unavailable")
		detach("audit_unavailable")
		writeAdminJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "audit_unavailable"})
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		entry.end("no_hijack")
		detach("no_hijack")
		writeAdminJSON(w, http.StatusInternalServerError, map[string]any{"error": "attach_unavailable"})
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		entry.end("no_hijack")
		detach("no_hijack")
		return
	}
	// The admin server's read and write timeouts do not apply to the stream.
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(attachWriteTimeout))
	_, err = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " +
		attachproto.AttachProtocol + "\r\n\r\n")
	if err == nil {
		err = brw.Flush()
	}
	if err != nil {
		_ = conn.Close()
		entry.end("write_failed")
		detach("write_failed")
		return
	}
	if notify {
		verb := "viewing"
		if rw {
			verb = "controlling"
		}
		fmt.Fprintf(session.Out, "\r\n[adssh] %s is %s this session\r\n", principal.Name, verb)
	}
	runAttach(session, entry, conn, brw.Reader)
	detach(entry.reason)
}

// attachCapacity reports why another attach of this kind is refused, or "".
func attachCapacity(session *sys.Session, rw bool) string {
	attachMu.Lock()
	defer attachMu.Unlock()
	if rw {
		if session.Controller() != "" {
			return "controller_present"
		}
		return ""
	}
	views := 0
	for a := range attachSessions[session.ID] {
		if !a.rw {
			views++
		}
	}
	if views >= attachMaxViewers {
		return "viewer_limit"
	}
	return ""
}

// reserveAttach registers a, claiming the controller for rw. The session
// must still be registered, so the unregister hook cannot miss a.
func reserveAttach(session *sys.Session, a *attachEntry) string {
	attachMu.Lock()
	defer attachMu.Unlock()
	if sys.GetSession(session.ID) != session {
		return "session_not_found"
	}
	entries := attachSessions[session.ID]
	if a.rw {
		if !session.ClaimController(a.key) {
			return "controller_present"
		}
	} else {
		views := 0
		for e := range entries {
			if !e.rw {
				views++
			}
		}
		if views >= attachMaxViewers {
			return "viewer_limit"
		}
	}
	if entries == nil {
		entries = map[*attachEntry]struct{}{}
		attachSessions[session.ID] = entries
	}
	entries[a] = struct{}{}
	return ""
}

func releaseAttach(session *sys.Session, a *attachEntry) {
	attachMu.Lock()
	defer attachMu.Unlock()
	if a.rw {
		session.ReleaseController(a.key)
	}
	if entries := attachSessions[session.ID]; entries != nil {
		delete(entries, a)
		if len(entries) == 0 {
			delete(attachSessions, session.ID)
		}
	}
}

// snoopGate runs the policy gate for command snoop with args
// [purpose, mode, user] and input.snoop, and resolves the notice.
func (e *Engine) snoopGate(key, purpose, mode, user, sessionID string) (notify, allowed bool, err error) {
	args := []string{purpose, mode, user}
	pctx := PolicyContext{
		User:    key,
		Command: "snoop",
		Args:    args,
		Time:    time.Now().UTC().Format(time.RFC3339),
		Snoop:   &SnoopClaim{Purpose: purpose, Mode: mode, User: user, Session: sessionID},
	}
	decision, perr := e.EvaluatePolicyDecision(pctx)
	if perr != nil {
		decision.Allowed = false
		if decision.DenyReason == "" {
			decision.DenyReason = perr.Error()
		}
	}
	if err := e.LogPolicyDecisionDetail(key, "snoop "+strings.Join(args, " "), decision); err != nil {
		return false, false, err
	}
	if !decision.Allowed {
		return false, false, nil
	}
	return resolveSnoopNotify(os.Getenv(snoopNotifyLockEnv), os.Getenv(snoopNotifyEnv), purpose, decision.Notify), true, nil
}

// resolveSnoopNotify decides whether the session owner sees the notice. The
// operator lock forces it; otherwise a policy notify answer decides;
// otherwise an investigation is shown and support follows the operator
// default (on unless "off"). A lock value other than empty/off/0/false is on.
func resolveSnoopNotify(lock, def, purpose string, policy *bool) bool {
	switch strings.ToLower(strings.TrimSpace(lock)) {
	case "", "off", "0", "false":
	default:
		return true
	}
	if policy != nil {
		return *policy
	}
	if purpose == "investigation" {
		return true
	}
	return strings.ToLower(strings.TrimSpace(def)) != "off"
}

const (
	snoopPending = iota
	snoopApproved
	snoopDenied
)

var errSnoopAudit = errors.New("snoop: audit write failed")

func snoopApprovalKey(key, sessionID, purpose string) string {
	return key + "\x00" + sessionID + "\x00" + purpose
}

// snoopApprovalState reports the rw request for key on session, opening one
// when none is live. It never waits for the decision.
func (e *Engine) snoopApprovalState(key string, session *sys.Session, owner, purpose string) (int, string, error) {
	k := snoopApprovalKey(key, session.ID, purpose)
	attachMu.Lock()
	defer attachMu.Unlock()
	if a := snoopApprovals[k]; a != nil {
		now := time.Now()
		if _, err := os.Stat(filepath.Join(e.fourEyesApprovedDir(), a.requestID)); err == nil && now.Before(a.deadline) {
			return snoopApproved, a.requestID, nil
		}
		if _, err := os.Stat(filepath.Join(e.fourEyesDeniedDir(), a.requestID)); err == nil {
			delete(snoopApprovals, k)
			return snoopDenied, a.requestID, nil
		}
		if now.Before(a.deadline) {
			return snoopPending, a.requestID, nil
		}
		delete(snoopApprovals, k)
		_ = os.Remove(a.pendingFile)                                       // best-effort: an expired request
		_ = os.Remove(filepath.Join(e.fourEyesApprovedDir(), a.requestID)) // best-effort: a late approval is void
	}
	if err := e.ensureFourEyesDirs(); err != nil {
		return 0, "", err
	}
	cmd := fmt.Sprintf("snoop rw %s %s %s", purpose, session.ID, owner)
	rule := FourEyesRule{Pattern: "snoop rw *"}
	// An unreadable rules file refuses the request rather than dropping a
	// configured Approver restriction.
	matched, ok, err := e.matchFourEyes(cmd)
	if err != nil {
		return 0, "", fmt.Errorf("foureyes: %v; refusing the request", err)
	}
	if ok {
		rule = *matched
	}
	if rule.TTL <= 0 {
		rule.TTL = snoopDefaultTTL
	}
	switch purpose {
	case "support":
		if rule.Approver == "" {
			rule.Approver = owner
		}
	case "investigation":
		rule.NotApprover = owner
		rule.Surface = FourEyesSurfaceHTTP
	}
	pending, pendingFile, err := e.createFourEyesPendingAs(cmd, rule, key)
	if err != nil {
		return 0, "", err
	}
	if err := e.LogEvent(fmt.Sprintf("SNOOP_APPROVAL_REQUESTED key=%s session=%s user=%s purpose=%s request=%s",
		key, session.ID, owner, purpose, pending.RequestID)); err != nil {
		_ = os.Remove(pendingFile) // best-effort: the unaudited request is withdrawn
		return 0, "", fmt.Errorf("%w: %v", errSnoopAudit, err)
	}
	snoopApprovals[k] = &snoopApproval{
		sessionID:   session.ID,
		requestID:   pending.RequestID,
		pendingFile: pendingFile,
		deadline:    time.Now().Add(time.Duration(rule.TTL) * time.Second),
	}
	if purpose == "support" {
		w := session.PromptWriter()
		if w == nil {
			w = session.Out
		}
		fmt.Fprintf(w, "\r\n[adssh] %s asks to control this session (support). Approve: 4eyes approve %s\r\n",
			key, pending.RequestID)
	}
	return snoopPending, pending.RequestID, nil
}

// consumeSnoopApproval makes an approval single use.
func (e *Engine) consumeSnoopApproval(key, sessionID, purpose string) {
	k := snoopApprovalKey(key, sessionID, purpose)
	attachMu.Lock()
	a := snoopApprovals[k]
	delete(snoopApprovals, k)
	attachMu.Unlock()
	if a != nil {
		_ = os.Remove(filepath.Join(e.fourEyesApprovedDir(), a.requestID)) // best-effort: the map entry is already gone
	}
}

// attachOut is the session-output listener for one attach. It never blocks
// the broadcaster: when the queue is full the attach ends.
type attachOut struct {
	ch   chan []byte
	full chan struct{}
	once sync.Once
}

func (o *attachOut) Write(p []byte) (int, error) {
	select {
	case o.ch <- append([]byte(nil), p...):
	default:
		o.once.Do(func() { close(o.full) })
	}
	return len(p), nil
}

func writeAttachOut(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n := min(len(b), attachproto.AttachMaxFrame)
		_ = conn.SetWriteDeadline(time.Now().Add(attachWriteTimeout))
		if err := attachproto.WriteAttachFrame(conn, attachproto.AttachFrameOut, b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// applyAttachResize decodes {"cols":N,"rows":N} and sizes the terminal. A
// malformed payload is refused; a terminal that cannot be sized is ignored.
func applyAttachResize(session *sys.Session, payload []byte) bool {
	var size struct {
		Cols int `json:"cols"`
		Rows int `json:"rows"`
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&size); err != nil || dec.More() {
		return false
	}
	if size.Cols < 1 || size.Rows < 1 || size.Cols > attachMaxPTYDim || size.Rows > attachMaxPTYDim {
		return false
	}
	_ = sys.SetPTYSize(session.PTYMaster, &pty.Winsize{Cols: uint16(size.Cols), Rows: uint16(size.Rows)}) // best-effort: not every terminal can be sized
	return true
}

// runAttach streams session output to conn as Out frames and, for rw, In
// frames to the terminal, until a.end is called. It then sends Close with the
// reason and closes conn.
func runAttach(session *sys.Session, a *attachEntry, conn net.Conn, br *bufio.Reader) {
	out := &attachOut{ch: make(chan []byte, attachOutQueue), full: make(chan struct{})}
	activity := make(chan struct{}, 1)
	touch := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	inR, inW := io.Pipe()
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer inW.Close()
		for {
			typ, payload, err := attachproto.ReadAttachFrame(br)
			if err != nil {
				if errors.Is(err, io.EOF) {
					a.end("client_closed")
				} else {
					a.end("protocol")
				}
				return
			}
			touch()
			switch typ {
			case attachproto.AttachFrameClose:
				a.end("detach")
				return
			case attachproto.AttachFrameIn:
				if !a.rw {
					a.end("view_only")
					return
				}
				if _, err := inW.Write(payload); err != nil {
					a.end("input_closed")
					return
				}
			case attachproto.AttachFrameResize:
				if !a.rw {
					a.end("view_only")
					return
				}
				if !applyAttachResize(session, payload) {
					a.end("protocol")
					return
				}
			default:
				a.end("protocol")
				return
			}
		}
	}()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		idle := time.NewTimer(attachIdleTimeout())
		defer idle.Stop()
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-out.full:
				a.end("slow_client")
				return
			case <-idle.C:
				a.end("idle")
				return
			case <-activity:
				idle.Reset(attachIdleTimeout())
			case b := <-out.ch:
				if err := writeAttachOut(conn, b); err != nil {
					a.end("write_failed")
					return
				}
				idle.Reset(attachIdleTimeout())
			}
		}
	}()
	mirrorStream(a.ctx, session, a.rw, out, inR)
	<-writerDone
	_ = inR.Close() // unblocks a reader waiting on the terminal
	payload, err := json.Marshal(map[string]string{"reason": a.reason})
	if err == nil {
		_ = conn.SetWriteDeadline(time.Now().Add(attachWriteTimeout))
		_ = attachproto.WriteAttachFrame(conn, attachproto.AttachFrameClose, payload) // best-effort: the client may be gone
	}
	_ = conn.Close()
	<-readerDone
}
