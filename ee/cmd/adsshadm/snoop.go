//go:build ee

package main

// Threats: snoop attaches an operator to another user's live terminal, so
// every attach names a purpose (support or investigation) and a reason that
// the server records with the attach and detach audit events; the client
// refuses to send without both. View-only is the default; --rw must be asked
// for, and the server decides whether the key may have it (named key,
// admin.snoop.rw entitlement, four-eyes). The server, not this client, decides
// whether the watched user is told. The session is matched by both id and
// user so a reused id cannot land the operator in the wrong terminal. Frames
// are length-prefixed and capped; an oversized or unknown frame ends the
// attach (fail closed). In view mode no keystroke is ever sent; Ctrl-] always
// detaches. Output is the watched terminal's raw bytes, as with any terminal
// multiplexer, so escape sequences from that session reach this terminal.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/attachproto"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// adssh-attach/1 framing comes from internal/attachproto, the package the
// server uses, so the two cannot drift. It imports nothing from adssh and has
// no init. adsshadm must never import internal/sys: that package's init turns
// any binary run with --session-child into a command launcher
// (TestShippedBinaryDoesNotImportInternalSys).
const (
	attachProtocol = attachproto.AttachProtocol
	frameOut       = attachproto.AttachFrameOut    // server -> client: raw terminal output
	frameIn        = attachproto.AttachFrameIn     // client -> server: raw input (rw only)
	frameResize    = attachproto.AttachFrameResize // client -> server: {"cols":N,"rows":N} (rw only)
	frameClose     = attachproto.AttachFrameClose  // either way: {"reason":"..."}
	maxFrame       = attachproto.AttachMaxFrame
	detachKey      = 0x1d // Ctrl-]
	maxReason      = 512
)

var (
	sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	userPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	errNoAttach      = errors.New("this adssh server has no attach endpoint yet; snoop needs the server-side support")
)

type snoopRequest struct {
	SessionID string
	User      string
	RW        bool
	Purpose   string
	Reason    string
}

func (r snoopRequest) mode() string {
	if r.RW {
		return "rw"
	}
	return "view"
}

func parseSnoop(args []string) (snoopRequest, error) {
	var r snoopRequest
	var pos []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--rw":
			r.RW = true
		case "--purpose", "--reason":
			if i+1 >= len(args) {
				return r, fmt.Errorf("%s needs a value", args[i])
			}
			if args[i] == "--purpose" {
				r.Purpose = args[i+1]
			} else {
				r.Reason = args[i+1]
			}
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return r, fmt.Errorf("unknown flag %q", args[i])
			}
			pos = append(pos, args[i])
		}
	}
	if len(pos) != 2 {
		return r, errors.New("usage: snoop <session-id> <user> [--rw] --purpose support|investigation --reason TEXT")
	}
	r.SessionID, r.User = pos[0], pos[1]
	if !sessionIDPattern.MatchString(r.SessionID) {
		return r, fmt.Errorf("invalid session id %q", r.SessionID)
	}
	if !userPattern.MatchString(r.User) {
		return r, fmt.Errorf("invalid user %q", r.User)
	}
	if r.Purpose != "support" && r.Purpose != "investigation" {
		return r, errors.New("--purpose must be support or investigation")
	}
	r.Reason = strings.TrimSpace(r.Reason)
	if r.Reason == "" {
		return r, errors.New("--reason is required; it goes on the audit record")
	}
	if len(r.Reason) > maxReason {
		return r, fmt.Errorf("--reason is longer than %d bytes", maxReason)
	}
	if strings.IndexFunc(r.Reason, unsafeRune) >= 0 {
		return r, errors.New("--reason must not contain control or bidi characters")
	}
	return r, nil
}

func snoopPrompt(_ context.Context, _ *app, args []string) (string, error) {
	req, err := parseSnoop(args)
	if err != nil {
		return "", err
	}
	mode := "view-only"
	if req.RW {
		mode = "READ-WRITE"
	}
	return fmt.Sprintf("attach %s to %s (%s) for %s?", mode, req.SessionID, req.User, req.Purpose), nil
}

func runSnoop(ctx context.Context, a *app, args []string) error {
	req, err := parseSnoop(args)
	if err != nil {
		return err
	}
	return a.snoop(ctx, a, req)
}

func suggestSnoop(ctx context.Context, a *app, argIndex int) []string {
	s, err := fetchSessions(ctx, a)
	if err != nil {
		return nil
	}
	var out []string
	for _, x := range s {
		if x.Terminated {
			continue
		}
		switch argIndex {
		case 0:
			out = append(out, x.ID)
		case 1:
			out = append(out, x.User)
		}
	}
	if argIndex >= 2 {
		return []string{"--rw", "--purpose", "--reason", "support", "investigation"}
	}
	return out
}

// attachPath builds the attach request target.
func attachPath(req snoopRequest) string {
	q := url.Values{}
	q.Set("user", req.User)
	q.Set("mode", req.mode())
	q.Set("purpose", req.Purpose)
	q.Set("reason", req.Reason)
	return "/v1/sessions/" + url.PathEscape(req.SessionID) + "/attach?" + q.Encode()
}

// openAttach performs the upgrade and returns the stream, positioned at the
// first frame. A 404 means the server predates the endpoint.
func (c *client) openAttach(ctx context.Context, req snoopRequest) (net.Conn, *bufio.Reader, error) {
	var d net.Dialer
	var conn net.Conn
	var err error
	if c.ep.socket != "" {
		conn, err = d.DialContext(ctx, "unix", c.ep.socket)
	} else {
		conn, err = d.DialContext(ctx, "tcp", strings.TrimPrefix(c.ep.base, "http://"))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("admin API unreachable: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	hreq, err := http.NewRequest("GET", c.ep.base+attachPath(req), nil)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	hreq.Header.Set("Authorization", "Bearer "+c.key)
	hreq.Header.Set("Connection", "Upgrade")
	hreq.Header.Set("Upgrade", attachProtocol)
	if err := hreq.Write(conn); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("attach: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, hreq)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("attach: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer conn.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		var e struct {
			Error     string `json:"error"`
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(data, &e)
		// The admin router answers an unknown route with exactly "not found";
		// a missing session on a server that has the route says more.
		if resp.StatusCode == http.StatusNotFound && e.Error == "not found" {
			return nil, nil, errNoAttach
		}
		if msg := attachRefusal(req, e.Error, e.RequestID); msg != "" {
			return nil, nil, &apiError{Status: resp.StatusCode, Message: msg}
		}
		return nil, nil, &apiError{Status: resp.StatusCode, Message: e.Error}
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), attachProtocol) {
		conn.Close()
		return nil, nil, fmt.Errorf("attach: server upgraded to %q, want %s", resp.Header.Get("Upgrade"), attachProtocol)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, br, nil
}

// attachRefusal explains the server's attach error codes in plain words.
func attachRefusal(req snoopRequest, code, requestID string) string {
	switch code {
	case "session_not_found":
		return fmt.Sprintf("no live session %s (see sessions)", req.SessionID)
	case "user_mismatch":
		return fmt.Sprintf("session %s does not belong to %s; check the user", req.SessionID, req.User)
	case "attach_forbidden":
		if req.RW {
			return "this key may not attach read-write; it needs a named key with admin.snoop.rw granted to its name (a * entitlement does not count)"
		}
		return "this key may not attach; snoop needs a named admin key"
	case "approval_required":
		approver := "the session owner"
		if req.Purpose == "investigation" {
			approver = "a second admin (never the session owner)"
		}
		return fmt.Sprintf("read-write attach is waiting for four-eyes approval by %s: request %s (they run: adsshadm approve %s), then run snoop again",
			approver, clean(requestID), clean(requestID))
	case "approval_unavailable":
		return "the server could not record the approval request; the attach was refused"
	case "viewer_limit":
		return "this session already has the maximum number of viewers"
	case "no_terminal":
		return "this session has no terminal to drive; attach view-only instead"
	case "bad_mode", "purpose_required", "reason_required":
		return "the server refused the request (" + code + "); this adsshadm may be older than the server"
	}
	return ""
}

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	return attachproto.WriteAttachFrame(w, typ, payload)
}

func readFrame(r io.Reader) (byte, []byte, error) {
	return attachproto.ReadAttachFrame(r)
}

// pump copies frames from the server to out until close, and keystrokes from
// in to the server (rw only). Ctrl-] in in ends the attach in either mode.
// It returns the close reason, if the server sent one.
// stopIn must unblock a pending in.Read; pump calls it and waits for the
// reader to exit before returning, so no keystroke is left to a dead attach.
func pump(conn io.Writer, frames io.Reader, in io.Reader, stopIn func(), out io.Writer, rw bool) (string, error) {
	var wmu sync.Mutex
	send := func(typ byte, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return writeFrame(conn, typ, p)
	}
	detached := make(chan struct{})
	readerDone := make(chan struct{})
	defer func() {
		stopIn()
		<-readerDone
	}()
	go func() {
		defer close(readerDone)
		buf := make([]byte, 4096)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if i := indexByte(chunk, detachKey); i >= 0 {
					if rw && i > 0 {
						_ = send(frameIn, chunk[:i])
					}
					_ = send(frameClose, []byte(`{"reason":"detach"}`))
					close(detached)
					// Unblock the frame loop even if the server never answers.
					if c, ok := conn.(io.Closer); ok {
						_ = c.Close()
					}
					return
				}
				if rw && send(frameIn, chunk) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		typ, payload, err := readFrame(frames)
		if err != nil {
			select {
			case <-detached:
				return "detached", nil
			default:
			}
			if errors.Is(err, io.EOF) {
				return "connection closed", nil
			}
			_ = send(frameClose, []byte(`{"reason":"protocol"}`))
			return "", fmt.Errorf("attach: %w", err)
		}
		switch typ {
		case frameOut:
			if _, err := out.Write(payload); err != nil {
				return "", err
			}
		case frameClose:
			var c struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(payload, &c)
			return dash(clean(c.Reason)), nil
		default:
			_ = send(frameClose, []byte(`{"reason":"protocol"}`))
			return "", fmt.Errorf("attach: unexpected frame type 0x%02x", typ)
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// snoopTerminal is the real attach: raw local terminal, resize forwarding
// in rw mode, and a status line on exit.
func snoopTerminal(ctx context.Context, a *app, req snoopRequest) error {
	raw, br, err := a.c.openAttach(ctx, req)
	if err != nil {
		return err
	}
	conn := &lockedConn{Conn: raw}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	// SIGINT/SIGTERM cancel ctx; closing the stream unblocks pump so every
	// deferred restore below runs and the terminal is left usable.
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		old, err := term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("attach: %w", err)
		}
		defer func() { _ = term.Restore(fd, old) }()
	}
	fmt.Fprintf(os.Stderr, "[adsshadm] attached %s to %s (%s); Ctrl-] detaches\r\n", req.mode(), req.SessionID, req.User)
	if req.RW && term.IsTerminal(fd) {
		sendSize := func() {
			if cols, rows, err := term.GetSize(fd); err == nil {
				p, _ := json.Marshal(map[string]int{"cols": cols, "rows": rows})
				_ = writeFrame(conn, frameResize, p)
			}
		}
		sendSize()
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for {
				select {
				case <-winch:
					sendSize()
				case <-done:
					return
				}
			}
		}()
	}
	in, stopIn, restoreIn, err := cancellableStdin(fd)
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer restoreIn()
	reason, err := pump(conn, br, in, stopIn, os.Stdout, req.RW)
	if ctx.Err() != nil {
		reason, err = "interrupted", nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\r\n[adsshadm] detached from %s: %s\r\n", req.SessionID, clean(reason))
	return nil
}

// lockedConn serializes whole-frame writes from pump and the resize watcher.
type lockedConn struct {
	net.Conn
	mu sync.Mutex
}

func (c *lockedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.Write(p)
}

// cancellableStdin returns a pollable duplicate of stdin whose pending Read
// can be interrupted, so the prompt gets the next keystroke after detach.
// The descriptor is shared with stdin, so restore puts blocking mode back.
func cancellableStdin(fd int) (io.Reader, func(), func(), error) {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	wasNonblock := flags&unix.O_NONBLOCK != 0
	nfd, err := syscall.Dup(fd)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := syscall.SetNonblock(nfd, true); err != nil {
		_ = syscall.Close(nfd)
		return nil, nil, nil, err
	}
	f := os.NewFile(uintptr(nfd), "stdin")
	stop := func() { _ = f.SetReadDeadline(time.Now()) }
	restore := func() {
		_ = syscall.SetNonblock(fd, wasNonblock)
		_ = f.Close()
	}
	return f, stop, restore, nil
}
