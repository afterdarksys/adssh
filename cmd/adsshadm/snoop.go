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
	"encoding/binary"
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
	"unicode"

	"golang.org/x/term"
)

// adssh-attach/1 framing: 4-byte big-endian payload length, 1 type byte,
// payload. Same shape as the monitor socket. The type values below are the
// client half of the contract agreed for the server's attach endpoint.
const (
	attachProtocol = "adssh-attach/1"
	frameOut       = byte(0x10) // server -> client: raw terminal output
	frameIn        = byte(0x11) // client -> server: raw input (rw only)
	frameResize    = byte(0x12) // client -> server: {"cols":N,"rows":N} (rw only)
	frameClose     = byte(0x13) // either way: {"reason":"..."}
	maxFrame       = 1 << 20
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
	for _, c := range r.Reason {
		if unicode.IsControl(c) {
			return r, errors.New("--reason must not contain control characters")
		}
	}
	return r, nil
}

func runSnoop(ctx context.Context, a *app, args []string) error {
	req, err := parseSnoop(args)
	if err != nil {
		return err
	}
	mode := "view-only"
	if req.RW {
		mode = "READ-WRITE"
	}
	if err := a.confirmWrite(fmt.Sprintf("attach %s to %s (%s) for %s?", mode, req.SessionID, req.User, req.Purpose)); err != nil {
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
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		// The admin router answers an unknown route with exactly "not found";
		// a missing session on a server that has the route says more.
		if resp.StatusCode == http.StatusNotFound && e.Error == "not found" {
			return nil, nil, errNoAttach
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

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > maxFrame {
		return errors.New("attach: frame too large")
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	buf[4] = typ
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n > maxFrame {
		return 0, nil, errors.New("attach: frame too large")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[4], payload, nil
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
			return "", err
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
			return dash(c.Reason), nil
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
	conn, br, err := a.c.openAttach(ctx, req)
	if err != nil {
		return err
	}
	defer conn.Close()
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
			for range winch {
				sendSize()
			}
		}()
	}
	in, stopIn, restoreIn, err := cancellableStdin(fd)
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer restoreIn()
	reason, err := pump(conn, br, in, stopIn, os.Stdout, req.RW)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\r\n[adsshadm] detached from %s: %s\r\n", req.SessionID, reason)
	return nil
}

// cancellableStdin returns a pollable duplicate of stdin whose pending Read
// can be interrupted, so the prompt gets the next keystroke after detach.
// The descriptor is shared with stdin, so restore puts blocking mode back.
func cancellableStdin(fd int) (io.Reader, func(), func(), error) {
	nfd, err := syscall.Dup(fd)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := syscall.SetNonblock(nfd, true); err != nil {
		syscall.Close(nfd)
		return nil, nil, nil, err
	}
	f := os.NewFile(uintptr(nfd), "stdin")
	stop := func() { _ = f.SetReadDeadline(time.Now()) }
	restore := func() {
		_ = syscall.SetNonblock(fd, false)
		_ = f.Close()
	}
	return f, stop, restore, nil
}
