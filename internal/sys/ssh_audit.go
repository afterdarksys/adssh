package sys

// Threats: the SSH listener is the front door, so its record of who got in
// and who was turned away has to survive an attacker who controls every
// client-supplied string. Login and session events go to the audit hook (the
// hash chain in adssh) with client-controlled values (login name, client
// version, certificate key id) quoted, so a name containing spaces or "key="
// cannot forge another field. Only fingerprints, serials, and principals are
// recorded: never key material, environment values, or terminal bytes. A
// failed audit write refuses the login or the session (fail closed). Login
// failures are summarized once per connection, only when the client actually
// tried to authenticate (a bare port scan records nothing), and at most
// loginFailBurst per source address per loginFailWindow, so a scanner cannot
// flood the chain; suppressed failures are counted into the next record and
// always reach the operational log. The operational log (slog) is separate
// from the audit chain and carries the same fields at info and debug.

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHAudit records one listener event in the audit chain. adssh wires it to
// the security engine's LogEvent. Nil records nothing.
type SSHAudit func(event string) error

var (
	sshAuditMu sync.RWMutex
	sshAudit   SSHAudit
)

func setSSHAudit(a SSHAudit) {
	sshAuditMu.Lock()
	sshAudit = a
	sshAuditMu.Unlock()
}

func auditSSH(event string) error {
	sshAuditMu.RLock()
	a := sshAudit
	sshAuditMu.RUnlock()
	if a == nil {
		return nil
	}
	return a(event)
}

// Permission extensions adssh sets in the auth callback for the audit record.
// A certificate's own extensions land in the same map, so these are always
// overwritten or deleted, never trusted from the certificate.
const (
	extPubkeyFP   = "pubkey-fp"
	extAuthMethod = "adssh-auth-method"
	extCertKeyFP  = "adssh-cert-key-fp"
	extCertCAFP   = "adssh-cert-ca-fp"
	extCertSerial = "adssh-cert-serial"
	extCertKeyID  = "adssh-cert-key-id"
)

// q quotes a client-controlled value for a key=value record and caps it.
func q(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	return strconv.Quote(s)
}

// authRecord gathers one connection's authentication attempts.
type authRecord struct {
	mu       sync.Mutex
	user     string
	attempts int
	reasons  []string
	keyFPs   []string
}

var authRecords sync.Map // remote address string -> *authRecord

func beginAuthRecord(peer string) *authRecord {
	r := &authRecord{}
	authRecords.Store(peer, r)
	return r
}

func endAuthRecord(peer string) { authRecords.Delete(peer) }

// authLogCallback is ssh.ServerConfig.AuthLogCallback: one call per attempt.
func authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	peer := conn.RemoteAddr().String()
	result := "accepted"
	reason := ""
	if err != nil {
		result = "refused"
		reason = err.Error()
	}
	slog.Debug("ssh auth attempt", "addr", peer, "user", conn.User(), "method", method, "result", result, "reason", reason)
	if method == "none" || err == nil {
		return // "none" is the client asking which methods exist
	}
	if v, ok := authRecords.Load(peer); ok {
		r := v.(*authRecord)
		r.mu.Lock()
		r.user = conn.User()
		r.attempts++
		if len(r.reasons) < 8 {
			r.reasons = append(r.reasons, reason)
		}
		r.mu.Unlock()
	}
}

// noteAuthKey remembers a refused key's fingerprint for the failure record.
func noteAuthKey(peer, fp string) {
	if v, ok := authRecords.Load(peer); ok {
		r := v.(*authRecord)
		r.mu.Lock()
		if len(r.keyFPs) < 8 && !containsString(r.keyFPs, fp) {
			r.keyFPs = append(r.keyFPs, fp)
		}
		r.mu.Unlock()
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

const (
	loginFailWindow  = time.Minute
	loginFailBurst   = 5
	loginFailSources = 4096
)

type failWindow struct {
	start      time.Time
	count      int
	suppressed int
}

var (
	loginFailMu  sync.Mutex
	loginFailSrc = map[string]*failWindow{}
	loginFailNow = time.Now
)

// allowLoginFailRecord reports whether a failure from host may be written to
// the chain now, and how many earlier ones were suppressed.
func allowLoginFailRecord(host string) (bool, int) {
	loginFailMu.Lock()
	defer loginFailMu.Unlock()
	now := loginFailNow()
	w := loginFailSrc[host]
	if w == nil || now.Sub(w.start) >= loginFailWindow {
		suppressed := 0
		if w != nil {
			suppressed = w.suppressed
		}
		if w == nil && len(loginFailSrc) >= loginFailSources {
			loginFailSrc = map[string]*failWindow{} // bounded memory under a wide scan
		}
		loginFailSrc[host] = &failWindow{start: now, count: 1}
		return true, suppressed
	}
	if w.count < loginFailBurst {
		w.count++
		return true, 0
	}
	w.suppressed++
	return false, 0
}

func hostOf(peer string) string {
	if h, _, err := net.SplitHostPort(peer); err == nil {
		return h
	}
	return peer
}

// recordLoginFailure summarizes a connection whose handshake failed.
func recordLoginFailure(peer string, rec *authRecord, handshakeErr error) {
	rec.mu.Lock()
	user, attempts := rec.user, rec.attempts
	reasons := append([]string(nil), rec.reasons...)
	fps := append([]string(nil), rec.keyFPs...)
	rec.mu.Unlock()
	slog.Info("ssh login failed", "addr", peer, "user", user, "attempts", attempts,
		"keys", strings.Join(fps, ","), "reasons", strings.Join(reasons, "; "), "error", handshakeErr)
	if attempts == 0 {
		return // never tried to authenticate: a probe, not a login
	}
	ok, suppressed := allowLoginFailRecord(hostOf(peer))
	if !ok {
		slog.Debug("ssh login failure not written to the audit chain (rate limit)", "addr", peer)
		return
	}
	event := fmt.Sprintf("SSH_LOGIN_FAIL addr=%s user=%s attempts=%d keys=%s", peer, q(user), attempts, q(strings.Join(fps, ",")))
	if suppressed > 0 {
		event += fmt.Sprintf(" suppressed_before=%d", suppressed)
	}
	if err := auditSSH(event); err != nil {
		slog.Error("ssh audit write failed", "event", "SSH_LOGIN_FAIL", "addr", peer, "error", err)
	}
}

// loginOKEvent builds the SSH_LOGIN_OK record for an authenticated connection.
func loginOKEvent(conn *ssh.ServerConn) string {
	ext := conn.Permissions.Extensions
	event := fmt.Sprintf("SSH_LOGIN_OK addr=%s user=%s client=%s method=%s key_fp=%s",
		conn.RemoteAddr(), q(conn.User()), q(string(conn.ClientVersion())), ext[extAuthMethod], ext[extPubkeyFP])
	if ext[extAuthMethod] == "cert" {
		event += fmt.Sprintf(" cert_key_fp=%s ca_fp=%s serial=%s key_id=%s principals=%s",
			ext[extCertKeyFP], ext[extCertCAFP], ext[extCertSerial], q(ext[extCertKeyID]), q(ext[principalsExtension]))
	}
	return event
}

// sessionEndReason maps a starter result to an exit status and a reason.
func sessionEndReason(err error) (int, string) {
	if err == nil {
		return 0, "exit"
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return code, "exit"
		}
		return -1, "signal"
	}
	return -1, "error"
}
