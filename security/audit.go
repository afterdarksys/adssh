package security

// Threats: a crash between a command and the next fsync drops that audit line,
// and a shared host that ignores the write error runs the command anyway.
// The flat log and the HMAC chain are the authoritative record. A failed write
// or Sync refuses the command. Syslog and the remote POST run only after both
// durable writes succeed, and a failed remote POST does not authorize anything.
// An unconfigured audit file (nil) is not a failure. This does not cover a
// disk that reports Sync success and then loses the sector.
// The remote POST carries ADSSH_AUDIT_TOKEN as a bearer. When the engine is
// built, ADSSH_AUDIT_URL is checked for syntax only (https, a host, no
// userinfo or fragment, not a blocked name or literal blocked IP), with no
// network call, so DNS that is down or slow cannot stop adssh from starting.
// At POST time the host is resolved with a bound of auditResolveTimeout; an
// unresolved host, or an answer holding a private, metadata, link-local, or
// loopback address, fails that one POST closed before a connection is opened,
// and the bearer is never sent. The checked address is the one dialed, and
// callbackDialContext checks it again at connect time. Failures go to stderr
// at most once per auditWarnInterval, naming only the host. The POST uses TLS
// 1.3 and refuses redirects. This does not authenticate the SIEM beyond its
// certificate, and dropped POSTs are not retried (the flat log and the chain
// stay the record).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// syncFile is the durability hook for the flat log and the hash chain.
// Tests replace it to force a Sync failure without depending on the OS.
var syncFile = func(f *os.File) error { return f.Sync() }

// parseSyslogFacility maps an ADSSH_SYSLOG env var value to a syslog priority facility.
func parseSyslogFacility(s string) syslog.Priority {
	switch strings.ToLower(s) {
	case "1", "auth":
		return syslog.LOG_AUTH
	case "daemon":
		return syslog.LOG_DAEMON
	case "local0":
		return syslog.LOG_LOCAL0
	case "local1":
		return syslog.LOG_LOCAL1
	case "local2":
		return syslog.LOG_LOCAL2
	case "local3":
		return syslog.LOG_LOCAL3
	case "local4":
		return syslog.LOG_LOCAL4
	case "local5":
		return syslog.LOG_LOCAL5
	case "local6":
		return syslog.LOG_LOCAL6
	case "local7":
		return syslog.LOG_LOCAL7
	default:
		return syslog.LOG_AUTH
	}
}

// InitAuditLog opens the flat audit log and records the optional remote sink.
// A directory or file that cannot be created is an error. Syslog stays a
// secondary sink: a failed open is noted on stderr and does not fail init.
func (e *Engine) InitAuditLog(path, url, token string) error {
	if syslogEnv := os.Getenv("ADSSH_SYSLOG"); syslogEnv != "" {
		facility := parseSyslogFacility(syslogEnv)
		w, err := syslog.New(facility|syslog.LOG_INFO, "adssh")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open syslog writer: %v\n", err)
		} else {
			e.syslogWriter = w
		}
	}

	if url != "" {
		parsed, err := validateCallbackURLSyntax(url)
		if errors.Is(err, errPrivateHost) {
			return fmt.Errorf("audit webhook URL rejected: %w", auditPrivateHostError(parsed, url))
		}
		if err != nil || parsed.Scheme != "https" || strings.Contains(url, "#") {
			return fmt.Errorf("audit webhook URL rejected: ADSSH_AUDIT_URL must be an https URL with a host and no userinfo or fragment, and must not name localhost, a metadata service, or a link-local address")
		}
		url = parsed.String()
	}
	e.remoteAuditURL = url
	e.remoteAuditToken = token

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}
	logFile, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to initialize audit logger at %s: %w", path, err)
	}
	e.auditMu.Lock()
	e.auditFile = logFile
	e.auditMu.Unlock()
	return nil
}

// SetAuditSession sets the chain session ID. Call this after InitChain if the session
// ID is known separately (e.g. for SSH sessions generated after startup).
func (e *Engine) SetAuditSession(id string) {
	e.chainMu.Lock()
	e.chainSession = id
	e.chainMu.Unlock()
}

// SetAuditChangeID stores a CM ticket ID that is embedded in every subsequent chain entry.
func (e *Engine) SetAuditChangeID(id string) {
	e.chainMu.Lock()
	e.auditChangeID = id
	e.chainMu.Unlock()
}

// GetAuditChangeID returns the current CM ticket ID.
func (e *Engine) GetAuditChangeID() string {
	e.chainMu.Lock()
	defer e.chainMu.Unlock()
	return e.auditChangeID
}

// isSyslogWarning returns true if the event string contains keywords that indicate
// a warning or error severity.
func isSyslogWarning(event string) bool {
	lower := strings.ToLower(event)
	return strings.Contains(lower, "error") ||
		strings.Contains(lower, "fail") ||
		strings.Contains(lower, "deny") ||
		strings.Contains(lower, "restrict")
}

// writeAuditLine appends one flat-log line and Syncs it. A nil file means the
// audit log is not configured. The layout matches the previous logger:
// "AUDIT: 2006/01/02 15:04:05 " plus the message, local time, one trailing newline.
func (e *Engine) writeAuditLine(message string) error {
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	if e.auditFile == nil {
		return nil
	}
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	stamp := time.Now().Format("2006/01/02 15:04:05")
	line := "AUDIT: " + stamp + " " + message
	if _, err := e.auditFile.WriteString(line); err != nil {
		return err
	}
	return syncFile(e.auditFile)
}

func (e *Engine) dispatchAuditEvent(payload map[string]interface{}) {
	if e.remoteAuditURL == "" {
		return
	}
	payload["time"] = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh: audit webhook marshal failed: %v\n", err)
		return
	}

	target := e.remoteAuditURL
	token := e.remoteAuditToken
	go func() {
		if err := postAuditEvent(context.Background(), target, token, data); err != nil {
			host := ""
			if parsed, perr := neturl.Parse(target); perr == nil {
				host = parsed.Hostname()
			}
			auditWarn(host, err)
		}
	}()
}

// auditResolveTimeout bounds the DNS lookup for the audit host at POST time.
var auditResolveTimeout = 5 * time.Second

// auditWarnInterval is the minimum gap between two stderr warnings about a
// failed audit POST, so a down SIEM does not flood the terminal.
const auditWarnInterval = time.Minute

var (
	auditWarnWriter io.Writer = os.Stderr
	auditWarnLast   atomic.Int64
)

// auditWarn writes one line naming the host and the cause, at most once per
// auditWarnInterval. It never prints the URL path, query, or bearer.
func auditWarn(host string, err error) {
	now := time.Now().UnixNano()
	last := auditWarnLast.Load()
	if last != 0 && now-last < int64(auditWarnInterval) {
		return
	}
	if !auditWarnLast.CompareAndSwap(last, now) {
		return
	}
	var uerr *neturl.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	fmt.Fprintf(auditWarnWriter, "adssh: audit webhook POST to %s failed: %v\n", host, err)
}

func auditPrivateHostError(parsed *neturl.URL, raw string) error {
	host := ""
	if parsed != nil {
		host = parsed.Hostname()
	} else if p, err := neturl.Parse(raw); err == nil {
		host = p.Hostname()
	}
	return fmt.Errorf("ADSSH_AUDIT_URL: host %s resolves to a private address; set ADSSH_CALLBACK_ALLOW_PRIVATE=1 to allow it", host)
}

// auditResolveHost resolves the audit host within auditResolveTimeout and
// refuses an answer holding any blocked address. The error names the cause.
func auditResolveHost(ctx context.Context, host string) ([]net.IP, error) {
	rctx, cancel := context.WithTimeout(ctx, auditResolveTimeout)
	defer cancel()
	ips, err := callbackLookupIP(rctx, host)
	if err == nil && len(ips) == 0 {
		err = errors.New("no addresses")
	}
	if err != nil {
		return nil, fmt.Errorf("ADSSH_AUDIT_URL: host %s did not resolve: %v", host, err)
	}
	switch checkResolvedIPs(ips) {
	case nil:
		return ips, nil
	case errPrivateHost:
		return nil, fmt.Errorf("ADSSH_AUDIT_URL: host %s resolves to a private address; set ADSSH_CALLBACK_ALLOW_PRIVATE=1 to allow it", host)
	default:
		return nil, fmt.Errorf("ADSSH_AUDIT_URL: host %s resolves to a blocked address", host)
	}
}

// auditDialContext resolves and checks the audit host, then dials only the
// checked addresses through callbackDialContext, which checks them again at
// connect time. A literal IP host was checked at construction and goes
// straight to callbackDialContext.
func auditDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errDialDenied
	}
	if net.ParseIP(host) != nil {
		return callbackDialContext(ctx, network, addr)
	}
	ips, err := auditResolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := callbackDialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// postAuditEvent sends one audit event. Any failure, including an unresolved
// or refused host, returns an error and sends nothing.
func postAuditEvent(ctx context.Context, target, token string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("audit webhook request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := callbackHTTPClient(5 * time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return errDialDenied
	}
	transport.DialContext = auditDialContext
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	return resp.Body.Close()
}

func (e *Engine) LogCommand(source string, cmd string) error {
	cmd = RedactSensitiveText(cmd)
	if err := e.writeAuditLine(fmt.Sprintf("[%s] %s\n", source, cmd)); err != nil {
		return err
	}
	if err := e.AppendChain(ChainEntry{
		Type:     "cmd",
		Source:   source,
		Command:  cmd,
		ChangeID: e.GetAuditChangeID(),
	}); err != nil {
		return err
	}
	e.dispatchAuditEvent(map[string]interface{}{
		"type":    "command",
		"source":  source,
		"command": cmd,
	})
	return nil
}

// LogCommand records a command in the audit log and hash chain.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func LogCommand(source string, cmd string) error {
	return defaultEngine.LogCommand(source, cmd)
}

func (e *Engine) LogEvent(event string) error {
	event = RedactSensitiveText(event)
	if err := e.writeAuditLine(event); err != nil {
		return err
	}
	if err := e.AppendChain(ChainEntry{
		Type:     "event",
		Command:  event,
		ChangeID: e.GetAuditChangeID(),
	}); err != nil {
		return err
	}
	if e.syslogWriter != nil {
		// Best-effort: syslog is a secondary sink and runs only after both
		// durable writes succeed.
		if isSyslogWarning(event) {
			_ = e.syslogWriter.Warning(event)
		} else {
			_ = e.syslogWriter.Info(event)
		}
	}
	return nil
}

// LogEvent records an event in the audit log and hash chain.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func LogEvent(event string) error {
	return defaultEngine.LogEvent(event)
}

// LogPolicyDecision records a Rego policy evaluation result in the audit log.
func (e *Engine) LogPolicyDecision(user, command string, allowed bool, denyReason string) error {
	command = RedactSensitiveText(command)
	denyReason = RedactSensitiveText(denyReason)
	if err := e.writeAuditLine(fmt.Sprintf("[POLICY] user=%s command=%s allowed=%v reason=%q\n",
		user, command, allowed, denyReason)); err != nil {
		return err
	}
	if err := e.AppendChain(ChainEntry{
		Type:     "policy",
		User:     user,
		Command:  command,
		Allowed:  &allowed,
		Reason:   denyReason,
		ChangeID: e.GetAuditChangeID(),
	}); err != nil {
		return err
	}
	e.dispatchAuditEvent(map[string]interface{}{
		"type":        "policy_decision",
		"user":        user,
		"command":     command,
		"allowed":     allowed,
		"deny_reason": denyReason,
	})
	return nil
}

// LogCMTicket records a change management ticket entry in the chain.
func (e *Engine) LogCMTicket(ticketID string) error {
	if err := e.writeAuditLine(fmt.Sprintf("[CM] ticket=%s\n", ticketID)); err != nil {
		return err
	}
	return e.AppendChain(ChainEntry{
		Type:     "cm",
		Reason:   ticketID,
		ChangeID: ticketID,
	})
}

// joinDeny keeps a denial even when the denial record itself fails.
func joinDeny(deny string, auditErr error) error {
	if auditErr == nil {
		return fmt.Errorf("%s", deny)
	}
	return fmt.Errorf("%s (audit: %v)", deny, auditErr)
}
