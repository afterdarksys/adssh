package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

// InitAuditLog initializes the audit logger at the given path and sets up remote SIEM.
func (e *Engine) InitAuditLog(path, url, token string) {
	// Initialize syslog writer if ADSSH_SYSLOG is set.
	if syslogEnv := os.Getenv("ADSSH_SYSLOG"); syslogEnv != "" {
		facility := parseSyslogFacility(syslogEnv)
		w, err := syslog.New(facility|syslog.LOG_INFO, "adssh")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open syslog writer: %v\n", err)
		} else {
			e.syslogWriter = w
		}
	}

	e.remoteAuditURL = url
	e.remoteAuditToken = token

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create audit log directory: %v\n", err)
		return
	}
	logFile, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize audit logger at %s: %v\n", path, err)
		return
	}
	e.auditLogger = log.New(logFile, "AUDIT: ", log.Ldate|log.Ltime)
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

func (e *Engine) dispatchAuditEvent(payload map[string]interface{}) {
	if e.remoteAuditURL == "" {
		return
	}
	payload["time"] = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := e.remoteAuditURL
	token := e.remoteAuditToken
	go func() {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "adssh: audit webhook POST to %s failed: %v\n", url, err)
			return
		}
		resp.Body.Close()
	}()
}

func (e *Engine) LogCommand(source string, cmd string) {
	if e.auditLogger != nil {
		e.auditLogger.Printf("[%s] %s\n", source, cmd)
	}
	e.dispatchAuditEvent(map[string]interface{}{
		"type":    "command",
		"source":  source,
		"command": cmd,
	})
	e.AppendChain(ChainEntry{
		Type:     "cmd",
		Source:   source,
		Command:  cmd,
		ChangeID: e.GetAuditChangeID(),
	})
}

// LogCommand records a command in the audit log and hash chain.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func LogCommand(source string, cmd string) {
	defaultEngine.LogCommand(source, cmd)
}

func (e *Engine) LogEvent(event string) {
	if e.auditLogger != nil {
		e.auditLogger.Println(event)
	}
	if e.syslogWriter != nil {
		// Best-effort: syslog is a secondary sink. The flat audit logger and
		// hash chain (below) are the authoritative record regardless of outcome.
		if isSyslogWarning(event) {
			_ = e.syslogWriter.Warning(event)
		} else {
			_ = e.syslogWriter.Info(event)
		}
	}
	e.AppendChain(ChainEntry{
		Type:     "event",
		Command:  event,
		ChangeID: e.GetAuditChangeID(),
	})
}

// LogEvent records an event in the audit log and hash chain.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func LogEvent(event string) {
	defaultEngine.LogEvent(event)
}

// LogPolicyDecision records a Rego policy evaluation result in the audit log.
func (e *Engine) LogPolicyDecision(user, command string, allowed bool, denyReason string) {
	if e.auditLogger != nil {
		e.auditLogger.Printf("[POLICY] user=%s command=%s allowed=%v reason=%q\n",
			user, command, allowed, denyReason)
	}
	e.dispatchAuditEvent(map[string]interface{}{
		"type":        "policy_decision",
		"user":        user,
		"command":     command,
		"allowed":     allowed,
		"deny_reason": denyReason,
	})
	e.AppendChain(ChainEntry{
		Type:     "policy",
		User:     user,
		Command:  command,
		Allowed:  &allowed,
		Reason:   denyReason,
		ChangeID: e.GetAuditChangeID(),
	})
}

// LogCMTicket records a change management ticket entry in the chain.
func (e *Engine) LogCMTicket(ticketID string) {
	if e.auditLogger != nil {
		e.auditLogger.Printf("[CM] ticket=%s\n", ticketID)
	}
	e.AppendChain(ChainEntry{
		Type:     "cm",
		Reason:   ticketID,
		ChangeID: ticketID,
	})
}
