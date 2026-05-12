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

var (
	auditLogger      *log.Logger
	remoteAuditURL   string
	remoteAuditToken string
	syslogWriter     *syslog.Writer
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

// InitAuditLog initialises the audit logger at the given path and sets up remote SIEM.
func InitAuditLog(path, url, token string) {
	// Initialise syslog writer if ADSSH_SYSLOG is set.
	if syslogEnv := os.Getenv("ADSSH_SYSLOG"); syslogEnv != "" {
		facility := parseSyslogFacility(syslogEnv)
		w, err := syslog.New(facility|syslog.LOG_INFO, "adssh")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open syslog writer: %v\n", err)
		} else {
			syslogWriter = w
		}
	}

	remoteAuditURL = url
	remoteAuditToken = token

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create audit log directory: %v\n", err)
		return
	}
	logFile, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize audit logger at %s: %v\n", path, err)
		return
	}
	auditLogger = log.New(logFile, "AUDIT: ", log.Ldate|log.Ltime)
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

func dispatchAuditEvent(payload map[string]interface{}) {
	if remoteAuditURL == "" {
		return
	}
	payload["time"] = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	go func() {
		req, err := http.NewRequest("POST", remoteAuditURL, bytes.NewBuffer(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if remoteAuditToken != "" {
			req.Header.Set("Authorization", "Bearer "+remoteAuditToken)
		}
		client := &http.Client{Timeout: 5 * time.Second}
		client.Do(req)
	}()
}

func LogCommand(source string, cmd string) {
	if auditLogger != nil {
		auditLogger.Printf("[%s] %s\n", source, cmd)
	}
	dispatchAuditEvent(map[string]interface{}{
		"type":    "command",
		"source":  source,
		"command": cmd,
	})
}

func LogEvent(event string) {
	if auditLogger != nil {
		auditLogger.Println(event)
	}
	if syslogWriter != nil {
		if isSyslogWarning(event) {
			syslogWriter.Warning(event)
		} else {
			syslogWriter.Info(event)
		}
	}
}

// LogPolicyDecision records a Rego policy evaluation result in the audit log.
func LogPolicyDecision(user, command string, allowed bool, denyReason string) {
	if auditLogger != nil {
		auditLogger.Printf("[POLICY] user=%s command=%s allowed=%v reason=%q\n",
			user, command, allowed, denyReason)
	}
	dispatchAuditEvent(map[string]interface{}{
		"type":        "policy_decision",
		"user":        user,
		"command":     command,
		"allowed":     allowed,
		"deny_reason": denyReason,
	})
}
