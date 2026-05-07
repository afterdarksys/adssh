package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	auditLogger      *log.Logger
	remoteAuditURL   string
	remoteAuditToken string
)

// InitAuditLog initialises the audit logger at the given path and sets up remote SIEM.
func InitAuditLog(path, url, token string) {
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
