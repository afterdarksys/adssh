package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FourEyesRule defines a pattern that requires dual approval before execution.
type FourEyesRule struct {
	Pattern  string `json:"pattern"`  // glob pattern matched against full command string
	Approver string `json:"approver"` // optional: specific username required to approve
	TTL      int    `json:"ttl"`      // seconds to wait for approval (default 300)
}

// FourEyesPending represents a command held for approval.
type FourEyesPending struct {
	Token     string       `json:"token"`
	Command   string       `json:"command"`
	Requester string       `json:"requester"`
	Hostname  string       `json:"hostname"`
	Timestamp string       `json:"timestamp"`
	Rule      FourEyesRule `json:"rule"`
}

// FourEyesDir returns the base directory for four-eyes IPC files.
func FourEyesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".adssh/foureyes"
	}
	return filepath.Join(home, ".adssh", "foureyes")
}

func fourEyesRulesPath() string {
	return filepath.Join(FourEyesDir(), "rules")
}

func fourEyesPendingDir() string {
	return filepath.Join(FourEyesDir(), "pending")
}

func fourEyesApprovedDir() string {
	return filepath.Join(FourEyesDir(), "approved")
}

func fourEyesDeniedDir() string {
	return filepath.Join(FourEyesDir(), "denied")
}

func ensureFourEyesDirs() error {
	for _, d := range []string{
		fourEyesPendingDir(),
		fourEyesApprovedDir(),
		fourEyesDeniedDir(),
	} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("foureyes: mkdir %s: %w", d, err)
		}
	}
	return nil
}

// LoadFourEyesRules reads the rules file. Returns empty slice if file doesn't exist.
func LoadFourEyesRules() ([]FourEyesRule, error) {
	data, err := os.ReadFile(fourEyesRulesPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("foureyes: read rules: %w", err)
	}
	var rules []FourEyesRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("foureyes: parse rules: %w", err)
	}
	return rules, nil
}

// SaveFourEyesRules writes the rules file atomically.
func SaveFourEyesRules(rules []FourEyesRule) error {
	if err := os.MkdirAll(FourEyesDir(), 0700); err != nil {
		return fmt.Errorf("foureyes: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return fmt.Errorf("foureyes: marshal rules: %w", err)
	}
	return os.WriteFile(fourEyesRulesPath(), data, 0600)
}

// AddFourEyesRule appends a new rule. Applies a default TTL of 300 if ttl <= 0.
func AddFourEyesRule(pattern, approver string, ttl int) error {
	if ttl <= 0 {
		ttl = 300
	}
	rules, err := LoadFourEyesRules()
	if err != nil {
		return err
	}
	// replace existing rule with same pattern if present
	for i, r := range rules {
		if r.Pattern == pattern {
			rules[i] = FourEyesRule{Pattern: pattern, Approver: approver, TTL: ttl}
			return SaveFourEyesRules(rules)
		}
	}
	rules = append(rules, FourEyesRule{Pattern: pattern, Approver: approver, TTL: ttl})
	return SaveFourEyesRules(rules)
}

// RemoveFourEyesRule removes the first rule matching pattern.
func RemoveFourEyesRule(pattern string) error {
	rules, err := LoadFourEyesRules()
	if err != nil {
		return err
	}
	filtered := rules[:0]
	for _, r := range rules {
		if r.Pattern != pattern {
			filtered = append(filtered, r)
		}
	}
	return SaveFourEyesRules(filtered)
}

// MatchesFourEyes returns the first rule whose pattern matches cmd, or nil.
// Uses filepath.Match glob semantics.
func MatchesFourEyes(cmd string) (*FourEyesRule, bool) {
	rules, err := LoadFourEyesRules()
	if err != nil || len(rules) == 0 {
		return nil, false
	}
	for _, r := range rules {
		matched, err := filepath.Match(r.Pattern, cmd)
		if err != nil {
			continue
		}
		if matched {
			rule := r
			return &rule, true
		}
		// Also check if any word in the command matches the pattern (substring glob)
		if strings.Contains(cmd, strings.Trim(r.Pattern, "*")) && r.Pattern != "" {
			// Try matching against individual tokens
			for _, tok := range strings.Fields(cmd) {
				if m, _ := filepath.Match(r.Pattern, tok); m {
					rule := r
					return &rule, true
				}
			}
		}
	}
	return nil, false
}

// generateToken creates a short deterministic token from cmd + current time.
func generateToken(cmd string) string {
	h := sha256.Sum256([]byte(cmd + time.Now().String()))
	return fmt.Sprintf("%x", h[:])[:12]
}

// RequestApproval creates a pending request and polls until approved, denied, or timed out.
// Prints the token prominently on stderr and shows a spinner while waiting.
func RequestApproval(cmd string, rule FourEyesRule) error {
	if err := ensureFourEyesDirs(); err != nil {
		return err
	}

	token := generateToken(cmd)
	hostname, _ := os.Hostname()
	requester := os.Getenv("USER")
	if requester == "" {
		requester = os.Getenv("LOGNAME")
	}
	if requester == "" {
		requester = "unknown"
	}

	pending := FourEyesPending{
		Token:     token,
		Command:   cmd,
		Requester: requester,
		Hostname:  hostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Rule:      rule,
	}

	data, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return fmt.Errorf("foureyes: marshal pending: %w", err)
	}
	pendingFile := filepath.Join(fourEyesPendingDir(), token+".json")
	if err := os.WriteFile(pendingFile, data, 0600); err != nil {
		return fmt.Errorf("foureyes: write pending: %w", err)
	}

	// Print token prominently
	fmt.Fprintf(os.Stderr, "\n\U0001F510 4-eyes required. Token: %s\nRun: 4eyes approve %s\n\n", token, token)

	// Send webhook notification if configured
	if webhookURL := os.Getenv("ADSSH_4EYES_WEBHOOK"); webhookURL != "" {
		go sendWebhookNotification(webhookURL, token, cmd, requester, hostname)
	}

	ttl := rule.TTL
	if ttl <= 0 {
		ttl = 300
	}

	deadline := time.Now().Add(time.Duration(ttl) * time.Second)
	spinChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := 0

	approvedPath := filepath.Join(fourEyesApprovedDir(), token)
	deniedPath := filepath.Join(fourEyesDeniedDir(), token)

	for time.Now().Before(deadline) {
		remaining := int(time.Until(deadline).Seconds())

		// Check approved
		if _, err := os.Stat(approvedPath); err == nil {
			fmt.Fprintf(os.Stderr, "\r\033[K\u2705 Request %s approved.\n", token)
			return nil
		}
		// Check denied
		if _, err := os.Stat(deniedPath); err == nil {
			fmt.Fprintf(os.Stderr, "\r\033[K\u274C Request %s denied.\n", token)
			return fmt.Errorf("foureyes: request %s denied", token)
		}

		fmt.Fprintf(os.Stderr, "\r%s waiting for approval (token: %s) [%ds remaining]",
			spinChars[spinIdx%len(spinChars)], token, remaining)
		spinIdx++
		time.Sleep(2 * time.Second)
	}

	// Timed out — clean up pending file
	fmt.Fprintf(os.Stderr, "\r\033[K\u23F0 Request %s timed out.\n", token)
	os.Remove(pendingFile) //nolint:errcheck
	return fmt.Errorf("foureyes: request %s timed out after %ds", token, ttl)
}

// sendWebhookNotification POSTs approval request details to a webhook URL.
func sendWebhookNotification(webhookURL, token, cmd, requester, hostname string) {
	payload := map[string]string{
		"token":        token,
		"command":      cmd,
		"requester":    requester,
		"hostname":     hostname,
		"approve_cmd":  "4eyes approve " + token,
		"deny_cmd":     "4eyes deny " + token,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// ApproveRequest writes an approved marker and removes the pending file.
func ApproveRequest(token string) error {
	if err := ensureFourEyesDirs(); err != nil {
		return err
	}
	approvedPath := filepath.Join(fourEyesApprovedDir(), token)
	if err := os.WriteFile(approvedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
		return fmt.Errorf("foureyes: write approved marker: %w", err)
	}
	// Remove pending file (best effort)
	pendingFile := filepath.Join(fourEyesPendingDir(), token+".json")
	os.Remove(pendingFile) //nolint:errcheck
	return nil
}

// DenyRequest writes a denied marker and removes the pending file.
func DenyRequest(token string) error {
	if err := ensureFourEyesDirs(); err != nil {
		return err
	}
	deniedPath := filepath.Join(fourEyesDeniedDir(), token)
	if err := os.WriteFile(deniedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
		return fmt.Errorf("foureyes: write denied marker: %w", err)
	}
	// Remove pending file (best effort)
	pendingFile := filepath.Join(fourEyesPendingDir(), token+".json")
	os.Remove(pendingFile) //nolint:errcheck
	return nil
}

// ListPending returns all pending approval requests.
func ListPending() ([]FourEyesPending, error) {
	entries, err := os.ReadDir(fourEyesPendingDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("foureyes: list pending: %w", err)
	}
	var out []FourEyesPending
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(fourEyesPendingDir(), e.Name()))
		if err != nil {
			continue
		}
		var p FourEyesPending
		if err := json.Unmarshal(data, &p); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
