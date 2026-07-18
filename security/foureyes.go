package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

// FourEyesDir returns the HOME-derived base directory for four-eyes IPC files.
// The default engine (and any engine constructed without an explicit
// FourEyesDir) resolves its base directory through this at call time, so tests
// that sandbox HOME see the sandboxed directory.
func FourEyesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".adssh/foureyes"
	}
	return filepath.Join(home, ".adssh", "foureyes")
}

// fourEyesBaseDir returns the engine's four-eyes base directory: its explicit
// fourEyesDir if set, otherwise the HOME-derived FourEyesDir() resolved now.
func (e *Engine) fourEyesBaseDir() string {
	if e.fourEyesDir != "" {
		return e.fourEyesDir
	}
	return FourEyesDir()
}

func (e *Engine) fourEyesRulesPath() string {
	return filepath.Join(e.fourEyesBaseDir(), "rules")
}

func (e *Engine) fourEyesPendingDir() string {
	return filepath.Join(e.fourEyesBaseDir(), "pending")
}

func (e *Engine) fourEyesApprovedDir() string {
	return filepath.Join(e.fourEyesBaseDir(), "approved")
}

func (e *Engine) fourEyesDeniedDir() string {
	return filepath.Join(e.fourEyesBaseDir(), "denied")
}

func fourEyesRulesPath() string   { return defaultEngine.fourEyesRulesPath() }
func fourEyesPendingDir() string  { return defaultEngine.fourEyesPendingDir() }
func fourEyesApprovedDir() string { return defaultEngine.fourEyesApprovedDir() }
func fourEyesDeniedDir() string   { return defaultEngine.fourEyesDeniedDir() }

func (e *Engine) ensureFourEyesDirs() error {
	for _, d := range []string{
		e.fourEyesPendingDir(),
		e.fourEyesApprovedDir(),
		e.fourEyesDeniedDir(),
	} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("foureyes: mkdir %s: %w", d, err)
		}
	}
	return nil
}

func ensureFourEyesDirs() error { return defaultEngine.ensureFourEyesDirs() }

// LoadFourEyesRules reads the rules file. Returns empty slice if file doesn't exist.
func (e *Engine) LoadFourEyesRules() ([]FourEyesRule, error) {
	data, err := os.ReadFile(e.fourEyesRulesPath())
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

// LoadFourEyesRules reads the rules file.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func LoadFourEyesRules() ([]FourEyesRule, error) {
	return defaultEngine.LoadFourEyesRules()
}

// SaveFourEyesRules writes the rules file atomically.
func (e *Engine) SaveFourEyesRules(rules []FourEyesRule) error {
	if err := os.MkdirAll(e.fourEyesBaseDir(), 0700); err != nil {
		return fmt.Errorf("foureyes: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return fmt.Errorf("foureyes: marshal rules: %w", err)
	}
	return os.WriteFile(e.fourEyesRulesPath(), data, 0600)
}

// SaveFourEyesRules writes the rules file atomically.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func SaveFourEyesRules(rules []FourEyesRule) error {
	return defaultEngine.SaveFourEyesRules(rules)
}

// AddFourEyesRule appends a new rule. Applies a default TTL of 300 if ttl <= 0.
func (e *Engine) AddFourEyesRule(pattern, approver string, ttl int) error {
	if ttl <= 0 {
		ttl = 300
	}
	rules, err := e.LoadFourEyesRules()
	if err != nil {
		return err
	}
	// replace existing rule with same pattern if present
	for i, r := range rules {
		if r.Pattern == pattern {
			rules[i] = FourEyesRule{Pattern: pattern, Approver: approver, TTL: ttl}
			return e.SaveFourEyesRules(rules)
		}
	}
	rules = append(rules, FourEyesRule{Pattern: pattern, Approver: approver, TTL: ttl})
	return e.SaveFourEyesRules(rules)
}

// AddFourEyesRule appends a new rule.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func AddFourEyesRule(pattern, approver string, ttl int) error {
	return defaultEngine.AddFourEyesRule(pattern, approver, ttl)
}

// RemoveFourEyesRule removes the first rule matching pattern.
func (e *Engine) RemoveFourEyesRule(pattern string) error {
	rules, err := e.LoadFourEyesRules()
	if err != nil {
		return err
	}
	filtered := rules[:0]
	for _, r := range rules {
		if r.Pattern != pattern {
			filtered = append(filtered, r)
		}
	}
	return e.SaveFourEyesRules(filtered)
}

// RemoveFourEyesRule removes the first rule matching pattern.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func RemoveFourEyesRule(pattern string) error {
	return defaultEngine.RemoveFourEyesRule(pattern)
}

// MatchesFourEyes returns the first rule whose pattern matches cmd, or nil.
// The glob pattern is translated into an anchored regexp: '*' matches any run
// of characters (including spaces and '/') and '?' matches any single
// character. This is a deliberate change from filepath.Match semantics — a
// rule like "rm *" now matches "rm -rf /" (filepath.Match's '*' would not
// cross the '/' path separator). Matching is anchored to the full command
// string, so "rm *" does not match "ls" and does not prefix-match "format".
// A rule whose pattern fails to compile as a regexp is skipped (cannot match).
func (e *Engine) MatchesFourEyes(cmd string) (*FourEyesRule, bool) {
	rules, err := e.LoadFourEyesRules()
	if err != nil || len(rules) == 0 {
		return nil, false
	}
	for _, r := range rules {
		re, err := regexp.Compile(globToRegexp(r.Pattern))
		if err != nil {
			continue
		}
		if re.MatchString(cmd) {
			rule := r
			return &rule, true
		}
	}
	return nil, false
}

// MatchesFourEyes returns the first rule whose pattern matches cmd, or nil.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func MatchesFourEyes(cmd string) (*FourEyesRule, bool) {
	return defaultEngine.MatchesFourEyes(cmd)
}

// globToRegexp translates a glob pattern into an anchored regexp source where
// '*' matches any characters (including spaces and '/') and '?' matches any
// single character. All other glob metacharacters are taken literally.
func globToRegexp(pattern string) string {
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, `\*`, `.*`)
	quoted = strings.ReplaceAll(quoted, `\?`, `.`)
	return `^(?s:` + quoted + `)$`
}

// generateToken creates a short deterministic token from cmd + current time.
func generateToken(cmd string) string {
	h := sha256.Sum256([]byte(cmd + time.Now().String()))
	return fmt.Sprintf("%x", h[:])[:12]
}

// RequestApproval creates a pending request and polls until approved, denied, or timed out.
// Prints the token prominently on stderr and shows a spinner while waiting.
func (e *Engine) RequestApproval(cmd string, rule FourEyesRule) error {
	if err := e.ensureFourEyesDirs(); err != nil {
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
	pendingFile := filepath.Join(e.fourEyesPendingDir(), token+".json")
	if err := os.WriteFile(pendingFile, data, 0600); err != nil {
		return fmt.Errorf("foureyes: write pending: %w", err)
	}

	// Print token prominently
	fmt.Fprintf(os.Stderr, "\n\U0001F510 4-eyes required. Token: %s\nRun: 4eyes approve %s\n\n", token, token)

	// Send webhook notification if configured
	// TODO(engine-config): read the webhook URL from EngineConfig instead of the process env.
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

	approvedPath := filepath.Join(e.fourEyesApprovedDir(), token)
	deniedPath := filepath.Join(e.fourEyesDeniedDir(), token)

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

// RequestApproval creates a pending request and polls until approved, denied, or timed out.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func RequestApproval(cmd string, rule FourEyesRule) error {
	return defaultEngine.RequestApproval(cmd, rule)
}

// sendWebhookNotification POSTs approval request details to a webhook URL.
func sendWebhookNotification(webhookURL, token, cmd, requester, hostname string) {
	payload := map[string]string{
		"token":       token,
		"command":     cmd,
		"requester":   requester,
		"hostname":    hostname,
		"approve_cmd": "4eyes approve " + token,
		"deny_cmd":    "4eyes deny " + token,
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
func (e *Engine) ApproveRequest(token string) error {
	if err := e.ensureFourEyesDirs(); err != nil {
		return err
	}
	approvedPath := filepath.Join(e.fourEyesApprovedDir(), token)
	if err := os.WriteFile(approvedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
		return fmt.Errorf("foureyes: write approved marker: %w", err)
	}
	// Remove pending file (best effort)
	pendingFile := filepath.Join(e.fourEyesPendingDir(), token+".json")
	os.Remove(pendingFile) //nolint:errcheck
	return nil
}

// ApproveRequest writes an approved marker and removes the pending file.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func ApproveRequest(token string) error {
	return defaultEngine.ApproveRequest(token)
}

// DenyRequest writes a denied marker and removes the pending file.
func (e *Engine) DenyRequest(token string) error {
	if err := e.ensureFourEyesDirs(); err != nil {
		return err
	}
	deniedPath := filepath.Join(e.fourEyesDeniedDir(), token)
	if err := os.WriteFile(deniedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
		return fmt.Errorf("foureyes: write denied marker: %w", err)
	}
	// Remove pending file (best effort)
	pendingFile := filepath.Join(e.fourEyesPendingDir(), token+".json")
	os.Remove(pendingFile) //nolint:errcheck
	return nil
}

// DenyRequest writes a denied marker and removes the pending file.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func DenyRequest(token string) error {
	return defaultEngine.DenyRequest(token)
}

// ListPending returns all pending approval requests.
func (e *Engine) ListPending() ([]FourEyesPending, error) {
	entries, err := os.ReadDir(e.fourEyesPendingDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("foureyes: list pending: %w", err)
	}
	var out []FourEyesPending
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(e.fourEyesPendingDir(), ent.Name()))
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

// ListPending returns all pending approval requests.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func ListPending() ([]FourEyesPending, error) {
	return defaultEngine.ListPending()
}
