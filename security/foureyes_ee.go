//go:build ee

package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// FourEyesPending represents a command held for approval.
type FourEyesPending struct {
	Token     string       `json:"token"`
	RequestID string       `json:"request_id,omitempty"`
	Command   string       `json:"command"`
	Requester string       `json:"requester"`
	Hostname  string       `json:"hostname"`
	Timestamp string       `json:"timestamp"`
	Rule      FourEyesRule `json:"rule"`
	// Status is set by ListPending: pending, or claimed while a decision is
	// in progress. It is not stored in the request file.
	Status string `json:"status,omitempty"`
}

// ListPending statuses.
const (
	FourEyesStatusPending = "pending"
	FourEyesStatusClaimed = "claimed"
)

func (e *Engine) fourEyesPendingDir() string {
	return filepath.Join(e.fourEyesBaseDir(), "pending")
}

func (e *Engine) fourEyesApprovedDir() string {
	return filepath.Join(e.fourEyesBaseDir(), "approved")
}

func (e *Engine) fourEyesDeniedDir() string {
	return filepath.Join(e.fourEyesBaseDir(), "denied")
}

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

// RequestApproval creates a pending request and polls until approved, denied, or timed out.
// The secret token stays in the pending file. Stderr shows the public request id.
func (e *Engine) RequestApproval(cmd string, rule FourEyesRule) error {
	return e.RequestApprovalForSession(cmd, rule, "")
}

// RequestApprovalForSession creates a pending request attributed to the
// authenticated session identity, then waits for a distinct approver.
func (e *Engine) RequestApprovalForSession(cmd string, rule FourEyesRule, sessionID string) error {
	return e.RequestApprovalForSessionContext(context.Background(), cmd, rule, sessionID)
}

// RequestApprovalForSessionContext is RequestApprovalForSession whose wait
// ends when ctx is done. A canceled wait removes the pending request and
// denies.
func (e *Engine) RequestApprovalForSessionContext(ctx context.Context, cmd string, rule FourEyesRule, sessionID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := e.ensureFourEyesDirs(); err != nil {
		return err
	}

	pending, pendingFile, err := e.createFourEyesPending(cmd, rule, sessionID)
	if err != nil {
		return err
	}
	requestID := pending.RequestID
	sink := approvalSink(sessionID)
	fmt.Fprint(sink, formatApprovalPrompt(pendingFile, requestID, rule.Approver))

	required := rule.Approver
	if required == "" {
		required = "any distinct approver"
	}
	noticeApprover := rule.Approver
	if noticeApprover == "" {
		noticeApprover = "unspecified"
	}
	fingerprint := fingerprintSecret(pending.Token)
	commandName := commandHead(cmd)
	go func() {
		_ = sendApprovalNotice(approvalNotice{
			Event:            "approval_required",
			Kind:             "foureyes",
			Command:          commandName,
			RequiredApprover: noticeApprover,
			Fingerprint:      fingerprint,
		})
	}()

	ttl := rule.TTL
	if ttl <= 0 {
		ttl = 300
	}

	deadline := time.Now().Add(time.Duration(ttl) * time.Second)
	spinChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := 0

	approvedPath := filepath.Join(e.fourEyesApprovedDir(), requestID)
	deniedPath := filepath.Join(e.fourEyesDeniedDir(), requestID)

	for time.Now().Before(deadline) {
		remaining := int(time.Until(deadline).Seconds())

		if _, err := os.Stat(approvedPath); err == nil {
			fmt.Fprintf(sink, "\r\033[K\u2705 Request %s approved.\n", requestID)
			return nil
		}
		if _, err := os.Stat(deniedPath); err == nil {
			fmt.Fprintf(sink, "\r\033[K\u274C Request %s denied.\n", requestID)
			return fmt.Errorf("foureyes: request %s denied (required approver: %s)", requestID, required)
		}

		fmt.Fprintf(sink, "\r%s waiting for approval (request: %s) [%ds remaining]",
			spinChars[spinIdx%len(spinChars)], requestID, remaining)
		spinIdx++
		select {
		case <-ctx.Done():
			fmt.Fprintf(sink, "\r\033[K\u274C Request %s canceled.\n", requestID)
			os.Remove(pendingFile) //nolint:errcheck
			return fmt.Errorf("foureyes: request %s canceled (required approver: %s)", requestID, required)
		case <-time.After(2 * time.Second):
		}
	}

	fmt.Fprintf(sink, "\r\033[K\u23F0 Request %s timed out.\n", requestID)
	os.Remove(pendingFile) //nolint:errcheck
	return fmt.Errorf("foureyes: request %s timed out after %ds (required approver: %s)", requestID, ttl, required)
}

// RequestApproval creates a pending request and polls until approved, denied, or timed out.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func RequestApproval(cmd string, rule FourEyesRule) error {
	return defaultEngine.RequestApproval(cmd, rule)
}

// approvalSink is the session channel when the listener has one, and stderr
// for a local approval. The writer is captured once per request.
func approvalSink(sessionID string) io.Writer {
	if sessionID != "" {
		if session := sys.GetSession(sessionID); session != nil {
			if w := session.PromptWriter(); w != nil {
				return w
			}
		}
	}
	return os.Stderr
}

func approvalActor(sessionID string) string {
	if sessionID != "" {
		if session := sys.GetSession(sessionID); session != nil {
			return session.User
		}
	}
	if user, err := osuser.Current(); err == nil {
		return user.Username
	}
	return ""
}

// Four-eyes decision surfaces recorded in FOUREYES_DECISION.
const (
	FourEyesSurfaceHTTP  = "http"
	FourEyesSurfaceShell = "shell"
	FourEyesSurfaceAPI   = "api"
)

var (
	errFourEyesDecisionsForbidden = errors.New("foureyes: this process cannot approve or deny requests")
	errFourEyesAudit              = errors.New("foureyes: audit write failed; decision not recorded")
)

// shellApprover returns the identity a shell session may approve or deny as.
//
// Threats: SetIdentity renames a session at runtime (identity device login,
// OIDC import), so session.User alone is caller-asserted. Only a session whose
// user was set by the code that registered it (empty identity source: the
// local shell, an SSH login), or one whose source a verifier set to
// oidc-verified, may decide. A managed agent session, an unregistered session
// id, a missing session id, and a process that forbade decisions are refused.
// This does not stop the OS account that owns the four-eyes directory from
// writing a marker file by hand.
func shellApprover(sessionID string) (string, error) {
	if fourEyesDecisionsForbidden.Load() {
		return "", errFourEyesDecisionsForbidden
	}
	if sessionID == "" {
		return "", fmt.Errorf("foureyes: approving identity requires a registered session")
	}
	session := sys.GetSession(sessionID)
	if session == nil {
		return "", fmt.Errorf("foureyes: approving identity requires a registered session")
	}
	if session.ManagedAgent() != nil {
		return "", fmt.Errorf("foureyes: agent sessions cannot approve or deny")
	}
	switch source := session.IdentitySource(); source {
	case "", sys.IdentitySourceOIDCVerified:
	default:
		return "", fmt.Errorf("foureyes: identity set by %s cannot approve or deny", source)
	}
	user := session.Info().User
	if user == "" {
		return "", fmt.Errorf("foureyes: approving identity is unavailable")
	}
	return user, nil
}

func validApprovalToken(token string) bool {
	if token == "" || len(token) > 128 || filepath.Base(token) != token {
		return false
	}
	for _, r := range token {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// ApproveRequestAs approves as a caller-asserted identity through the Go API.
// The requester may never self-approve; a configured rule approver must match.
func (e *Engine) ApproveRequestAs(token, approver string) error {
	return e.DecideRequest(token, approver, FourEyesSurfaceAPI, true)
}

// DenyRequestAs denies as a caller-asserted identity through the Go API, with
// the same identity checks as ApproveRequestAs.
func (e *Engine) DenyRequestAs(token, approver string) error {
	return e.DecideRequest(token, approver, FourEyesSurfaceAPI, false)
}

// DecideRequest approves or denies one pending request as approver. The
// caller must already have authenticated approver; surface names how.
//
// Order: identity checks, then an atomic rename of the pending file to a
// claimed name (a second decision loses with "already decided"), then a
// FOUREYES_DECISION audit event, then the marker. If the audit write fails the
// claim is put back and no marker is written. If the marker write fails after
// the audit event, FOUREYES_DECISION_REVERTED is logged and the claim is put
// back, so the chain never holds a decision that did not take effect without
// its revert. Claims older than their TTL are swept first (see
// sweepStaleClaims).
func (e *Engine) DecideRequest(token, approver, surface string, approve bool) error {
	if fourEyesDecisionsForbidden.Load() {
		return errFourEyesDecisionsForbidden
	}
	verb := "deny"
	if approve {
		verb = "approve"
	}
	if err := e.ensureFourEyesDirs(); err != nil {
		return err
	}
	if !validApprovalToken(token) {
		return fmt.Errorf("foureyes: invalid approval token")
	}
	if approver == "" {
		return fmt.Errorf("foureyes: %s identity is unavailable", verb)
	}
	e.sweepStaleClaims()

	pending, pendingFile, markerName, err := e.locatePending(token)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("foureyes: request is not pending or was already decided")
		}
		return err
	}
	if pending.Requester != "" && approver == pending.Requester {
		return fmt.Errorf("foureyes: requester %q cannot %s their own request", approver, verb)
	}
	if pending.Rule.Approver != "" && approver != pending.Rule.Approver {
		return fmt.Errorf("foureyes: request requires approver %q", pending.Rule.Approver)
	}
	if pending.Rule.NotApprover != "" && approver == pending.Rule.NotApprover {
		return fmt.Errorf("foureyes: %q cannot %s this request", approver, verb)
	}
	if pending.Rule.Surface != "" && surface != pending.Rule.Surface {
		return fmt.Errorf("foureyes: this request must be decided through %s", pending.Rule.Surface)
	}

	claimed := filepath.Join(e.fourEyesPendingDir(), markerName+".claimed")
	if err := os.Rename(pendingFile, claimed); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("foureyes: request %s already decided", markerName)
		}
		return fmt.Errorf("foureyes: claim pending request: %w", err)
	}
	// Stamp the claim time so the sweep measures how long the claim has been
	// held, not how old the request is.
	now := time.Now()
	_ = os.Chtimes(claimed, now, now)
	release := func(cause error) error {
		if rerr := os.Rename(claimed, pendingFile); rerr != nil {
			return fmt.Errorf("%w (restore pending request: %v)", cause, rerr)
		}
		return cause
	}
	// revert undoes a decision already written to the chain.
	revert := func(cause error) error {
		if lerr := e.LogEvent(fmt.Sprintf("FOUREYES_DECISION_REVERTED request=%s approver=%s reason=%q",
			markerName, approver, cause.Error())); lerr != nil {
			cause = fmt.Errorf("%w (audit revert: %v)", cause, lerr)
		}
		return release(cause)
	}

	if err := e.LogEvent(fmt.Sprintf("FOUREYES_DECISION request=%s approver=%s decision=%s surface=%s",
		markerName, approver, verb, surface)); err != nil {
		return release(fmt.Errorf("%w: %v", errFourEyesAudit, err))
	}

	dir := e.fourEyesDeniedDir()
	field := "denied_at"
	if approve {
		dir = e.fourEyesApprovedDir()
		field = "approved_at"
	}
	marker, err := json.Marshal(map[string]string{
		field:      time.Now().UTC().Format(time.RFC3339),
		"approver": approver,
		"surface":  surface,
	})
	if err != nil {
		return revert(fmt.Errorf("foureyes: marshal %s marker: %w", verb, err))
	}
	if err := writeExclusive0600(filepath.Join(dir, markerName), marker); err != nil {
		return revert(fmt.Errorf("foureyes: write %s marker: %w", verb, err))
	}
	if err := os.Remove(claimed); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("foureyes: remove claimed request: %w", err)
	}
	return nil
}

// sweepStaleClaims removes claimed requests held longer than their rule TTL
// (default 300s). A claim that old belongs to a decision that crashed between
// the claim and the marker; the requester has already timed out. Each removal
// is logged as FOUREYES_CLAIM_EXPIRED before the file is deleted, and a claim
// whose event cannot be logged is kept for the next sweep.
func (e *Engine) sweepStaleClaims() {
	dir := e.fourEyesPendingDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := time.Now()
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".claimed") {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(dir, name)
		ttl := 300
		if data, err := os.ReadFile(path); err == nil {
			var p FourEyesPending
			if json.Unmarshal(data, &p) == nil && p.Rule.TTL > 0 {
				ttl = p.Rule.TTL
			}
		}
		if now.Sub(info.ModTime()) <= time.Duration(ttl)*time.Second {
			continue
		}
		if err := e.LogEvent(fmt.Sprintf("FOUREYES_CLAIM_EXPIRED request=%s", strings.TrimSuffix(name, ".claimed"))); err != nil {
			continue
		}
		_ = os.Remove(path)
	}
}

func writeExclusive0600(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := file.Write(data)
	cerr := file.Close()
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(path)
		return cerr
	}
	return nil
}

// ApproveRequest approves as the local OS user through the Go API.
func (e *Engine) ApproveRequest(token string) error {
	return e.ApproveRequestAs(token, approvalActor(""))
}

// ApproveRequestAs approves a pending request as the named actor.
func ApproveRequestAs(token, approver string) error {
	return defaultEngine.ApproveRequestAs(token, approver)
}

// ApproveRequest writes an approved marker and removes the pending file.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func ApproveRequest(token string) error {
	return defaultEngine.ApproveRequest(token)
}

// DenyRequest denies as the local OS user. Prefer DenyRequestAs when the
// caller already has an approver identity.
func (e *Engine) DenyRequest(token string) error {
	return e.DenyRequestAs(token, approvalActor(""))
}

// DenyRequestAs denies a pending request as the named actor.
func DenyRequestAs(token, approver string) error {
	return defaultEngine.DenyRequestAs(token, approver)
}

// DenyRequest writes a denied marker and removes the pending file.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func DenyRequest(token string) error {
	return defaultEngine.DenyRequest(token)
}

// ListPending returns all pending approval requests, including requests
// claimed by a decision still in progress (Status claimed). It sweeps stale
// claims first.
func (e *Engine) ListPending() ([]FourEyesPending, error) {
	e.sweepStaleClaims()
	entries, err := os.ReadDir(e.fourEyesPendingDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("foureyes: list pending: %w", err)
	}
	var out []FourEyesPending
	for _, ent := range entries {
		status := FourEyesStatusPending
		switch {
		case ent.IsDir():
			continue
		case strings.HasSuffix(ent.Name(), ".json"):
		case strings.HasSuffix(ent.Name(), ".claimed"):
			status = FourEyesStatusClaimed
		default:
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
		p.Status = status
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
