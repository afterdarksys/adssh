package security

// The core half of the approval layer (open-core split, wave 2).
//
// Change management and four-eyes approval are enterprise (cm_ee.go,
// foureyes_ee.go). Their configuration is not: the four-eyes rules file and
// ADSSH_CM_PATTERNS / ADSSH_CM_STRICT are read here, in every build, so a
// core build that finds a rule it cannot satisfy refuses the command instead
// of skipping the approval.
//
// Threats: a host that switches from the enterprise build to the core build,
// or an embedder that never installs an ApprovalGate, keeps its four-eyes
// rules file and its strict change-management patterns. Without this file
// those commands would run with no second approver and no ticket. The core
// gate denies a command that matches a four-eyes rule, denies a command that
// strict change management covers, and denies every command when the rules
// file exists but cannot be read or parsed. It does not stop an operator who
// deletes the rules file or unsets ADSSH_CM_STRICT; that is a configuration
// change, recorded nowhere by adssh.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// ApprovalGate runs after Rego policy and entitlements allow a command and
// before the command executes. The enterprise build installs one from
// init() (approval_gate_ee.go). Without one, the core gate below applies.
type ApprovalGate interface {
	// Check returns nil when the command may run. A refusal error starts with
	// "cm:" or "foureyes:" so engine.IsApprovalRequired classifies it.
	Check(ctx context.Context, e *Engine, sessionID string, args []string) error
	// Explain returns the change_management and four_eyes stages that why
	// and ?? show. It must not create requests or write audit entries.
	Explain(e *Engine, sessionID string, args []string) []ExplanationStage
	// NotifyPolicyDenial is called, without blocking the caller, when policy
	// denies gateway, lease or elevate.
	NotifyPolicyDenial(command, requiredRole string)
}

var (
	approvalGateMu sync.RWMutex
	approvalGate   ApprovalGate
)

// SetApprovalGate installs g for every engine in the process. It can be
// called once; a second call returns an error, so an embedder cannot replace
// the enterprise gate, and the enterprise gate cannot replace an embedder's.
func SetApprovalGate(g ApprovalGate) error {
	if g == nil {
		return errors.New("security: SetApprovalGate: nil gate")
	}
	approvalGateMu.Lock()
	defer approvalGateMu.Unlock()
	if approvalGate != nil {
		return errors.New("security: SetApprovalGate: a gate is already installed")
	}
	approvalGate = g
	return nil
}

func currentApprovalGate() ApprovalGate {
	approvalGateMu.RLock()
	defer approvalGateMu.RUnlock()
	if approvalGate == nil {
		return coreApprovalGate{}
	}
	return approvalGate
}

// coreApprovalGate is the gate of a build with no approval layer.
type coreApprovalGate struct{}

func (coreApprovalGate) Check(_ context.Context, e *Engine, sessionID string, args []string) error {
	if CMStrictMode() && e.CMRequiredForSession(sessionID, args[0]) {
		return e.auditCoreRefusal("cm", sessionID, args[0], fmt.Errorf("cm: command %q requires an active change ticket; change management is part of the adssh enterprise build, so this build refuses it", args[0]))
	}
	rule, matched, err := e.matchFourEyes(strings.Join(args, " "))
	if err != nil {
		return e.auditCoreRefusal("foureyes", sessionID, args[0], fmt.Errorf("foureyes: %v; refusing the command", err))
	}
	if matched {
		return e.auditCoreRefusal("foureyes", sessionID, args[0], fmt.Errorf("foureyes: command matches rule %q and needs a second approver; four-eyes approval is part of the adssh enterprise build, so this build refuses it", rule.Pattern))
	}
	return nil
}

// auditCoreRefusal records a core-gate refusal in the audit chain and returns
// refusal, joined with the audit error when the write fails. The command name
// is logged, not its arguments.
func (e *Engine) auditCoreRefusal(kind, sessionID, command string, refusal error) error {
	if err := e.LogEvent(fmt.Sprintf("APPROVAL_REFUSED: gate=core kind=%s session=%s command=%q", kind, emptyDash(sessionID), command)); err != nil {
		return fmt.Errorf("%w (audit: %v)", refusal, err)
	}
	return refusal
}

func (coreApprovalGate) Explain(e *Engine, sessionID string, args []string) []ExplanationStage {
	cm := ExplanationStage{Name: "change_management", Status: "not_required"}
	if e.CMRequiredForSession(sessionID, args[0]) {
		if CMStrictMode() {
			cm = ExplanationStage{Name: "change_management", Status: "denied", Reason: "an active approved change ticket is required; change management is enterprise-only"}
		} else {
			cm = ExplanationStage{Name: "change_management", Status: "warning", Reason: "no active ticket; strict mode is disabled"}
		}
	}
	return []ExplanationStage{cm, explainFourEyes(e, args, "four-eyes approval is enterprise-only, so this build refuses the command")}
}

func (coreApprovalGate) NotifyPolicyDenial(string, string) {}

// explainFourEyes is the four_eyes stage. A matching rule is
// approval_required, or denied when refusal is non-empty; an unreadable
// rules file is denied.
func explainFourEyes(e *Engine, args []string, refusal string) ExplanationStage {
	rule, matched, err := e.matchFourEyes(strings.Join(args, " "))
	if err != nil {
		return ExplanationStage{Name: "four_eyes", Status: "denied", Reason: err.Error()}
	}
	if !matched {
		return ExplanationStage{Name: "four_eyes", Status: "not_required"}
	}
	reason := fmt.Sprintf("matches rule %q", rule.Pattern)
	if rule.Approver != "" {
		reason += "; approver=" + rule.Approver
	}
	if refusal != "" {
		return ExplanationStage{Name: "four_eyes", Status: "denied", Reason: reason + "; " + refusal}
	}
	return ExplanationStage{Name: "four_eyes", Status: "approval_required", Reason: reason}
}

// matchFourEyes is MatchesFourEyes that reports an unreadable or malformed
// rules file instead of treating it as no rules. The gates fail closed on it.
func (e *Engine) matchFourEyes(cmd string) (*FourEyesRule, bool, error) {
	rules, err := e.LoadFourEyesRules()
	if err != nil {
		return nil, false, err
	}
	for _, r := range rules {
		re, err := regexp.Compile(globToRegexp(r.Pattern))
		if err != nil {
			continue
		}
		if re.MatchString(cmd) {
			rule := r
			return &rule, true, nil
		}
	}
	return nil, false, nil
}

// FourEyesRule defines a pattern that requires dual approval before execution.
type FourEyesRule struct {
	Pattern  string `json:"pattern"`  // glob pattern matched against full command string
	Approver string `json:"approver"` // optional: specific username required to approve
	TTL      int    `json:"ttl"`      // seconds to wait for approval (default 300)
	// NotApprover names a user who may never decide the request (a snoop
	// investigation excludes the session owner).
	NotApprover string `json:"not_approver,omitempty"`
	// Surface, when set, is the only surface that may decide the request.
	Surface string `json:"surface,omitempty"`
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

func fourEyesRulesPath() string { return defaultEngine.fourEyesRulesPath() }

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

// MatchesFourEyes returns the first rule whose pattern matches cmd, or nil.
// The glob pattern is translated into an anchored regexp: '*' matches any run
// of characters (including spaces and '/') and '?' matches any single
// character. This is a deliberate change from filepath.Match semantics — a
// rule like "rm *" now matches "rm -rf /" (filepath.Match's '*' would not
// cross the '/' path separator). Matching is anchored to the full command
// string, so "rm *" does not match "ls" and does not prefix-match "format".
// A rule whose pattern fails to compile as a regexp is skipped (cannot match).
// A rules file that cannot be read reports no match here; the gates use
// matchFourEyes, which refuses the command instead.
func (e *Engine) MatchesFourEyes(cmd string) (*FourEyesRule, bool) {
	rule, matched, err := e.matchFourEyes(cmd)
	if err != nil {
		return nil, false
	}
	return rule, matched
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

// fourEyesDecisionsForbidden is set once by a process that must never approve
// or deny, such as the MCP server. It cannot be cleared.
var fourEyesDecisionsForbidden atomic.Bool

// ForbidFourEyesDecisions makes every approve and deny in this process fail.
// adssh-mcp calls it at startup so an agent cannot approve through any tool,
// including run_shell or eval_starlark.
func ForbidFourEyesDecisions() { fourEyesDecisionsForbidden.Store(true) }

// parseCMPatterns splits a comma-separated ADSSH_CM_PATTERNS value.
func parseCMPatterns(raw string) []string {
	var out []string
	for _, pat := range strings.Split(raw, ",") {
		if pat = strings.TrimSpace(pat); pat != "" {
			out = append(out, pat)
		}
	}
	return out
}

// CMPatternsForSession returns the process default patterns followed by the
// ones sessionID added with cm require.
func (e *Engine) CMPatternsForSession(sessionID string) []string {
	e.cmMu.Lock()
	defer e.cmMu.Unlock()
	out := append([]string(nil), e.cmDefaultPatterns...)
	return append(out, e.cmPatterns[sessionID]...)
}

// AddCMPatternForSession adds pattern to sessionID's own list. It reports
// false when the session already requires the pattern.
func (e *Engine) AddCMPatternForSession(sessionID, pattern string) bool {
	e.cmMu.Lock()
	defer e.cmMu.Unlock()
	if slices.Contains(e.cmDefaultPatterns, pattern) || slices.Contains(e.cmPatterns[sessionID], pattern) {
		return false
	}
	if e.cmPatterns == nil {
		e.cmPatterns = map[string][]string{}
	}
	e.cmPatterns[sessionID] = append(e.cmPatterns[sessionID], pattern)
	return true
}

// CMRequiredForSession reports whether cmd matches a pattern sessionID is
// held to (filepath.Match globs on the command and its base name).
func (e *Engine) CMRequiredForSession(sessionID, cmd string) bool {
	base := filepath.Base(cmd)
	for _, pat := range e.CMPatternsForSession(sessionID) {
		if matched, _ := filepath.Match(pat, cmd); matched {
			return true
		}
		if matched, _ := filepath.Match(pat, base); matched {
			return true
		}
	}
	return false
}

// CMRequiredForCommand checks cmd against the default engine's process-wide
// patterns.
//
// Deprecated: use Engine.CMRequiredForSession.
func CMRequiredForCommand(cmd string) bool {
	return defaultEngine.CMRequiredForSession("", cmd)
}

// CMStrictMode returns true when ADSSH_CM_STRICT=1.
func CMStrictMode() bool {
	// TODO(engine-config): read from EngineConfig instead of the process env.
	return os.Getenv("ADSSH_CM_STRICT") == "1"
}
