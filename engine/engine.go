package engine

import (
	"errors"
	"strings"

	"github.com/afterdarksys/adssh/security"
)

// Config is the embedder-facing configuration for an Engine. It unifies the
// security engine configuration (policy, audit sink, HMAC chain, entitlements,
// restricted mode) with the session-level defaults a host applies when it opens
// sessions through this engine.
//
// The embedded security.EngineConfig carries the security core: PolicyPath /
// PolicySource / RequirePolicy, AuditLogPath / AuditLogURL / AuditLogToken,
// ChainPath / ChainKeyPath / SessionID, FourEyesDir, EntitlementsPath and
// Restricted. New passes it straight to security.NewEngine, so construction is
// FAIL-CLOSED: malformed Rego, or RequirePolicy set with no policy, returns an
// error and no Engine.
type Config struct {
	security.EngineConfig

	// ProfilePath is the login-profile Starlark script sourced for sessions that
	// load profiles (~/.adsshprofile by default). Empty disables it.
	ProfilePath string
	// RCPath is the interactive RC Starlark script sourced per session
	// (~/.adsshrc by default). Empty disables it.
	RCPath string
	// HistoryFile is the default history file path applied to sessions opened
	// via (*Engine).NewSession when SessionOptions.HistoryFile is empty.
	HistoryFile string
	// IsLoginShell selects login-shell profile loading semantics for the host.
	IsLoginShell bool
}

// Engine is the public facade over a single isolated security engine. One
// Engine owns its own policy evaluator, audit log, HMAC hash chain, four-eyes /
// change-management state, entitlements and virtual-binary registry; two Engines
// in one process share nothing mutable, so a commercial host can run isolated
// tenants side by side. Sessions opened via NewSession authorize through THIS
// engine, not the process-global default.
type Engine struct {
	sec *security.Engine
	cfg Config
}

// New builds an isolated Engine from cfg. It wraps security.NewEngine and is
// FAIL-CLOSED: a bad policy (malformed Rego, or RequirePolicy with none
// configured) or an unreadable entitlements file returns an error and no
// Engine. A zero-value Config yields an allow-by-default engine with no audit
// log or chain — the same posture the process default has before configuration.
func New(cfg Config) (*Engine, error) {
	sec, err := security.NewEngine(cfg.EngineConfig)
	if err != nil {
		return nil, err
	}
	return &Engine{sec: sec, cfg: cfg}, nil
}

// Security returns the underlying *security.Engine. Hosts that must reach the
// security core directly (to mount the SSH server or MCP handlers, verify the
// audit chain, or evaluate policy outside a session) use this handle. Prefer the
// higher-level Engine/Session methods where they exist.
func (e *Engine) Security() *security.Engine { return e.sec }

// Config returns the configuration this Engine was built from.
func (e *Engine) Config() Config { return e.cfg }

// NewSession builds a fully isolated Session bound to THIS engine. Unless opts
// overrides them, the session inherits the engine's restricted mode and default
// history file, and always authorizes (policy, audit, chain, four-eyes/CM,
// vbins) through this engine rather than the process-global default. It fails
// only if the shell runner cannot be constructed.
func (e *Engine) NewSession(opts SessionOptions) (*Session, error) {
	if opts.Engine == nil {
		opts.Engine = e.sec
	}
	if !opts.Restricted {
		opts.Restricted = e.cfg.Restricted
	}
	if opts.HistoryFile == "" {
		opts.HistoryFile = e.cfg.HistoryFile
	}
	return NewSession(opts)
}

// ErrAccessDenied is the sentinel the platform can match with errors.Is to
// detect a policy denial. The interceptor currently returns denial via
// fmt.Errorf strings ("adssh: access denied: ..."); IsAccessDenied recognises
// those without any behaviour change, and errors.Is against ErrAccessDenied
// keeps working if the interceptor is later updated to wrap this sentinel.
var ErrAccessDenied = errors.New("access denied")

// ErrApprovalRequired is the sentinel for a command blocked by a governance
// gate (four-eyes dual approval or a change-management ticket). As with
// ErrAccessDenied it is matched by IsApprovalRequired against the current error
// strings without altering interceptor behaviour.
var ErrApprovalRequired = errors.New("approval required")

// IsAccessDenied reports whether err is a policy denial produced by the
// interceptor (or wraps ErrAccessDenied). Hosts use it to distinguish an
// authorization DENY from an execution FAILURE.
func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAccessDenied) {
		return true
	}
	return strings.Contains(err.Error(), "adssh: access denied")
}

// IsApprovalRequired reports whether err is a governance gate blocking the
// command: a four-eyes approval that was denied or timed out, or a
// change-management ticket that is missing or invalid. Hosts use it to prompt
// for approval rather than treating the command as a hard failure.
func IsApprovalRequired(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrApprovalRequired) {
		return true
	}
	msg := err.Error()
	return strings.HasPrefix(msg, "foureyes:") || strings.HasPrefix(msg, "cm:")
}
