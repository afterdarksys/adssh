package security

import (
	"context"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

// EngineConfig configures a security Engine constructed via NewEngine.
//
// Every field is optional; a zero-value EngineConfig produces an engine that
// runs allow-by-default (no policy), with no audit log, no hash chain and no
// entitlements loaded — the same posture the process-global default engine has
// before its Init* shims are called.
type EngineConfig struct {
	// PolicyPath is a path to a Rego policy file. Ignored when PolicySource is
	// non-empty.
	PolicyPath string
	// PolicySource, when non-empty, is inline Rego that takes precedence over
	// PolicyPath. Use it to construct an engine without touching the filesystem.
	PolicySource []byte
	// RequirePolicy makes NewEngine FAIL CLOSED when no policy is configured or
	// the configured PolicyPath does not exist. When RequirePolicy is false and
	// no policy is configured/found, the engine runs ALLOW-BY-DEFAULT exactly as
	// the shell does today (EvaluatePolicy returns (true, "", nil) with no
	// prepared query loaded).
	RequirePolicy bool

	// AuditLogPath, when non-empty, initializes the flat audit logger at that
	// path. AuditLogURL/AuditLogToken configure the optional remote SIEM sink.
	AuditLogPath  string
	AuditLogURL   string
	AuditLogToken string

	// ChainPath/ChainKeyPath/SessionID initialize the HMAC hash-chain ledger.
	// ChainPath empty leaves the chain uninitialised (AppendChain is a no-op).
	ChainPath    string
	ChainKeyPath string
	SessionID    string

	// FourEyesDir is the base directory for four-eyes IPC files. Empty means the
	// engine derives it from HOME at call time via FourEyesDir(), matching the
	// default engine's behavior.
	FourEyesDir string

	// EntitlementsPath, when non-empty, loads the RBAC entitlements file.
	// LoadEntitlements is fail-closed: a missing file is an error.
	EntitlementsPath string

	// Restricted enables restricted-mode command checks in the interceptor.
	Restricted bool
}

// Engine holds all of the security state that used to live in package-level
// globals: the prepared Rego query, the audit logger, the HMAC chain state, the
// active change-management ticket, the four-eyes base directory, the RBAC
// entitlements, the virtual-binary registry, and the restricted-mode flag.
//
// Two Engines in one process share NOTHING mutable: each has its own maps,
// slices and mutexes, so concurrent sessions bound to different engines cannot
// observe or corrupt each other's state. Every field group is guarded by the
// mutex declared alongside it, exactly as the corresponding package global was.
type Engine struct {
	// policy
	policyMu      sync.RWMutex
	preparedQuery *rego.PreparedEvalQuery

	// audit log (set once at init, read thereafter — matches legacy globals)
	auditLogger      *log.Logger
	remoteAuditURL   string
	remoteAuditToken string
	syslogWriter     *syslog.Writer

	// hmac chain — chainMu also guards auditChangeID (as it did as a global)
	chainMu       sync.Mutex
	chainPath     string
	chainKey      []byte
	chainSession  string
	auditChangeID string

	// active change-management tickets, keyed by authenticated session ID.
	// The empty key is retained for legacy single-session package APIs.
	cmMu      sync.Mutex
	cmTickets map[string]cmTicketState

	// four-eyes base directory ("" => derive from HOME via FourEyesDir())
	fourEyesDir string

	// entitlements (RBAC)
	entitlementsMu     sync.RWMutex
	entitlements       EntitlementsConfig
	entitlementsLoaded bool

	// virtual binary registry
	vbinMu sync.RWMutex
	vbins  map[string]VirtualBinary

	// restricted mode
	restricted bool

	// last denial, keyed by authenticated session ID.
	denialMu    sync.RWMutex
	lastDenials map[string]CommandExplanation
}

// defaultEngine is the process-global engine that every package-level shim
// delegates to. It is created before any init() function runs (package-level
// variable initialisation happens before init), so the vbin_*.go init()
// Register calls populate its registry directly.
var defaultEngine = newDefaultEngine()

// newDefaultEngine builds the process-global engine with a zero-value config:
// no policy (allow-by-default), no audit/chain/entitlements, unrestricted, and
// an empty vbin registry that init() Register calls fill in.
func newDefaultEngine() *Engine {
	return &Engine{
		vbins:       map[string]VirtualBinary{},
		cmTickets:   map[string]cmTicketState{},
		lastDenials: map[string]CommandExplanation{},
	}
}

// DefaultEngine returns the process-global default engine that every
// package-level function delegates to. The built-in binaries (adssh, adssh-mcp)
// use it to route the paths that still resolve the package default — the SSH
// server, the Starlark exec builtins and the completer — through the same
// engine their sessions authorize against. Embedded hosts should NOT rely on it:
// build isolated engines with NewEngine (or engine.New) instead.
func DefaultEngine() *Engine { return defaultEngine }

// SetDefaultEngine replaces the process-global default engine. It is intended
// for the binaries' single-tenant startup: after building a configured engine,
// they point the default at it so every package-default path (SSH sessions,
// exec builtins, sec.audit) shares that one configured engine. Call it once at
// startup, before any session or server is created; it is NOT safe to call
// concurrently with running sessions, and multi-tenant hosts must never use it.
func SetDefaultEngine(e *Engine) {
	if e != nil {
		defaultEngine = e
	}
}

// NewEngine builds an isolated Engine from cfg. It FAILS CLOSED: malformed Rego
// (via PolicySource or PolicyPath) returns an error, and RequirePolicy with no
// policy configured/found returns an error. When RequirePolicy is false and no
// policy is configured, the engine runs allow-by-default.
//
// The new engine's vbin registry is seeded by copying the package registry that
// init() Register calls built (i.e. the default engine's registry), so every
// engine sees the built-in virtual binaries but registrations made afterward on
// one engine are invisible to the others.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	e := &Engine{
		restricted:  cfg.Restricted,
		fourEyesDir: cfg.FourEyesDir,
		vbins:       map[string]VirtualBinary{},
		cmTickets:   map[string]cmTicketState{},
		lastDenials: map[string]CommandExplanation{},
	}

	// Seed the vbin registry from the package default (built by init()).
	defaultEngine.vbinMu.RLock()
	for k, v := range defaultEngine.vbins {
		e.vbins[k] = v
	}
	defaultEngine.vbinMu.RUnlock()

	// Policy — inline source takes precedence over a path. Fail closed.
	switch {
	case len(cfg.PolicySource) > 0:
		src := "inline"
		if cfg.PolicyPath != "" {
			src = cfg.PolicyPath
		}
		if err := e.compilePolicy(src, cfg.PolicySource); err != nil {
			return nil, err
		}
	case cfg.PolicyPath != "":
		data, err := os.ReadFile(cfg.PolicyPath)
		if err != nil {
			if os.IsNotExist(err) {
				if cfg.RequirePolicy {
					return nil, fmt.Errorf("engine: RequirePolicy set but policy file %q does not exist", cfg.PolicyPath)
				}
				break // allow-by-default
			}
			return nil, fmt.Errorf("failed to read policy: %w", err)
		}
		if err := e.compilePolicy(cfg.PolicyPath, data); err != nil {
			return nil, err
		}
	default:
		if cfg.RequirePolicy {
			return nil, fmt.Errorf("engine: RequirePolicy set but no policy configured")
		}
	}

	if cfg.AuditLogPath != "" {
		e.InitAuditLog(cfg.AuditLogPath, cfg.AuditLogURL, cfg.AuditLogToken)
	}
	if cfg.ChainPath != "" {
		e.InitChain(cfg.ChainPath, cfg.ChainKeyPath, cfg.SessionID)
	}
	if cfg.EntitlementsPath != "" {
		if err := e.LoadEntitlements(cfg.EntitlementsPath); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// compilePolicy compiles Rego source and, on success, installs it as the
// engine's prepared query. On failure the previously-loaded policy (if any) is
// left untouched — the caller decides whether that is an error.
func (e *Engine) compilePolicy(name string, data []byte) error {
	ctx := context.Background()
	query, err := rego.New(
		rego.Query("data.adssh.authz"),
		rego.Module(name, string(data)),
		// Fail closed: surface builtin runtime errors (div-by-zero, bad
		// to_number, etc.) as Eval errors instead of silently treating the
		// rule as undefined.
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}

	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	e.preparedQuery = &query
	return nil
}
