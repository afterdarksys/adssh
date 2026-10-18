package security

import (
	"context"
	"fmt"
	"log/syslog"
	"os"
	"slices"
	"sync"

	"github.com/open-policy-agent/opa/rego"
	v1ast "github.com/open-policy-agent/opa/v1/ast"
	v1rego "github.com/open-policy-agent/opa/v1/rego"
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

	// audit log. auditMu guards auditFile. The file is opened once at init.
	auditMu          sync.Mutex
	auditFile        *os.File
	remoteAuditURL   string
	remoteAuditToken string
	syslogWriter     *syslog.Writer

	// hmac chain — chainMu also guards auditChangeID and the tail cache.
	// The cache is valid for one process and one ledger. Another process
	// appending to the same file is outside the contract.
	chainMu       sync.Mutex
	chainPath     string
	chainKey      []byte
	chainSession  string
	auditChangeID string

	// change-management patterns. The tickets themselves are enterprise
	// state (cm_ee.go) and live in ext.
	cmMu sync.Mutex
	// cmDefaultPatterns is ADSSH_CM_PATTERNS, read once when the engine is
	// built; cmPatterns holds what each session added with cm require.
	cmDefaultPatterns []string
	cmPatterns        map[string][]string

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

	// identities binds a session ID to the principal it authorizes as. It is
	// consulted before the process-global sys session registry, so an embedded
	// session never borrows the host identity or another engine's binding.
	identityMu sync.RWMutex
	identities map[string]sessionIdentity

	// ext holds per-engine state that *_ee.go files create on first use
	// (see extension). The core build leaves it empty.
	extMu sync.Mutex
	ext   map[string]any
}

// extension returns the per-engine value stored under key, creating it with
// create on first use. Enterprise files keep their engine state here so the
// core Engine type does not name enterprise types.
func (e *Engine) extension(key string, create func() any) any {
	e.extMu.Lock()
	defer e.extMu.Unlock()
	if v, ok := e.ext[key]; ok {
		return v
	}
	if e.ext == nil {
		e.ext = map[string]any{}
	}
	v := create()
	e.ext[key] = v
	return v
}

// sessionIdentity is the principal bound to one session ID on one engine.
// refs counts identical bindings so the last Unbind removes it.
type sessionIdentity struct {
	user   string
	groups []string
	refs   int
}

// BindSessionIdentity binds sessionID to user and groups on this engine. Policy
// evaluation for that session ID then sees exactly this principal.
//
// Threats: it stops a named session from authorizing as the host process
// user and stops a second caller from rebinding a live session ID to another
// principal. It does not authenticate user; the host must. Rebinding an ID to
// the same principal is counted and needs a matching Unbind.
func (e *Engine) BindSessionIdentity(sessionID, user string, groups []string) error {
	if sessionID == "" {
		return fmt.Errorf("adssh: session identity: empty session ID")
	}
	if user == "" {
		return fmt.Errorf("adssh: session identity: empty user")
	}
	e.identityMu.Lock()
	defer e.identityMu.Unlock()
	if e.identities == nil {
		e.identities = map[string]sessionIdentity{}
	}
	if cur, ok := e.identities[sessionID]; ok {
		if cur.user != user || !slices.Equal(cur.groups, groups) {
			return fmt.Errorf("adssh: session identity: session %s is already bound to another principal", sessionID)
		}
		cur.refs++
		e.identities[sessionID] = cur
		return nil
	}
	e.identities[sessionID] = sessionIdentity{
		user:   user,
		groups: append([]string(nil), groups...),
		refs:   1,
	}
	return nil
}

// UnbindSessionIdentity releases one binding of sessionID. When the last
// binding goes, the session ID is unknown to this engine again and named
// gate calls for it are denied.
func (e *Engine) UnbindSessionIdentity(sessionID string) {
	e.identityMu.Lock()
	defer e.identityMu.Unlock()
	cur, ok := e.identities[sessionID]
	if !ok {
		return
	}
	cur.refs--
	if cur.refs <= 0 {
		delete(e.identities, sessionID)
		return
	}
	e.identities[sessionID] = cur
}

func (e *Engine) boundIdentity(sessionID string) (string, []string, bool) {
	e.identityMu.RLock()
	defer e.identityMu.RUnlock()
	cur, ok := e.identities[sessionID]
	if !ok {
		return "", nil, false
	}
	return cur.user, append([]string(nil), cur.groups...), true
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
		lastDenials: map[string]CommandExplanation{},
		identities:  map[string]sessionIdentity{},

		cmDefaultPatterns: parseCMPatterns(os.Getenv("ADSSH_CM_PATTERNS")),
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
		lastDenials: map[string]CommandExplanation{},
		identities:  map[string]sessionIdentity{},

		cmDefaultPatterns: parseCMPatterns(os.Getenv("ADSSH_CM_PATTERNS")),
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

	if cfg.AuditLogURL != "" && cfg.AuditLogPath == "" {
		return nil, fmt.Errorf("engine: AuditLogURL is set but AuditLogPath is empty; the webhook sink needs the audit logger")
	}
	if cfg.AuditLogPath != "" {
		if err := e.InitAuditLog(cfg.AuditLogPath, cfg.AuditLogURL, cfg.AuditLogToken); err != nil {
			return nil, err
		}
	}
	if cfg.ChainPath != "" {
		if err := e.InitChain(cfg.ChainPath, cfg.ChainKeyPath, cfg.SessionID); err != nil {
			return nil, err
		}
	}
	if cfg.EntitlementsPath != "" {
		if err := e.LoadEntitlements(cfg.EntitlementsPath); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// parsePolicyModule parses a policy as Rego v1 when it parses that way, else
// as v0, the syntax the shipped policies use.
// Threats: compiled as v0, a v1 rule such as `allow = true if { ... }` loads
// without error and does not mean what it says (a deny-by-default policy
// with that rule allowed every command, the excluded one included). A source
// that parses as v1 means the same in v0 wherever v0 also accepts it, so
// preferring v1 changes no working v0 policy; a v0-only body (no `if`) does
// not parse as v1 and keeps v0.
//
// The v0 fallback parses with every future keyword (if, contains, in,
// every) on: one v0-only rule in a file must not turn the file's v1 rules
// back into v0, where `allow = true if { ... }` does not mean what it says.
// A v0 policy that uses one of those words as a name fails to load.
func parsePolicyModule(name string, data []byte) (*v1ast.Module, v1ast.RegoVersion, error) {
	if m, err := v1ast.ParseModuleWithOpts(name, string(data), v1ast.ParserOptions{RegoVersion: v1ast.RegoV1}); err == nil {
		return m, v1ast.RegoV1, nil
	}
	m, err := v1ast.ParseModuleWithOpts(name, string(data), v1ast.ParserOptions{RegoVersion: v1ast.RegoV0, AllFutureKeywords: true})
	return m, v1ast.RegoV0, err
}

// compilePolicy compiles Rego source and, on success, installs it as the
// engine's prepared query. On failure the previously-loaded policy (if any) is
// left untouched — the caller decides whether that is an error.
func (e *Engine) compilePolicy(name string, data []byte) error {
	ctx := context.Background()
	module, version, err := parsePolicyModule(name, data)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}
	query, err := v1rego.New(
		v1rego.Query("data.adssh.authz"),
		v1rego.ParsedModule(module),
		v1rego.SetRegoVersion(version),
		// Fail closed: surface builtin runtime errors (div-by-zero, bad
		// to_number, etc.) as Eval errors instead of silently treating the
		// rule as undefined.
		v1rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}

	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	e.preparedQuery = &query
	return nil
}

// PolicyLoaded reports whether a Rego policy is installed. The shell's
// allow-by-default posture stays in EvaluatePolicy. Callers that must fail
// closed, including sah/1 execute, check this instead of treating a nil
// policy as allow.
func (e *Engine) PolicyLoaded() bool {
	if e == nil {
		return false
	}
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	return e.preparedQuery != nil
}
