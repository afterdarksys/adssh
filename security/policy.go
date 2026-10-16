package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"regexp"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"

	"github.com/open-policy-agent/opa/rego"
)

// PolicyContext is the input document passed to OPA evaluation.
type PolicyContext struct {
	User    string   `json:"user"`
	Groups  []string `json:"groups"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	// Capabilities are the capability groups the command touches (net, cloud,
	// fileops, proc, ...). Empty for shell-layer commands; populated for
	// governed Starlark builtins by ClassifyCapabilities. Surfaced to Rego as
	// input.capabilities so policies can gate whole classes of operation.
	Capabilities []string        `json:"capabilities,omitempty"`
	Time         string          `json:"time"`
	SessionID    string          `json:"session_id"`
	Elevation    *ElevationClaim `json:"elevation,omitempty"`
	Gateway      *GatewayClaim   `json:"gateway,omitempty"`
	Lease        *LeaseClaim     `json:"lease,omitempty"`
	Agent        *AgentClaim     `json:"agent,omitempty"`
	// IdentityUnknown is set when a non-empty session ID resolves to no bound
	// or registered principal. User is then empty and the gate denies before
	// policy runs. It is never sent to Rego.
	IdentityUnknown bool `json:"-"`
}

type ElevationClaim struct {
	Role      string `json:"role"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

type GatewayClaim struct {
	Action     string `json:"action"`
	Listen     string `json:"listen,omitempty"`
	Name       string `json:"name,omitempty"`
	Target     string `json:"target"`
	TargetHost string `json:"target_host"`
	TargetIP   string `json:"target_ip,omitempty"`
	TargetPort string `json:"target_port"`
}

type LeaseClaim struct {
	ID          string   `json:"id"`
	SourceType  string   `json:"source_type"`
	SourceName  string   `json:"source_name"`
	Destination string   `json:"destination"`
	TTLSeconds  int64    `json:"ttl_seconds"`
	Command     []string `json:"command"`
	Delivery    string   `json:"delivery"`
}

type AgentClaim struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Risk      string `json:"risk"`
	DryRun    bool   `json:"dry_run"`
	SessionID string `json:"session_id"`
}

type PolicyContextExtra struct {
	Lease *LeaseClaim
	Agent *AgentClaim
}

// LoadPolicy reads a Rego file and prepares the OPA query.
// Returns nil if the file does not exist (allow-all fallback).
func (e *Engine) LoadPolicy(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read policy: %w", err)
	}
	return e.compilePolicy(path, data)
}

// LoadPolicy reads a Rego file and prepares the OPA query.
// Returns nil if the file does not exist (allow-all fallback).
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func LoadPolicy(path string) error {
	return defaultEngine.LoadPolicy(path)
}

// EvaluatePolicy evaluates the loaded Rego policy against the given context.
//
// FAIL-CLOSED CONTRACT (rule 8 of SECURITY-RULES.md — on any ambiguity, deny):
//   - No policy loaded at all (preparedQuery == nil) => ALLOW. This is the
//     documented allow-by-default posture for a shell started without a policy;
//     strictness is opted into separately via EngineConfig.RequirePolicy, which
//     refuses to construct an engine with no policy. (TestEvaluatePolicy_NoPolicyLoaded)
//   - A policy IS loaded but evaluation errors => DENY (fail closed, T-01-02).
//   - A policy IS loaded and yields a decision document: DENY-BY-DEFAULT. Only an
//     explicit boolean `allow == true` permits the command. Every other outcome
//     denies:
//   - missing `allow` key (author forgot `default allow`)  => DENY (FIX #3)
//   - `allow` present but not a Go bool (e.g. "yes", 1)     => DENY (FIX #2)
//   - empty result set / non-object decision document       => DENY
//     A genuinely permissive policy must say so explicitly with `default allow =
//     true`, which yields allow==true here.
//
// deny_reason is surfaced whenever the policy sets it, including alongside
// allow==true (it is an advisory message; the boolean `allow` is authoritative).
func (e *Engine) EvaluatePolicy(pctx PolicyContext) (bool, string, error) {
	allowed, reason, _, err := e.evaluatePolicy(pctx)
	return allowed, reason, err
}

var roleNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,64}$`)

// errPolicyRemoteOnly denies every local evaluation in an SSH session
// process. Its engine is empty, so an evaluation there would allow.
var errPolicyRemoteOnly = errors.New("policy is evaluated by the listener; not available in this process")

func (e *Engine) evaluatePolicy(pctx PolicyContext) (bool, string, string, error) {
	if RemoteGateProcess() {
		return false, errPolicyRemoteOnly.Error(), "", errPolicyRemoteOnly
	}
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()

	// No policy loaded => allow-by-default (see contract above).
	if e.preparedQuery == nil {
		return true, "", "", nil
	}

	ctx := context.Background()
	input := map[string]interface{}{
		"user":         pctx.User,
		"groups":       pctx.Groups,
		"command":      pctx.Command,
		"args":         pctx.Args,
		"capabilities": pctx.Capabilities,
		"time":         pctx.Time,
		"session_id":   pctx.SessionID,
	}
	if pctx.Elevation != nil {
		input["elevation"] = map[string]interface{}{
			"role":       pctx.Elevation.Role,
			"reason":     pctx.Elevation.Reason,
			"expires_at": pctx.Elevation.ExpiresAt,
		}
	}
	if pctx.Gateway != nil {
		input["gateway"] = map[string]interface{}{
			"action":      pctx.Gateway.Action,
			"listen":      pctx.Gateway.Listen,
			"name":        pctx.Gateway.Name,
			"target":      pctx.Gateway.Target,
			"target_host": pctx.Gateway.TargetHost,
			"target_ip":   pctx.Gateway.TargetIP,
			"target_port": pctx.Gateway.TargetPort,
		}
	}
	if pctx.Lease != nil {
		input["lease"] = map[string]interface{}{
			"id":          pctx.Lease.ID,
			"source_type": pctx.Lease.SourceType,
			"source_name": pctx.Lease.SourceName,
			"destination": pctx.Lease.Destination,
			"ttl_seconds": pctx.Lease.TTLSeconds,
			"command":     pctx.Lease.Command,
			"delivery":    pctx.Lease.Delivery,
		}
	}
	if pctx.Agent != nil {
		input["agent"] = map[string]interface{}{
			"id":         pctx.Agent.ID,
			"kind":       pctx.Agent.Kind,
			"risk":       pctx.Agent.Risk,
			"dry_run":    pctx.Agent.DryRun,
			"session_id": pctx.Agent.SessionID,
		}
	}

	results, err := e.preparedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, "", "", fmt.Errorf("policy evaluation failed: %w", err)
	}

	// From here a policy IS loaded, so the posture is DENY-BY-DEFAULT: any
	// outcome that is not an explicit boolean allow==true is a denial.

	// A loaded policy that produces no result at all yields no decision — deny.
	// (data.adssh.authz on a real package is normally a defined object, so this
	// is the defensive "no decision" case, not the allow-all case; an allow-all
	// policy carries `default allow = true` and produces allow==true below.)
	if len(results) == 0 {
		return false, "policy: no decision (empty result set)", "", nil
	}

	// The decision document must be an object (the adssh.authz package). Anything
	// else is malformed — deny.
	resultMap, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return false, "policy: malformed decision document", "", nil
	}
	role := decisionRequiredRole(resultMap)

	// deny_reason is advisory; extract it up front so denials can surface it.
	denyReason := ""
	if v, ok := resultMap["deny_reason"].(string); ok {
		denyReason = v
	}

	allowVal, present := resultMap["allow"]
	if !present {
		// FIX #3: a loaded policy with no `allow` decision denies by default.
		if denyReason == "" {
			denyReason = "policy: deny by default (no allow decision)"
		}
		return false, denyReason, role, nil
	}
	allowed, isBool := allowVal.(bool)
	if !isBool {
		// FIX #2: a non-boolean `allow` must never be ignored — fail closed.
		return false, "policy: non-boolean allow", role, nil
	}

	return allowed, denyReason, role, nil
}

func decisionRequiredRole(resultMap map[string]interface{}) string {
	if role, ok := roleFromValue(resultMap["required_role"]); ok {
		return role
	}
	meta, _ := resultMap["metadata"].(map[string]interface{})
	if meta == nil {
		return ""
	}
	role, _ := roleFromValue(meta["required_role"])
	return role
}

func roleFromValue(value interface{}) (string, bool) {
	text, ok := value.(string)
	if !ok || !roleNamePattern.MatchString(text) {
		return "", false
	}
	return text, true
}

// EvaluatePolicy evaluates the loaded Rego policy against the given context.
// Returns (true, "", nil) if no policy is loaded.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func EvaluatePolicy(pctx PolicyContext) (bool, string, error) {
	return defaultEngine.EvaluatePolicy(pctx)
}

// BuildPolicyContext builds a PolicyContext against the process-global default
// engine. See (*Engine).buildPolicyContext for the resolution order.
func BuildPolicyContext(command string, args []string, sessionID string) PolicyContext {
	return defaultEngine.buildPolicyContext(command, args, sessionID)
}

// buildPolicyContext resolves the principal for sessionID in this order:
//  1. the identity bound on this engine (BindSessionIdentity);
//  2. the process sys session registry (SSH and local sessions), with the
//     active elevation and managed-agent claims;
//  3. for an empty sessionID only, the current OS user and its groups;
//  4. otherwise IdentityUnknown with an empty User.
//
// Threats: a named session never falls back to the process identity, so an
// embedded session declared for another user cannot authorize as the host
// account. It trusts whoever bound or registered the identity.
func (e *Engine) buildPolicyContext(command string, args []string, sessionID string) PolicyContext {
	pctx := PolicyContext{
		Command:   command,
		Args:      args,
		Time:      time.Now().UTC().Format(time.RFC3339),
		SessionID: sessionID,
	}

	if sessionID != "" {
		if user, groups, ok := e.boundIdentity(sessionID); ok {
			pctx.User = user
			pctx.Groups = groups
			return pctx
		}
		if session := sys.GetSession(sessionID); session != nil {
			pctx.User = session.User
			pctx.Groups = append([]string(nil), session.Principals...)
			if elevation := session.ActiveElevation(); elevation != nil {
				pctx.Groups = append(pctx.Groups, elevation.Role)
				pctx.Elevation = &ElevationClaim{
					Role:      elevation.Role,
					Reason:    elevation.Reason,
					ExpiresAt: elevation.ExpiresAt.UTC().Format(time.RFC3339),
				}
			}
			if agent := session.ManagedAgent(); agent != nil && time.Now().Before(agent.ExpiresAt) {
				pctx.Agent = &AgentClaim{
					ID:        agent.ID,
					Kind:      agentKindCloud,
					Risk:      "worktree",
					SessionID: session.ID,
				}
			}
			return pctx
		}
		pctx.IdentityUnknown = true
		return pctx
	}

	pctx.User, pctx.Groups = CurrentOSIdentity()
	return pctx
}

// CurrentOSIdentity returns the process user's name and group names. It
// returns an empty user when the OS lookup fails.
func CurrentOSIdentity() (string, []string) {
	u, err := osuser.Current()
	if err != nil {
		return "", nil
	}
	var groups []string
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			if g, err := osuser.LookupGroupId(gid); err == nil {
				groups = append(groups, g.Name)
			}
		}
	}
	return u.Username, groups
}
