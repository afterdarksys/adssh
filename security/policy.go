package security

import (
	"context"
	"fmt"
	"os"
	osuser "os/user"
	"time"

	"github.com/afterdarksys/adssh/sys"

	"github.com/open-policy-agent/opa/rego"
)

// PolicyContext is the input document passed to OPA evaluation.
type PolicyContext struct {
	User      string   `json:"user"`
	Groups    []string `json:"groups"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Time      string   `json:"time"`
	SessionID string   `json:"session_id"`
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
// Returns (true, "", nil) if no policy is loaded.
// Returns (false, "", err) on evaluation error — fail closed on errors (T-01-02).
func (e *Engine) EvaluatePolicy(pctx PolicyContext) (bool, string, error) {
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()

	if e.preparedQuery == nil {
		return true, "", nil
	}

	ctx := context.Background()
	input := map[string]interface{}{
		"user":       pctx.User,
		"groups":     pctx.Groups,
		"command":    pctx.Command,
		"args":       pctx.Args,
		"time":       pctx.Time,
		"session_id": pctx.SessionID,
	}

	results, err := e.preparedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, "", fmt.Errorf("policy evaluation failed: %w", err)
	}

	if len(results) == 0 {
		return true, "", nil
	}

	// Extract allow and deny_reason from data.adssh.authz result set
	resultMap, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return true, "", nil
	}

	allowed := true
	if v, ok := resultMap["allow"].(bool); ok {
		allowed = v
	}

	denyReason := ""
	if v, ok := resultMap["deny_reason"].(string); ok {
		denyReason = v
	}

	return allowed, denyReason, nil
}

// EvaluatePolicy evaluates the loaded Rego policy against the given context.
// Returns (true, "", nil) if no policy is loaded.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func EvaluatePolicy(pctx PolicyContext) (bool, string, error) {
	return defaultEngine.EvaluatePolicy(pctx)
}

// BuildPolicyContext creates a PolicyContext from the current OS user and command.
// It is stateless (no engine state), so it remains a plain package function.
func BuildPolicyContext(command string, args []string, sessionID string) PolicyContext {
	pctx := PolicyContext{
		Command:   command,
		Args:      args,
		Time:      time.Now().UTC().Format(time.RFC3339),
		SessionID: sessionID,
	}

	if sessionID != "" {
		if session := sys.GetSession(sessionID); session != nil {
			pctx.User = session.User
			pctx.Groups = session.Principals
			return pctx
		}
	}

	if u, err := osuser.Current(); err == nil {
		pctx.User = u.Username
		if gids, err := u.GroupIds(); err == nil {
			for _, gid := range gids {
				if g, err := osuser.LookupGroupId(gid); err == nil {
					pctx.Groups = append(pctx.Groups, g.Name)
				}
			}
		}
	}

	return pctx
}
