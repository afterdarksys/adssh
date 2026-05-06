package security

import (
	"context"
	"fmt"
	osuser "os/user"
	"os"
	"sync"
	"time"

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

var (
	preparedQuery *rego.PreparedEvalQuery
	policyMu      sync.RWMutex
)

// LoadPolicy reads a Rego file and prepares the OPA query.
// Returns nil if the file does not exist (allow-all fallback).
func LoadPolicy(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read policy: %w", err)
	}

	ctx := context.Background()
	query, err := rego.New(
		rego.Query("data.adssh.authz"),
		rego.Module(path, string(data)),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}

	policyMu.Lock()
	defer policyMu.Unlock()
	preparedQuery = &query
	return nil
}

// EvaluatePolicy evaluates the loaded Rego policy against the given context.
// Returns (true, "", nil) if no policy is loaded.
// Returns (false, "", err) on evaluation error — fail closed on errors (T-01-02).
func EvaluatePolicy(pctx PolicyContext) (bool, string, error) {
	policyMu.RLock()
	defer policyMu.RUnlock()

	if preparedQuery == nil {
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

	results, err := preparedQuery.Eval(ctx, rego.EvalInput(input))
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

// BuildPolicyContext creates a PolicyContext from the current OS user and command.
func BuildPolicyContext(command string, args []string, sessionID string) PolicyContext {
	pctx := PolicyContext{
		Command:   command,
		Args:      args,
		Time:      time.Now().UTC().Format(time.RFC3339),
		SessionID: sessionID,
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
