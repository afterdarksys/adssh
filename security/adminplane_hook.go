package security

// The admin plane is the daily-path gate: alias translation, quarantine,
// and agent budgets. The enterprise build installs it from init. A core
// build leaves the hooks nil, which is a no-op, so today's shell behavior
// stays. This is not the approval gate. A missing admin-plane hook must
// not deny ordinary commands.
//
// Threats: an embedder or a second init must not replace the installed
// hook. SetAdminPlane rejects nil and a second call. The nil hook does not
// rewrite argv and does not deny. It does not itself decide policy.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/interp"
)

type adminRewriteFunc func(args []string) (rewritten []string, note string, err error)
type adminGateFunc func(e *Engine, ctx context.Context, sessionID string, args []string) error

var (
	adminPlaneMu        sync.Mutex
	adminPlaneRewrite   adminRewriteFunc
	adminPlaneGate      adminGateFunc
	adminPlaneInstalled bool
)

// SetAdminPlane installs the rewrite and the gate for every engine in the
// process. It can be called once. A nil function or a second call returns
// an error.
func SetAdminPlane(rewrite adminRewriteFunc, gate adminGateFunc) error {
	if rewrite == nil || gate == nil {
		return errors.New("security: SetAdminPlane: nil hook")
	}
	adminPlaneMu.Lock()
	defer adminPlaneMu.Unlock()
	if adminPlaneInstalled {
		return errors.New("security: SetAdminPlane: a hook is already installed")
	}
	adminPlaneRewrite = rewrite
	adminPlaneGate = gate
	adminPlaneInstalled = true
	return nil
}

func currentAdminPlaneRewrite(args []string) ([]string, string, error) {
	adminPlaneMu.Lock()
	fn := adminPlaneRewrite
	adminPlaneMu.Unlock()
	if fn == nil {
		return args, "", nil
	}
	return fn(args)
}

func currentAdminPlaneGate(e *Engine, ctx context.Context, sessionID string, args []string) error {
	adminPlaneMu.Lock()
	fn := adminPlaneGate
	adminPlaneMu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(e, ctx, sessionID, args)
}

// printAliasNote writes the alias translation after the gate has allowed
// the rewritten command. interp.HandlerCtx panics when the context has no
// handler, and a nil stderr must not be written.
func printAliasNote(ctx context.Context, note string) {
	if note == "" {
		return
	}
	defer func() { _ = recover() }()
	hc := interp.HandlerCtx(ctx)
	if hc.Stderr == nil {
		return
	}
	fmt.Fprintf(hc.Stderr, "%s\n", note)
}

func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// adminPlaneBlocked is installed with the enterprise gate. mutationBlocked
// is true only when both the gate and this predicate are set, so a core
// build never refuses package.
var adminPlaneBlocked func(ctx context.Context) bool

// mutationBlocked reports whether the admin plane refuses a mutating verb
// such as package. A core build has no gate, so this is false.
func mutationBlocked(ctx context.Context) bool {
	adminPlaneMu.Lock()
	gate := adminPlaneGate
	blocked := adminPlaneBlocked
	adminPlaneMu.Unlock()
	if gate == nil || blocked == nil {
		return false
	}
	return blocked(ctx)
}
