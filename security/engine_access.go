package security

import "context"

// EngineFromContext returns the engine DispatchVBin bound to ctx, or nil when
// ctx carries none. Virtual binaries outside this package (internal/grid) use
// it to evaluate policy on the engine that dispatched them.
func EngineFromContext(ctx context.Context) *Engine {
	if ctx == nil {
		return nil
	}
	engine, _ := ctx.Value(engineCtxKey).(*Engine)
	return engine
}

// BuildPolicyContext resolves the principal for a command under sessionID on
// this engine, in the order documented on buildPolicyContext. It evaluates
// nothing and writes no audit entry.
func (e *Engine) BuildPolicyContext(command string, args []string, sessionID string) PolicyContext {
	return e.buildPolicyContext(command, args, sessionID)
}
