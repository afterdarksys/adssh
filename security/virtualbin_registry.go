package security

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

// VirtualBinary is the standard interface for all adssh virtual binaries.
// Add a new virtual binary by implementing this interface and calling
// Register in an init() function.
type VirtualBinary interface {
	Name() string
	Description() string
	Usage() string
	Run(ctx context.Context, args []string) error
}

// Register adds a virtual binary to the engine's registry. Call from init()
// (via the package-level Register shim) or at runtime. It panics on
// programmer error (empty/invalid/duplicate name), matching the legacy global.
func (e *Engine) Register(vb VirtualBinary) {
	name := vb.Name()
	if strings.TrimSpace(name) == "" {
		panic("adssh: virtual binary name cannot be empty")
	}
	if strings.ContainsAny(name, " \t\r\n/") {
		panic(fmt.Sprintf("adssh: invalid virtual binary name %q", name))
	}
	e.vbinMu.Lock()
	defer e.vbinMu.Unlock()
	if _, exists := e.vbins[name]; exists {
		panic(fmt.Sprintf("adssh: duplicate virtual binary %q", name))
	}
	e.vbins[name] = vb
}

// Register adds a virtual binary to the process-global registry. Call from init().
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func Register(vb VirtualBinary) {
	defaultEngine.Register(vb)
}

// Lookup returns the virtual binary registered under name.
func (e *Engine) Lookup(name string) (VirtualBinary, bool) {
	e.vbinMu.RLock()
	defer e.vbinMu.RUnlock()
	vb, ok := e.vbins[name]
	return vb, ok
}

// Lookup returns the virtual binary registered under name.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func Lookup(name string) (VirtualBinary, bool) {
	return defaultEngine.Lookup(name)
}

// ListVBins returns all registered virtual binaries sorted by name.
func (e *Engine) ListVBins() []VirtualBinary {
	e.vbinMu.RLock()
	out := make([]VirtualBinary, 0, len(e.vbins))
	for _, vb := range e.vbins {
		out = append(out, vb)
	}
	e.vbinMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// ListVBins returns all registered virtual binaries sorted by name.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func ListVBins() []VirtualBinary {
	return defaultEngine.ListVBins()
}

// DispatchVBin runs a virtual binary, handling --help automatically. It holds no
// engine state (vb is supplied by the caller) but is exposed as a method for
// API symmetry.
func (e *Engine) DispatchVBin(ctx context.Context, vb VirtualBinary, args []string) error {
	return DispatchVBin(ctx, vb, args)
}

// DispatchVBin runs a virtual binary, handling --help automatically.
func DispatchVBin(ctx context.Context, vb VirtualBinary, args []string) error {
	if len(args) > 1 && (args[1] == "--help" || args[1] == "help") {
		hc := interp.HandlerCtx(ctx)
		fmt.Fprintf(hc.Stdout, "%s — %s\nUsage: %s\n", vb.Name(), vb.Description(), vb.Usage())
		return nil
	}
	return vb.Run(ctx, args)
}

// context key for sessionID threading through virtual binary dispatch.
type vbinContextKey string

const sessionIDCtxKey vbinContextKey = "sessionID"

// WithSessionID stores a session ID in the context for virtual binaries that need it.
func WithSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionIDCtxKey, id)
}

// SessionIDFromContext retrieves the session ID stored by WithSessionID.
func SessionIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(sessionIDCtxKey).(string)
	return v
}
