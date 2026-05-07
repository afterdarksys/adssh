package security

import (
	"context"
	"fmt"
	"sort"

	"mvdan.cc/sh/v3/interp"
)

// VirtualBinary is the standard interface for all adssh virtual binaries.
// Add a new virtual binary by implementing this interface and calling
// Register in an init() function.
type VirtualBinary interface {
	Name()        string
	Description() string
	Usage()       string
	Run(ctx context.Context, args []string) error
}

var vbinRegistry = map[string]VirtualBinary{}

// Register adds a virtual binary to the registry. Call from init().
func Register(vb VirtualBinary) {
	vbinRegistry[vb.Name()] = vb
}

// Lookup returns the virtual binary registered under name.
func Lookup(name string) (VirtualBinary, bool) {
	vb, ok := vbinRegistry[name]
	return vb, ok
}

// ListVBins returns all registered virtual binaries sorted by name.
func ListVBins() []VirtualBinary {
	out := make([]VirtualBinary, 0, len(vbinRegistry))
	for _, vb := range vbinRegistry {
		out = append(out, vb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
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
