package main

import (
	"fmt"
	"go.starlark.net/starlark"
)

// ExamplePlugin is a concrete implementation of starlarkext.AdsshPlugin
type ExamplePlugin struct{}

// Name returns the name of the plugin
func (p *ExamplePlugin) Name() string {
	return "math_accel"
}

// Init sets up the Starlark dictionary injected into the environment
func (p *ExamplePlugin) Init(globals starlark.StringDict) error {
	fmt.Println("[Plugin] math_accel initialized natively via CGO!")

	dict := starlark.NewDict(1)

	// A high-performance native function exposed to Starlark
	dict.SetKey(starlark.String("fibonacci"), starlark.NewBuiltin("fibonacci", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var n int
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "n", &n); err != nil {
			return nil, err
		}

		res := fib(n)
		return starlark.MakeInt(res), nil
	}))

	// Inject into the global plugins registry to bypass Starlark parse-time static checks
	if pluginsVal, ok := globals["plugins"]; ok {
		if pluginsDict, ok := pluginsVal.(*starlark.Dict); ok {
			pluginsDict.SetKey(starlark.String("math_accel"), dict)
		}
	}
	return nil
}

// Simple internal native Go function that runs outside of the VM
func fib(n int) int {
	if n <= 1 {
		return n
	}
	return fib(n-1) + fib(n-2)
}

// Export the plugin struct exactly as expected by the Go plugin loader
var Plugin ExamplePlugin
