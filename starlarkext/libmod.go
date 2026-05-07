package starlarkext

import (
	"fmt"
	"go.starlark.net/starlark"
	"plugin"
)

// AdsshPlugin is the interface that dynamic Go plugins must implement
type AdsshPlugin interface {
	Init(globals starlark.StringDict) error
}

// createLoadPlugin creates the sys.load_plugin builtin
func createLoadPlugin(globals starlark.StringDict) *starlark.Builtin {
	return starlark.NewBuiltin("load_plugin", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path); err != nil {
			return starlark.None, err
		}

		p, err := plugin.Open(path)
		if err != nil {
			return starlark.None, fmt.Errorf("failed to open plugin %s: %v", path, err)
		}

		sym, err := p.Lookup("Plugin")
		if err != nil {
			return starlark.None, fmt.Errorf("failed to find 'Plugin' symbol in %s: %v", path, err)
		}

		adsshPlugin, ok := sym.(AdsshPlugin)
		if !ok {
			return starlark.None, fmt.Errorf("symbol 'Plugin' in %s does not implement AdsshPlugin interface", path)
		}

		if err := adsshPlugin.Init(globals); err != nil {
			return starlark.None, fmt.Errorf("plugin initialization failed: %v", err)
		}

		return starlark.True, nil
	})
}
