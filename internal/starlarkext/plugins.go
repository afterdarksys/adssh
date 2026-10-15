package starlarkext

import (
	"fmt"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// createLoadPlugins loads checked Starlark plugins into env.
// Argument errors do not open the plugins directory.
func createLoadPlugins(env starlark.StringDict) *starlark.Builtin {
	return starlark.NewBuiltin("load_plugins", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var names *starlark.List
		var all bool
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "names?", &names, "all?", &all); err != nil {
			return nil, err
		}
		if names != nil && all {
			return nil, fmt.Errorf("load_plugins: pass names or all=True, not both")
		}
		if names == nil && !all {
			return nil, fmt.Errorf("load_plugins: pass names or all=True")
		}
		var nameList []string
		if names != nil {
			if names.Len() == 0 {
				return nil, fmt.Errorf("load_plugins: names must not be empty")
			}
			iter := names.Iterate()
			defer iter.Done()
			var item starlark.Value
			for iter.Next(&item) {
				text, ok := item.(starlark.String)
				if !ok {
					return nil, fmt.Errorf("plugin: invalid name")
				}
				nameList = append(nameList, string(text))
			}
		}
		loaded, err := security.LoadStarlarkPlugins(env, nameList, all)
		if err != nil {
			return nil, err
		}
		vals := make([]starlark.Value, len(loaded))
		for i, name := range loaded {
			vals[i] = starlark.String(name)
		}
		return starlark.NewList(vals), nil
	})
}
