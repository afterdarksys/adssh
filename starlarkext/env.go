package starlarkext

import (
	"os"

	"go.starlark.net/starlark"
)

func builtinGetEnv(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key); err != nil {
		return nil, err
	}
	val := os.Getenv(key)
	return starlark.String(val), nil
}

func builtinSetEnv(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, val string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "val", &val); err != nil {
		return nil, err
	}
	os.Setenv(key, val)
	return starlark.None, nil
}
