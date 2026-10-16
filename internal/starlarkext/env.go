package starlarkext

import (
	"fmt"
	"os"

	"github.com/afterdarksys/adssh/internal/sys"

	"go.starlark.net/starlark"
)

// Threats: a session-scoped sys.setenv must not write the process
// environment. A missing session fails closed and does not call os.Setenv.
// The error does not include the value. An empty session id is the local
// operator path and still uses the process environment.

func getenvBuiltin(sessionID string) starlark.Value {
	return starlark.NewBuiltin("getenv", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var key string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key); err != nil {
			return nil, err
		}
		if sessionID == "" {
			val, _ := os.LookupEnv(key)
			return starlark.String(val), nil
		}
		s := sys.GetSession(sessionID)
		if s == nil {
			return nil, fmt.Errorf("adssh: session %s is not registered", sessionID)
		}
		val, _ := s.LookupEnv(key)
		return starlark.String(val), nil
	})
}

func setenvBuiltin(sessionID string) starlark.Value {
	return starlark.NewBuiltin("setenv", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var key, val string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "val", &val); err != nil {
			return nil, err
		}
		if sessionID == "" {
			if err := os.Setenv(key, val); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}
		s := sys.GetSession(sessionID)
		if s == nil {
			return nil, fmt.Errorf("adssh: session %s is not registered", sessionID)
		}
		if err := s.SetEnv(key, val); err != nil {
			return nil, err
		}
		return starlark.None, nil
	})
}
