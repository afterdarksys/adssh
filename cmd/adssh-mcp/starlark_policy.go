package main

import (
	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

type mcpSecurityEngineContextKey struct{}

func governStarlarkGlobals(sec *security.Engine, globals starlark.StringDict) starlark.StringDict {
	return starlarkext.GovernStarlarkGlobals(sec, globals)
}
