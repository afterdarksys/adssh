package security

import (
	"context"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
)

func BashInterceptor(restricted bool, globals starlark.StringDict) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			cmd := strings.Join(args, " ")
			LogCommand("BASH", cmd)

			// 0. Rego policy evaluation (primary authorization)
			pctx := BuildPolicyContext(args[0], args[1:], "")
			allowed, reason, policyErr := EvaluatePolicy(pctx)
			if policyErr != nil {
				return fmt.Errorf("adssh: policy evaluation error: %v", policyErr)
			}
			if !allowed {
				LogPolicyDecision(pctx.User, cmd, false, reason)
				if reason != "" {
					return fmt.Errorf("adssh: access denied: %s", reason)
				}
				return fmt.Errorf("adssh: access denied for '%s' by policy", args[0])
			}
			LogPolicyDecision(pctx.User, cmd, true, "")

			// 1. Custom Starlark commands registered via register_command()
			if globals != nil {
				if dictVal, ok := globals["__custom_commands__"]; ok {
					if dict, ok := dictVal.(*starlark.Dict); ok {
						if cmdVal, found, _ := dict.Get(starlark.String(args[0])); found {
							if callable, ok := cmdVal.(starlark.Callable); ok {
								newThread := &starlark.Thread{Name: "bash-interceptor"}
								var starlarkArgs []starlark.Value
								for _, arg := range args {
									starlarkArgs = append(starlarkArgs, starlark.String(arg))
								}
								_, err := starlark.Call(newThread, callable, starlark.Tuple{starlark.NewList(starlarkArgs)}, nil)
								return err
							}
						}
					}
				}
			}

			// 2. Virtual binary registry — thread sessionID through context for binaries that need it
			if vb, ok := Lookup(args[0]); ok {
				sessionID := ""
				if globals != nil {
					if val, ok := globals["SESSION_ID"]; ok {
						if strVal, ok := val.(starlark.String); ok {
							sessionID = string(strVal)
						}
					}
				}
				return DispatchVBin(WithSessionID(ctx, sessionID), vb, args)
			}

			// 3. Restricted mode checks before falling through to the real shell
			if restricted {
				if strings.Contains(args[0], "/") {
					return fmt.Errorf("adssh: restricted: cannot specify '/' in command names")
				}
				if args[0] == "cd" || args[0] == "export" {
					return fmt.Errorf("adssh: restricted: %s is not allowed", args[0])
				}
			}

			return next(ctx, args)
		}
	}
}
