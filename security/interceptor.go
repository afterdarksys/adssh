package security

import (
	"context"
	"fmt"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"strings"
)

func BashInterceptor(restricted bool, globals starlark.StringDict) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			cmd := strings.Join(args, " ")
			LogCommand("BASH", cmd)

			// 1. Check for custom Starlark Commands
			if globals != nil {
				if dictVal, ok := globals["__custom_commands__"]; ok {
					if dict, ok := dictVal.(*starlark.Dict); ok {
						if cmdVal, found, _ := dict.Get(starlark.String(args[0])); found {
							if callable, ok := cmdVal.(starlark.Callable); ok {
								if !IsAuthorized(args[0]) {
									return fmt.Errorf("adssh: access denied for custom command '%s' by RBAC policy", args[0])
								}
								// Found a custom Starlark command!
								// Run it in a new Thread to ensure thread-safety for background Bash jobs
								newThread := &starlark.Thread{Name: "bash-interceptor"}

								// Convert args to starlark list
								var starlarkArgs []starlark.Value
								for _, arg := range args {
									starlarkArgs = append(starlarkArgs, starlark.String(arg))
								}
								listArg := starlark.NewList(starlarkArgs)

								_, err := starlark.Call(newThread, callable, starlark.Tuple{listArg}, nil)
								return err
							}
						}
					}
				}
			}

			// 2. Virtual DevOps Binaries
			isVirtual := args[0] == "jq" || args[0] == "yq" || args[0] == "http" || args[0] == "mirror" || args[0] == "cmdgen"
			if isVirtual {
				if !IsAuthorized(args[0]) {
					return fmt.Errorf("adssh: access denied for virtual binary '%s' by RBAC policy", args[0])
				}
				if args[0] == "jq" {
					return runVirtualJQ(ctx, args)
				}
				if args[0] == "yq" {
					return runVirtualYQ(ctx, args)
				}
				if args[0] == "http" {
					return runVirtualHTTP(ctx, args)
				}
				if args[0] == "mirror" {
					return runMirrorCommand(ctx, args)
				}
				if args[0] == "cmdgen" {
					return runCmdGen(ctx, args)
				}
			}

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
