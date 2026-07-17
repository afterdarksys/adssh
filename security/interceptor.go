package security

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/sys"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
)

func BashInterceptor(restricted bool, globals starlark.StringDict) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}

			// xtrace: print command before executing
			if opts, ok := globals["__shopts__"].(*starlark.Dict); ok {
				if v, found, _ := opts.Get(starlark.String("xtrace")); found {
					if b, ok := v.(starlark.Bool); ok && bool(b) {
						fmt.Fprintf(interp.HandlerCtx(ctx).Stderr, "+ %s\n", strings.Join(args, " "))
					}
				}
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

			// 0a. Change management ticket check
			if err := CMSessionCheck(args[0], args[1:]); err != nil {
				return err
			}

			// 0b. 4-eyes dual-approval gate
			if err := CheckFourEyes(cmd, args, nil); err != nil {
				return err
			}

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

			// 1.5. Shell builtins
			hc := interp.HandlerCtx(ctx)

			// ensure __shopts__ exists as a *starlark.Dict
			getShopts := func() *starlark.Dict {
				if globals == nil {
					return nil
				}
				if v, ok := globals["__shopts__"].(*starlark.Dict); ok {
					return v
				}
				d := new(starlark.Dict)
				globals["__shopts__"] = d
				return d
			}

			// ensure __aliases__ exists as a *starlark.Dict
			getAliases := func() *starlark.Dict {
				if globals == nil {
					return nil
				}
				if v, ok := globals["__aliases__"].(*starlark.Dict); ok {
					return v
				}
				d := new(starlark.Dict)
				globals["__aliases__"] = d
				return d
			}

			switch args[0] {

			// ------------------------------------------------------------------
			// set
			// ------------------------------------------------------------------
			case "set":
				if len(args) == 1 {
					// print all variables (skip __ keys)
					if globals != nil {
						for k, v := range globals {
							if strings.HasPrefix(k, "__") && strings.HasSuffix(k, "__") {
								continue
							}
							fmt.Fprintf(hc.Stdout, "%s=%s\n", k, v.String())
						}
					}
					return nil
				}

				// set -e / +e / -u / +u / -x / +x / -o pipefail / +o pipefail
				if len(args) >= 2 && (strings.HasPrefix(args[1], "-") || strings.HasPrefix(args[1], "+")) {
					enable := args[1][0] == '-'
					flag := args[1][1:]
					d := getShopts()
					if d == nil {
						return nil
					}
					var optName string
					switch flag {
					case "e":
						optName = "errexit"
					case "u":
						optName = "nounset"
					case "x":
						optName = "xtrace"
					case "o":
						if len(args) >= 3 && args[2] == "pipefail" {
							optName = "pipefail"
						}
					}
					if optName != "" {
						_ = d.SetKey(starlark.String(optName), starlark.Bool(enable))
					}
					return nil
				}

				// set VARNAME VALUE  or  set VARNAME=VALUE
				if len(args) >= 2 {
					var varName, varValue string
					if strings.Contains(args[1], "=") {
						parts := strings.SplitN(args[1], "=", 2)
						varName = parts[0]
						varValue = parts[1]
					} else if len(args) >= 3 {
						varName = args[1]
						varValue = args[2]
					} else {
						return fmt.Errorf("set: usage: set VARNAME VALUE or set VARNAME=VALUE")
					}
					if globals != nil {
						globals[varName] = starlark.String(varValue)
					}
					os.Setenv(varName, varValue) //nolint:errcheck
					return nil
				}
				return nil

			// ------------------------------------------------------------------
			// alias
			// ------------------------------------------------------------------
			case "alias":
				aliasDict := getAliases()
				if len(args) == 1 {
					// list all aliases
					if aliasDict != nil {
						for _, item := range aliasDict.Items() {
							fmt.Fprintf(hc.Stdout, "alias %s='%s'\n", item[0].(starlark.String), item[1].(starlark.String))
						}
					}
					return nil
				}
				arg := args[1]
				if !strings.Contains(arg, "=") {
					// alias name — print value
					if aliasDict != nil {
						if v, found, _ := aliasDict.Get(starlark.String(arg)); found {
							fmt.Fprintf(hc.Stdout, "alias %s='%s'\n", arg, v.(starlark.String))
						} else {
							return fmt.Errorf("alias: %s: not found", arg)
						}
					}
					return nil
				}
				parts := strings.SplitN(arg, "=", 2)
				name := parts[0]
				value := strings.Trim(parts[1], "'\"")
				if aliasDict != nil {
					_ = aliasDict.SetKey(starlark.String(name), starlark.String(value))
					fmt.Fprintf(hc.Stdout, "alias %s='%s'\n", name, value)
				}
				return nil

			// ------------------------------------------------------------------
			// unalias
			// ------------------------------------------------------------------
			case "unalias":
				if len(args) < 2 {
					return fmt.Errorf("unalias: usage: unalias name")
				}
				aliasDict := getAliases()
				if aliasDict != nil {
					_, _, _ = aliasDict.Delete(starlark.String(args[1]))
				}
				return nil

			// ------------------------------------------------------------------
			// type
			// ------------------------------------------------------------------
			case "type":
				if len(args) < 2 {
					return fmt.Errorf("type: usage: type name")
				}
				name := args[1]
				return resolveType(ctx, name, globals, hc, false)

			// ------------------------------------------------------------------
			// command
			// ------------------------------------------------------------------
			case "command":
				if len(args) >= 3 && args[1] == "-v" {
					return resolveType(ctx, args[2], globals, hc, true)
				}
				// fall through to real shell for other command forms
				return next(ctx, args)

			// ------------------------------------------------------------------
			// time
			// ------------------------------------------------------------------
			case "time":
				if len(args) < 2 {
					return fmt.Errorf("time: usage: time <command> [args...]")
				}
				start := time.Now()
				err := next(ctx, args[1:])
				fmt.Fprintf(hc.Stderr, "\nreal\t%s\n", time.Since(start).Round(time.Millisecond))
				return err

			// ------------------------------------------------------------------
			// disown
			// ------------------------------------------------------------------
			case "disown":
				if len(args) >= 2 && args[1] == "-a" {
					sys.GlobalJobTable().DisownAll()
					fmt.Fprintf(hc.Stdout, "all jobs disowned\n")
					return nil
				}
				if len(args) >= 2 {
					id, err := strconv.Atoi(args[1])
					if err != nil {
						return fmt.Errorf("disown: %s: invalid job id", args[1])
					}
					sys.GlobalJobTable().Disown(id)
					fmt.Fprintf(hc.Stdout, "[%d] disowned\n", id)
					return nil
				}
				return fmt.Errorf("disown: usage: disown [N|-a]")

			// ------------------------------------------------------------------
			// read
			// ------------------------------------------------------------------
			case "read":
				var prompt string
				var varName string
				i := 1
				if len(args) >= 4 && args[1] == "-p" {
					prompt = args[2]
					varName = args[3]
					i = 4
				} else if len(args) >= 2 {
					varName = args[i]
				} else {
					return fmt.Errorf("read: usage: read [-p prompt] VARNAME")
				}
				_ = i
				if prompt != "" {
					fmt.Fprint(hc.Stdout, prompt)
				}
				reader := bufio.NewReader(hc.Stdin)
				line, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("read: %w", err)
				}
				value := strings.TrimRight(line, "\n")
				os.Setenv(varName, value) //nolint:errcheck
				if globals != nil {
					globals[varName] = starlark.String(value)
				}
				return nil

			// ------------------------------------------------------------------
			// pushd
			// ------------------------------------------------------------------
			case "pushd":
				cwd, _ := os.Getwd()
				if len(args) >= 2 {
					dir := args[1]
					sys.DirStack().Push(cwd)
					if err := next(ctx, []string{"cd", dir}); err != nil {
						return err
					}
					printDirStack(hc)
					return nil
				}
				// no arg: swap top two (push cwd, cd to previous top)
				prev := sys.DirStack().Pop()
				if prev == "" {
					return fmt.Errorf("pushd: no other directory")
				}
				sys.DirStack().Push(cwd)
				if err := next(ctx, []string{"cd", prev}); err != nil {
					return err
				}
				printDirStack(hc)
				return nil

			// ------------------------------------------------------------------
			// popd
			// ------------------------------------------------------------------
			case "popd":
				cwd, _ := os.Getwd()
				prev := sys.DirStack().Pop()
				if prev == "" {
					return fmt.Errorf("popd: directory stack empty")
				}
				if err := next(ctx, []string{"cd", prev}); err != nil {
					return err
				}
				sys.DirStack().SetOldPwd(cwd)
				printDirStack(hc)
				return nil

			// ------------------------------------------------------------------
			// dirs
			// ------------------------------------------------------------------
			case "dirs":
				fmt.Fprintln(hc.Stdout, strings.Join(sys.DirStack().Dirs(), " "))
				return nil
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

// resolveType looks up what name resolves to.  When scripting=true the output
// is terse (just the path/descriptor), matching command -v semantics.
func resolveType(ctx context.Context, name string, globals starlark.StringDict, hc interp.HandlerContext, scripting bool) error {
	// 1. VBIN registry
	if _, ok := Lookup(name); ok {
		if scripting {
			fmt.Fprintf(hc.Stdout, "%s\n", name)
		} else {
			fmt.Fprintf(hc.Stdout, "%s is a virtual binary\n", name)
		}
		return nil
	}

	// 2. Custom Starlark commands
	if globals != nil {
		if dictVal, ok := globals["__custom_commands__"]; ok {
			if dict, ok := dictVal.(*starlark.Dict); ok {
				if _, found, _ := dict.Get(starlark.String(name)); found {
					if scripting {
						fmt.Fprintf(hc.Stdout, "%s\n", name)
					} else {
						fmt.Fprintf(hc.Stdout, "%s is a shell function\n", name)
					}
					return nil
				}
			}
		}
	}

	// 3. Aliases
	if globals != nil {
		if dictVal, ok := globals["__aliases__"]; ok {
			if dict, ok := dictVal.(*starlark.Dict); ok {
				if v, found, _ := dict.Get(starlark.String(name)); found {
					if scripting {
						fmt.Fprintf(hc.Stdout, "alias %s='%s'\n", name, v.(starlark.String))
					} else {
						fmt.Fprintf(hc.Stdout, "alias %s='%s'\n", name, v.(starlark.String))
					}
					return nil
				}
			}
		}
	}

	// 4. PATH lookup
	if path, err := exec.LookPath(name); err == nil {
		if scripting {
			fmt.Fprintf(hc.Stdout, "%s\n", path)
		} else {
			fmt.Fprintf(hc.Stdout, "%s is %s\n", name, path)
		}
		return nil
	}

	return fmt.Errorf("type: %s: not found", name)
}

// printDirStack prints the current directory stack to stdout.
func printDirStack(hc interp.HandlerContext) {
	dirs := sys.DirStack().Dirs()
	cwd, _ := os.Getwd()
	all := append([]string{cwd}, dirs...)
	fmt.Fprintln(hc.Stdout, strings.Join(all, " "))
}
