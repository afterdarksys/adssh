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

// SessionState carries the per-session context the interceptor needs so that
// many isolated sessions can run concurrently in one process, each using its
// own restricted flag, its own Starlark globals dict, and its own directory
// stack instead of the process-global singletons.
//
// It lives in the security package (not engine) so that security/ never has to
// import engine/ — engine.Session builds a SessionState and hands it to
// BashInterceptorSession.
type SessionState struct {
	// Restricted enables restricted-mode command checks for this session.
	Restricted bool
	// Globals is this session's own Starlark globals dict (aliases, custom
	// commands, shopts, session id, ...). Must not be shared between sessions.
	Globals starlark.StringDict
	// Dirs is this session's own directory stack for pushd/popd/dirs. When nil
	// the interceptor falls back to the process-global sys.DirStack().
	Dirs *sys.DirStackState
}

// BashInterceptor returns the shell exec middleware for the process-global
// default engine, honoring the caller-supplied restricted flag. It uses the
// process-global directory stack.
//
// Deprecated: use (*Engine).BashInterceptorSession with a per-session
// SessionState so concurrent sessions do not share a directory stack.
func BashInterceptor(restricted bool, globals starlark.StringDict) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return defaultEngine.execHandler(restricted, globals, nil)
}

// BashInterceptorSession returns the shell exec middleware for the process-global
// default engine bound to a specific session's state (restricted flag, globals,
// and directory stack).
func BashInterceptorSession(sess *SessionState) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return defaultEngine.execHandler(sess.Restricted, sess.Globals, sess.Dirs)
}

// BashInterceptor returns the shell exec middleware for this engine, using the
// engine's own restricted flag and its own security gates. It uses the
// process-global directory stack.
//
// Deprecated: use (*Engine).BashInterceptorSession for per-session isolation.
func (e *Engine) BashInterceptor(globals starlark.StringDict) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return e.execHandler(e.restricted, globals, nil)
}

// BashInterceptorSession returns the shell exec middleware for this engine bound
// to a specific session's state. All authorization gates run against engine e,
// while restricted, globals and the directory stack come from sess so that many
// sessions can share one engine without sharing per-session state.
func (e *Engine) BashInterceptorSession(sess *SessionState) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return e.execHandler(sess.Restricted, sess.Globals, sess.Dirs)
}

// execHandler is the shared implementation behind the BashInterceptor* entry
// points. All authorization gates and logging run against engine e; restricted,
// globals and dirs are parameterized so the deprecated package/method shims can
// pass the caller's flag plus the process-global stack while the session form
// passes per-session state. When dirs is nil the process-global directory stack
// is used.
func (e *Engine) execHandler(restricted bool, globals starlark.StringDict, dirs *sys.DirStackState) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	ds := dirs
	if ds == nil {
		ds = sys.DirStack()
	}
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
			e.LogCommand("BASH", cmd)

			// 0. Rego policy evaluation (primary authorization)
			pctx := BuildPolicyContext(args[0], args[1:], "")
			allowed, reason, policyErr := e.EvaluatePolicy(pctx)
			if policyErr != nil {
				return fmt.Errorf("adssh: policy evaluation error: %v", policyErr)
			}
			if !allowed {
				e.LogPolicyDecision(pctx.User, cmd, false, reason)
				if reason != "" {
					return fmt.Errorf("adssh: access denied: %s", reason)
				}
				return fmt.Errorf("adssh: access denied for '%s' by policy", args[0])
			}
			e.LogPolicyDecision(pctx.User, cmd, true, "")

			// 0a. Change management ticket check
			if err := e.CMSessionCheck(args[0], args[1:]); err != nil {
				return err
			}

			// 0b. 4-eyes dual-approval gate
			if err := e.CheckFourEyes(cmd, args, nil); err != nil {
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
				return e.resolveType(ctx, name, globals, hc, false)

			// ------------------------------------------------------------------
			// command
			// ------------------------------------------------------------------
			case "command":
				if len(args) >= 3 && args[1] == "-v" {
					return e.resolveType(ctx, args[2], globals, hc, true)
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
				cwd := hc.Dir
				if len(args) >= 2 {
					dir := args[1]
					ds.Push(cwd)
					if err := next(ctx, []string{"cd", dir}); err != nil {
						return err
					}
					printDirStack(hc, ds)
					return nil
				}
				// no arg: swap top two (push cwd, cd to previous top)
				prev := ds.Pop()
				if prev == "" {
					return fmt.Errorf("pushd: no other directory")
				}
				ds.Push(cwd)
				if err := next(ctx, []string{"cd", prev}); err != nil {
					return err
				}
				printDirStack(hc, ds)
				return nil

			// ------------------------------------------------------------------
			// popd
			// ------------------------------------------------------------------
			case "popd":
				cwd := hc.Dir
				prev := ds.Pop()
				if prev == "" {
					return fmt.Errorf("popd: directory stack empty")
				}
				if err := next(ctx, []string{"cd", prev}); err != nil {
					return err
				}
				ds.SetOldPwd(cwd)
				printDirStack(hc, ds)
				return nil

			// ------------------------------------------------------------------
			// dirs
			// ------------------------------------------------------------------
			case "dirs":
				fmt.Fprintln(hc.Stdout, strings.Join(ds.Dirs(), " "))
				return nil
			}

			// 2. Virtual binary registry — thread sessionID through context for binaries that need it
			if vb, ok := e.Lookup(args[0]); ok {
				sessionID := ""
				if globals != nil {
					if val, ok := globals["SESSION_ID"]; ok {
						if strVal, ok := val.(starlark.String); ok {
							sessionID = string(strVal)
						}
					}
				}
				return e.DispatchVBin(WithSessionID(ctx, sessionID), vb, args)
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
func (e *Engine) resolveType(ctx context.Context, name string, globals starlark.StringDict, hc interp.HandlerContext, scripting bool) error {
	// 1. VBIN registry
	if _, ok := e.Lookup(name); ok {
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

// printDirStack prints the current directory stack (top = current dir) to
// stdout, using the session's directory stack and the runner's current dir.
func printDirStack(hc interp.HandlerContext, ds *sys.DirStackState) {
	dirs := ds.Dirs()
	all := append([]string{hc.Dir}, dirs...)
	fmt.Fprintln(hc.Stdout, strings.Join(all, " "))
}
