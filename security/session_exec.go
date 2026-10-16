package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
)

// Threats: the innermost exec handler does not call the default handler. A
// credential or rlimit failure returns before Start, so the command is not
// run as root. Child environment collapses to the last value of each name so
// a smuggled earlier duplicate cannot hide a session overlay or a shell
// export. An unset after an export drops the name. There is no fallback to
// the listener uid.
const sessionKillTimeout = 2 * time.Second

// SessionExecHandler runs an already-authorized external command. It does not
// call next for a non-empty argv, so a failure cannot fall through to an
// exec that still has the listener uid. An empty argv is passed on.
func SessionExecHandler(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) == 0 {
			return next(ctx, args)
		}
		hc := interp.HandlerCtx(ctx)
		path, err := interp.LookPathDir(hc.Dir, hc.Env, args[0])
		if err != nil {
			if hc.Stderr != nil {
				fmt.Fprintln(hc.Stderr, err)
			}
			return interp.NewExitStatus(127)
		}
		cmd := exec.Cmd{
			Path:   path,
			Args:   args,
			Env:    ChildEnviron(hc.Env),
			Dir:    hc.Dir,
			Stdin:  hc.Stdin,
			Stdout: hc.Stdout,
			Stderr: hc.Stderr,
		}
		if err := sys.PrepareChild(&cmd, SessionFromEnv(hc.Env)); err != nil {
			if hc.Stderr != nil {
				fmt.Fprintf(hc.Stderr, "%v\n", err)
			}
			return err
		}
		err = cmd.Start()
		if err == nil {
			stopf := context.AfterFunc(ctx, func() {
				if sessionKillTimeout <= 0 || runtime.GOOS == "windows" {
					_ = cmd.Process.Signal(os.Kill)
					return
				}
				_ = cmd.Process.Signal(os.Interrupt)
				time.Sleep(sessionKillTimeout)
				_ = cmd.Process.Signal(os.Kill)
			})
			defer stopf()
			err = cmd.Wait()
		}
		switch err := err.(type) {
		case *exec.ExitError:
			if status, ok := err.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return interp.NewExitStatus(uint8(128 + int(status.Signal())))
			}
			return interp.NewExitStatus(uint8(err.ExitCode()))
		case *exec.Error:
			if hc.Stderr != nil {
				fmt.Fprintf(hc.Stderr, "%v\n", err)
			}
			return interp.NewExitStatus(127)
		default:
			return err
		}
	}
}

// ChildEnviron builds the environment of a shell child. The base is the
// session overlay merged over the live process environment, or the process
// environment when the interpreter has no registered session. Exported
// string values from env are then applied. The last value of each name wins,
// and a name that is unset at the end is removed from both the base and the
// exported values. A non-exported assignment does not clear an unset and is
// not passed to the child.
func ChildEnviron(env expand.Environ) []string {
	var base []string
	if session := SessionFromEnv(env); session != nil {
		base = session.Environ()
	} else {
		base = os.Environ()
	}
	exported := make([]string, 0, 32)
	unset := map[string]struct{}{}
	if env != nil {
		env.Each(func(name string, vr expand.Variable) bool {
			if name == "" {
				return true
			}
			if !vr.IsSet() {
				unset[name] = struct{}{}
				return true
			}
			if vr.Kind == expand.String && vr.Exported {
				delete(unset, name)
				exported = append(exported, name+"="+vr.Str)
			}
			return true
		})
	}
	base = dropEnvNames(base, unset)
	exported = dropEnvNames(exported, unset)
	out := sys.LastEnvWins(append(base, exported...))
	if out == nil {
		return []string{}
	}
	return out
}

func dropEnvNames(list []string, unset map[string]struct{}) []string {
	if len(unset) == 0 {
		return list
	}
	out := make([]string, 0, len(list))
	for _, kv := range list {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if _, drop := unset[name]; drop {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// SessionFromEnv returns the registered session named by an exported-or-not
// SESSION_ID string. A nil environ, an unset id, or an unregistered id
// returns nil so the child falls back to the process environment.
func SessionFromEnv(env expand.Environ) *sys.Session {
	if env == nil {
		return nil
	}
	vr := env.Get("SESSION_ID")
	if !vr.IsSet() || vr.Kind != expand.String || vr.Str == "" {
		return nil
	}
	return sys.GetSession(vr.Str)
}

type sessionEnviron struct {
	id string
}

// NewSessionEnviron is the interpreter environment for a session that does
// not use the REPL hybrid bridge. SESSION_ID is visible and not exported.
// Overlay values then the process environment are exported. Each reads the
// process environment live and does not emit SESSION_ID.
func NewSessionEnviron(sessionID string) expand.Environ {
	return sessionEnviron{id: sessionID}
}

func (e sessionEnviron) Get(name string) expand.Variable {
	if name == "SESSION_ID" {
		return expand.Variable{Set: true, Exported: false, Kind: expand.String, Str: e.id}
	}
	if session := sys.GetSession(e.id); session != nil {
		if value, ok := session.OverlayGet(name); ok {
			return expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: rewriteVault(value)}
		}
	}
	if value, ok := os.LookupEnv(name); ok {
		return expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: rewriteVault(value)}
	}
	return expand.Variable{}
}

func (e sessionEnviron) Each(fn func(name string, vr expand.Variable) bool) {
	for _, kv := range os.Environ() {
		name, val, ok := strings.Cut(kv, "=")
		if !ok || name == "" || name == "SESSION_ID" {
			continue
		}
		if !fn(name, expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: val}) {
			return
		}
	}
	session := sys.GetSession(e.id)
	if session == nil {
		return
	}
	overlay := session.EnvOverlay()
	keys := make([]string, 0, len(overlay))
	for key := range overlay {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "SESSION_ID" {
			continue
		}
		if !fn(key, expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: overlay[key]}) {
			return
		}
	}
}

func rewriteVault(val string) string {
	if strings.HasPrefix(val, "vault://") {
		return "RESOLVED_SECRET_" + strings.TrimPrefix(val, "vault://")
	}
	return val
}
