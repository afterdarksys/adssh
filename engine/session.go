// Package engine is the embeddable public facade for adssh. Session is the
// per-session unit of isolation: many Sessions run concurrently in one process,
// each owning its own Starlark thread + globals, its own shell interpreter
// (interp.Runner) with an explicit working directory, its own directory stack,
// and its own injectable I/O streams. Two Sessions share nothing mutable, so a
// commercial host can run isolated tenants side by side.
//
// engine may depend on security/, sys/, starlarkext/ (and repl/ helpers);
// security/ must never import engine/, so the interceptor takes a
// security.SessionState value that engine builds here.
package engine

import (
	"io"
	"os"
	"strings"

	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Session owns all per-session state that used to live in process globals or in
// a shallow-copied shared Starlark dict. Everything here is constructed fresh in
// NewSession; nothing is shared between two Sessions.
type Session struct {
	// SessionID identifies this session (also stored as Globals["SESSION_ID"]).
	SessionID string
	// User is the authenticated principal this session runs as.
	User string
	// Restricted mirrors the restricted-mode flag applied to this session.
	Restricted bool

	// Thread is this session's Starlark thread; Globals is its own globals dict
	// (freshly built via starlarkext.SetupExtensions — never a shallow copy of a
	// shared dict). Aliases, custom commands, shopts, plugins and completers all
	// live in Globals as this session's own dicts.
	Thread  *starlark.Thread
	Globals starlark.StringDict

	// Runner is this session's shell interpreter, with interp.Dir set explicitly
	// so its cwd is independent of the process cwd and other sessions.
	Runner *interp.Runner
	// Dirs is this session's own pushd/popd/dirs stack.
	Dirs *sys.DirStackState

	// In/Out/Err are this session's I/O streams. Session paths never touch
	// os.Stdin/os.Stdout/os.Stderr directly.
	In  io.Reader
	Out io.Writer
	Err io.Writer

	// HistoryFile is this session's history file path (carried; single-session
	// use only until per-session history is wired).
	HistoryFile string

	// engine is the security engine this session's runner authorizes through.
	engine *security.Engine
}

// SessionOptions configures NewSession. The zero value is usable: it produces an
// unrestricted session bound to the process-global default security engine, with
// discarded I/O and the process cwd as its working directory.
type SessionOptions struct {
	SessionID   string
	User        string
	Restricted  bool
	In          io.Reader
	Out         io.Writer
	Err         io.Writer
	HistoryFile string
	// Dir is the initial working directory. Empty means the process cwd.
	Dir string
	// Engine is the security engine to authorize through. Nil means the
	// process-global default engine (the same one the deprecated package-level
	// security funcs delegate to).
	Engine *security.Engine
	// ExecMiddleware are extra exec middlewares appended AFTER the security
	// interceptor, in order. Tests use this to install a sentinel recorder in
	// place of real OS exec (see security/interceptor_test.go's sentinelRecorder).
	ExecMiddleware []func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc
}

// NewSession builds a fully isolated Session. It fails only if the shell runner
// cannot be constructed.
func NewSession(opts SessionOptions) (*Session, error) {
	dir := opts.Dir
	if dir == "" {
		if cwd, err := os.Getwd(); err == nil {
			dir = cwd
		}
	}

	in := opts.In
	if in == nil {
		in = strings.NewReader("")
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	errW := opts.Err
	if errW == nil {
		errW = io.Discard
	}

	// FRESH globals for this session — never a shallow copy of a shared dict.
	globals := starlark.StringDict{}
	starlarkext.SetupExtensions(starlarkext.ExtensionOptions{
		Env:        globals,
		Restricted: opts.Restricted,
		SessionID:  opts.SessionID,
		In:         in,
		Out:        out,
		Err:        errW,
		Engine:     opts.Engine,
	})
	// Match repl.Start: ensure this session's own alias/completer dicts exist.
	if _, ok := globals["__aliases__"]; !ok {
		globals["__aliases__"] = starlark.NewDict(16)
	}
	if _, ok := globals["__completers__"]; !ok {
		globals["__completers__"] = starlark.NewDict(8)
	}

	// This session's own directory stack.
	dirs := &sys.DirStackState{}
	dirs.Init(dir)

	state := &security.SessionState{
		Restricted: opts.Restricted,
		Globals:    globals,
		Dirs:       dirs,
	}

	// Session-aware security interceptor, then any caller middleware (sentinel).
	// The call handler is the authorization gate (runs for every command,
	// including builtins); the exec handler is dispatch-only.
	var interceptor func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc
	var callGate interp.CallHandlerFunc
	if opts.Engine != nil {
		interceptor = opts.Engine.BashInterceptorSession(state)
		callGate = opts.Engine.CallInterceptorSession(state)
	} else {
		interceptor = security.BashInterceptorSession(state)
		callGate = security.CallInterceptorSession(state)
	}
	handlers := make([]func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc, 0, 1+len(opts.ExecMiddleware))
	handlers = append(handlers, interceptor)
	handlers = append(handlers, opts.ExecMiddleware...)

	runner, err := interp.New(
		interp.Dir(dir),
		interp.StdIO(in, out, errW),
		interp.CallHandler(callGate),
		interp.ExecHandlers(handlers...),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)
	if err != nil {
		return nil, err
	}

	return &Session{
		SessionID:   opts.SessionID,
		User:        opts.User,
		Restricted:  opts.Restricted,
		Thread:      &starlark.Thread{Name: "session-" + opts.SessionID},
		Globals:     globals,
		Runner:      runner,
		Dirs:        dirs,
		In:          in,
		Out:         out,
		Err:         errW,
		HistoryFile: opts.HistoryFile,
		engine:      opts.Engine,
	}, nil
}

// GateProgram runs the DeclClause-keyword authorization pre-scan (export/
// readonly/declare/local/typeset/nameref) against this session's engine before
// the parsed program is handed to Runner.Run. Those keywords bypass mvdan's call
// and exec handlers, so callers that run programs through Session.Runner MUST
// call this first and refuse to run when it returns an error — otherwise
// `export FOO=1` under a deny-all policy would execute ungated. It mirrors the
// engine/default-engine branching used to build this session's call handler.
func (s *Session) GateProgram(node syntax.Node) error {
	state := &security.SessionState{
		Restricted: s.Restricted,
		Globals:    s.Globals,
		Dirs:       s.Dirs,
	}
	if s.engine != nil {
		return s.engine.GateProgramSession(state, node)
	}
	return security.GateProgramSession(state, node)
}
