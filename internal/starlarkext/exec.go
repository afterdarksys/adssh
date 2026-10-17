package starlarkext

// Secure process execution for Starlark (sys.exec_cmd / sys.exec_json, and the
// shared core used by sys.exec_async in job.go).
//
// These run a command through adssh's OWN interpreter with the security engine's
// session-scoped interceptors installed — NOT the host `sh -c`. Every simple
// command inside the string is therefore individually policy-gated (Rego +
// entitlements + change-management + four-eyes + restricted-mode) and audited by
// the SAME engine the calling session authorizes against, exactly like a command
// typed at the REPL. The govern wrapper additionally gates the exec_* builtins
// themselves (capability group "proc"/"stdio").
//
// Threats:
//   - Ungoverned execution / gate bypass. The command is parsed and run through
//     the engine's own CallInterceptorSession / BashInterceptorSession /
//     GateProgramSession, so it cannot reach the OS without passing the same
//     authorization chokepoint as an interactive command. It never shells out to
//     an ungoverned host shell.
//   - Wrong-engine authorization. The builtins gate against the per-session
//     engine threaded in via ExtensionOptions.Engine (falling back to the
//     process default only when a session did not bind one), so a session on an
//     isolated engine is not silently authorized by the global default.
//   - Hung / runaway commands. Every run is bounded by a timeout (default
//     defaultExecTimeout, caller-overridable up to maxExecTimeout); on deadline
//     it fails closed with an error, never a partial success.
//   - Memory exhaustion from unbounded output. Output is captured into a capped
//     buffer that fails closed (errors, does NOT silently truncate) once the cap
//     is exceeded.
//   - Swallowed initialization errors. interp.New's error is checked, not `_ =`.
//   - The innermost handler is SessionExecHandler and fails closed (no fallback to root).
// It does NOT sanitize the command text or decide which commands are allowed —
// that is the Rego policy's job, enforced by the interceptors above.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const (
	// defaultExecTimeout bounds a run when the caller passes no timeout. maxExecTimeout
	// is the ceiling a caller may request; larger values are clamped down.
	defaultExecTimeout = 30 * time.Second
	maxExecTimeout     = 10 * time.Minute

	// defaultExecOutputCap bounds captured output when the caller passes none.
	// maxExecOutputCap is the ceiling; larger requests are clamped down.
	defaultExecOutputCap = 10 << 20 // 10 MiB
	maxExecOutputCap     = 64 << 20 // 64 MiB
)

// cappedBuffer captures output up to cap bytes and then FAILS CLOSED once the
// cap is exceeded: it records exceeded and cancels the run (killing the command)
// so an unbounded producer cannot keep the process alive, then DISCARDS the
// overflow while still reporting a successful Write. Discarding-with-success
// (rather than returning a Write error) is deliberate: an io.Copy that sees a
// short/errored write busy-loops retrying, pinning a core, whereas canceling the
// command stops production at the source. The caller turns exceeded into an
// explicit error after the run (see runGatedShell), so nothing is silently
// truncated from the caller's point of view — per SECURITY-RULES rule 10 (bound
// all external input).
type cappedBuffer struct {
	buf        bytes.Buffer
	cap        int
	exceeded   bool
	cancel     context.CancelFunc
	cancelOnce sync.Once
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.exceeded {
		return len(p), nil // already over the cap; discard, keep the copier happy
	}
	remaining := c.cap - c.buf.Len()
	if len(p) <= remaining {
		return c.buf.Write(p)
	}
	// This write crosses the cap: keep what fits, mark exceeded, kill the run.
	if remaining > 0 {
		_, _ = c.buf.Write(p[:remaining])
	}
	c.exceeded = true
	if c.cancel != nil {
		c.cancelOnce.Do(c.cancel)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// execParams carries the hardened, validated run parameters shared by every
// exec_* builtin.
type execParams struct {
	engine    *security.Engine
	session   *security.SessionState
	timeout   time.Duration
	outputCap int
}

// resolveExecParams builds execParams from the session options and the optional
// timeout/max_output kwargs, clamping both into their safe ranges. A non-positive
// value means "use the default".
func resolveExecParams(opts ExtensionOptions, timeoutSecs, maxOutput int) execParams {
	engine := opts.Engine
	if engine == nil {
		// No session-bound engine: fall back to the process default so the
		// interceptors still gate. This is the single-tenant path; multi-tenant
		// hosts always bind ExtensionOptions.Engine.
		engine = security.DefaultEngine()
	}

	timeout := defaultExecTimeout
	if timeoutSecs > 0 {
		timeout = time.Duration(timeoutSecs) * time.Second
		if timeout > maxExecTimeout {
			timeout = maxExecTimeout
		}
	}

	cap := defaultExecOutputCap
	if maxOutput > 0 {
		cap = maxOutput
		if cap > maxExecOutputCap {
			cap = maxExecOutputCap
		}
	}

	return execParams{
		engine:    engine,
		session:   &security.SessionState{Restricted: opts.Restricted, Globals: opts.Env, SessionID: opts.SessionID},
		timeout:   timeout,
		outputCap: cap,
	}
}

// runGatedShell parses cmdStr and runs it through the engine's session-scoped
// interceptors with a timeout and a capped output buffer. It returns the captured
// output and a fail-closed error on parse failure, policy denial, timeout, output
// overrun, or a non-zero command result. It is the single implementation behind
// exec_cmd, exec_json, exec_async, and parallel.
func runGatedShell(ctx context.Context, p execParams, cmdStr string) (string, error) {
	prog, err := syntax.NewParser().Parse(strings.NewReader(cmdStr), "")
	if err != nil {
		return "", fmt.Errorf("parse error: %v", err)
	}

	// The fixed session ID wins over the SESSION_ID global, which Starlark
	// code can overwrite.
	sid := sessionGateID(p.session)
	out := &cappedBuffer{cap: p.outputCap}
	runner, err := interp.New(
		interp.Env(security.NewSessionEnviron(sid)),
		interp.StdIO(nil, out, out),
		interp.CallHandler(p.engine.CallInterceptorSession(p.session)),
		interp.ExecHandlers(p.engine.BashInterceptorSession(p.session), security.SessionExecHandler),
		interp.OpenHandler(p.engine.OpenHandlerSession(p.session)),
	)
	if err != nil {
		return "", fmt.Errorf("exec init error: %v", err)
	}

	// Gate DeclClause keywords (export/readonly/...) that bypass the exec/call
	// handlers, before running anything. Fail closed on denial.
	if err := p.engine.GateProgramSession(p.session, prog); err != nil {
		return out.String(), fmt.Errorf("exec denied: %v", err)
	}

	// The run has no terminal, so each child gets its own process group and
	// a timeout or batch deadline kills the whole group.
	runCtx, cancel := context.WithTimeout(security.WithProcessGroupKill(ctx), p.timeout)
	defer cancel()
	// Let an output overrun cancel the run, so an unbounded producer is killed
	// at the source instead of spinning the output copier.
	out.cancel = cancel

	runErr := runner.Run(runCtx, prog)

	// Overrun and timeout are reported explicitly and take precedence over the
	// generic run error they may have induced (a capped Write or a canceled
	// context surfaces as a runner error too).
	if out.exceeded {
		return out.String(), fmt.Errorf("exec output exceeded %d bytes (fail-closed)", p.outputCap)
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return out.String(), fmt.Errorf("exec timed out after %s (fail-closed)", p.timeout)
	}
	if runErr != nil {
		return out.String(), fmt.Errorf("exec error: %v", runErr)
	}
	return out.String(), nil
}

// createExecCmd implements sys.exec_cmd(cmd, timeout=30, max_output=10MiB) -> str.
func createExecCmd(opts ExtensionOptions) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var cmdStr string
		var timeoutSecs, maxOutput int
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmdStr, "timeout?", &timeoutSecs, "max_output?", &maxOutput); err != nil {
			return nil, err
		}
		out, err := runGatedShell(context.Background(), resolveExecParams(opts, timeoutSecs, maxOutput), cmdStr)
		if err != nil {
			// The exit status alone does not say why: add the end of the
			// combined output, where the error message usually is.
			if out = strings.TrimRight(stripTerminalControls(out), "\n"); out != "" {
				if len(out) > execErrorOutputTail {
					out = "..." + strings.ToValidUTF8(out[len(out)-execErrorOutputTail:], "")
				}
				return nil, fmt.Errorf("%v; output:\n%s", err, out)
			}
			return nil, err
		}
		return starlark.String(out), nil
	}
}

// execErrorOutputTail is how much of a failed exec_cmd's output its error keeps.
const execErrorOutputTail = 4096

// stripTerminalControls removes escape sequences (CSI such as colors, OSC such
// as a window title), C1 controls (U+0080-U+009F, which terminals obey as
// 8-bit CSI and OSC) and other control characters but newline and tab. An
// unterminated sequence ends at the next ESC, and a string sequence also at a
// newline, so it cannot hide the text after it. The result is valid UTF-8.
// Threats: the error tail is printed to the user's terminal, so a command's
// output could otherwise retitle the window, move the cursor or hide text.
func stripTerminalControls(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r != 0x1b {
			if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f && (r < 0x80 || r > 0x9f)) {
				b.WriteString(s[i : i+size])
			}
			i += size
			continue
		}
		i++
		if i >= len(s) {
			break
		}
		switch s[i] {
		case '[': // CSI: parameters, then a final byte 0x40-0x7e
			i++
			for i < len(s) && s[i] < 0x80 && s[i] != 0x1b && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			if i < len(s) && s[i] < 0x80 && s[i] != 0x1b {
				i++
			}
		case ']', 'P', '_', '^': // OSC, DCS, APC, PM: until BEL, ST, any ESC or a newline
			i++
			for i < len(s) && s[i] != 0x07 && s[i] != 0x1b && s[i] != '\n' {
				i++
			}
			if i < len(s) && s[i] == 0x07 {
				i++
			} else if i+1 < len(s) && s[i+1] == '\\' {
				i += 2
			}
		default: // ESC, intermediates 0x20-0x2f, then one final byte (ESC ( B)
			for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
				i++
			}
			if i < len(s) && s[i] < 0x80 && s[i] != 0x1b {
				i++
			}
		}
	}
	return b.String()
}

// createExecJSON implements sys.exec_json(cmd, timeout=30, max_output=10MiB) and
// parses the command's stdout as JSON into a Starlark value.
func createExecJSON(opts ExtensionOptions) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var cmdStr string
		var timeoutSecs, maxOutput int
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmdStr, "timeout?", &timeoutSecs, "max_output?", &maxOutput); err != nil {
			return nil, err
		}
		out, err := runGatedShell(context.Background(), resolveExecParams(opts, timeoutSecs, maxOutput), cmdStr)
		if err != nil {
			return nil, err
		}
		parsed, err := decodeJSON([]byte(out))
		if err != nil {
			return nil, fmt.Errorf("json parse error: %v", err)
		}
		return GoToStarlark(parsed), nil
	}
}
