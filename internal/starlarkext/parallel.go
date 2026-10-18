package starlarkext

// sys.parallel runs command strings with bounded goroutines.
//
// Each string is a shell program, not a Starlark callable. The Starlark
// interpreter is not safe for concurrent use of one thread and one globals
// dict, so a callable would race. Every string goes through runGatedShell:
// the session engine gates it, the run has a timeout, and output is capped.
// Nothing is handed to /bin/sh -c.
//
// Threats:
//   - Fan-out. jobs, the command count, each command's size, each command's
//     output cap, and the whole batch's deadline are bounded. A value outside
//     the jobs or deadline range, an empty list, a non-string, an empty string,
//     or an oversized string is rejected before any command starts.
//   - Starlark on a worker goroutine. A command that names a registered
//     Starlark custom command (directly, or through command/exec/eval/builtin/
//     time) rejects the whole batch before any command starts. Each worker's
//     globals copy also has no custom-command table, so a name built at run
//     time cannot reach Starlark either; it falls through to the normal gate.
//   - A denied command hidden by its neighbors. Before any command starts,
//     every simple command whose words are all static is checked with the
//     engine's side-effect-free ExplainCommand. A denial there is confirmed
//     through AuthorizeCommand, which writes the audit line, and rejects the
//     batch. Commands with expanded words, and the remote gate of an SSH login
//     child, are decided only at run time. When a command is allowed at
//     pre-flight it is audited once, by the run-time gate.
//   - A failure that does not stop the rest. The first failure (denial,
//     timeout, non-zero exit, output overrun) cancels the batch context:
//     running commands are killed and queued commands never start. The call
//     returns that failure.
//   - An uninterruptible batch. Thread.Cancel on the calling Starlark thread
//     and the batch deadline (default 10 minutes, at most 1 hour) cancel the
//     batch the same way.
//   - Shared session mutation. Each command gets its own top-level globals
//     map, copied before any worker starts, so one command's `set` does not
//     write the caller's map. __aliases__ and __shopts__ are copied too, so
//     no two goroutines write one dict. Other nested dicts that were already
//     in the map are still shared. This is not a transaction: a command that already finished is
//     not rolled back when a later command fails.
// It does not decide which programs are allowed. That stays on the engine.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/syntax"
)

const (
	defaultParallelJobs     = 4
	maxParallelJobs         = 64
	maxParallelCommands     = 64
	maxParallelCommandBytes = 16 << 10
	parallelMaxOutputCap    = 1 << 20
	defaultParallelDeadline = 10 * time.Minute
	maxParallelDeadline     = time.Hour
	parallelCancelPoll      = 50 * time.Millisecond
)

// customCommandWrappers re-dispatch a later word through the exec handler,
// where custom Starlark commands are looked up.
var customCommandWrappers = map[string]bool{
	"command": true, "exec": true, "eval": true, "builtin": true, "time": true,
}

type parallelResult struct {
	out string
	err error
}

// createParallel implements
// sys.parallel(commands, jobs=4, timeout=30, max_output=1MiB, deadline=600) -> list[str].
// timeout bounds each command; deadline bounds the whole batch in seconds.
// jobs or deadline of 0 selects the default. An explicit jobs value outside
// 1..64 or a deadline outside 1..3600 is an error and starts nothing.
func createParallel(opts ExtensionOptions) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var commands *starlark.List
		var jobs, timeoutSecs, maxOutput, deadlineSecs int
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "commands", &commands, "jobs?", &jobs, "timeout?", &timeoutSecs, "max_output?", &maxOutput, "deadline?", &deadlineSecs); err != nil {
			return nil, err
		}
		cmds, progs, err := parallelCommandStrings(commands)
		if err != nil {
			return nil, err
		}
		workers, err := parallelWorkerCount(jobs, len(cmds))
		if err != nil {
			return nil, err
		}
		deadline, err := parallelDeadline(deadlineSecs)
		if err != nil {
			return nil, err
		}
		params := resolveExecParams(opts, timeoutSecs, maxOutput)
		if params.outputCap > parallelMaxOutputCap {
			params.outputCap = parallelMaxOutputCap
		}
		if err := refuseCustomCommands(params.session, progs); err != nil {
			return nil, err
		}
		if err := preflightParallel(params, progs); err != nil {
			return nil, err
		}
		return runParallel(thread, params, cmds, workers, deadline)
	}
}

func runParallel(thread *starlark.Thread, params execParams, cmds []string, workers int, deadline time.Duration) (starlark.Value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	var failOnce sync.Once
	var failErr error
	fail := func(index int, err error) {
		failOnce.Do(func() {
			failErr = fmt.Errorf("parallel: command %d: %w", index, err)
			cancel()
		})
	}

	// Copies are taken here, before any worker starts, so the caller's
	// dicts are only read on this goroutine.
	isolated := make([]execParams, len(cmds))
	for index := range cmds {
		copied, err := params.isolated()
		if err != nil {
			return nil, fmt.Errorf("parallel: command %d: %w", index, err)
		}
		isolated[index] = copied
	}
	results := make([]parallelResult, len(cmds))
	indices := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range indices {
				if ctx.Err() != nil {
					continue
				}
				out, runErr := runGatedShell(ctx, isolated[index], cmds[index])
				results[index] = parallelResult{out: out, err: runErr}
				// A command killed by the batch context is not the cause.
				if runErr != nil && ctx.Err() == nil {
					fail(index, runErr)
				}
			}
		}()
	}
	go func() {
		defer close(indices)
		for index := range cmds {
			select {
			case indices <- index:
			case <-ctx.Done():
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	var cancelErr error
	ticker := time.NewTicker(parallelCancelPoll)
	defer ticker.Stop()
wait:
	for {
		select {
		case <-done:
			break wait
		case <-ticker.C:
			if cancelErr == nil {
				if err := threadCancelled(thread); err != nil {
					cancelErr = fmt.Errorf("parallel: canceled: %v", err)
					cancel()
				}
			}
		}
	}

	switch {
	case failErr != nil:
		return nil, failErr
	case cancelErr != nil:
		return nil, cancelErr
	case ctx.Err() != nil:
		return nil, fmt.Errorf("parallel: batch deadline %s exceeded (fail-closed)", deadline)
	}
	list := starlark.NewList(make([]starlark.Value, 0, len(results)))
	for index, result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("parallel: command %d: %w", index, result.err)
		}
		if err := list.Append(starlark.String(result.out)); err != nil {
			return nil, err
		}
	}
	return list, nil
}

var (
	cancelProbeOnce sync.Once
	cancelProbe     starlark.Callable
	cancelProbeErr  error
)

// threadCancelled reports whether Thread.Cancel was called on thread. The
// starlark package does not expose the cancel state, so this calls an empty
// Starlark function on the thread: the interpreter checks the flag before its
// first step. It must run on the goroutine that owns thread.
func threadCancelled(thread *starlark.Thread) error {
	if thread == nil {
		return nil
	}
	cancelProbeOnce.Do(func() {
		globals, err := starlark.ExecFile(&starlark.Thread{Name: "parallel-cancel-probe"}, "parallel_cancel_probe.star", "def probe():\n    pass\n", nil)
		if err != nil {
			cancelProbeErr = err
			return
		}
		probe, ok := globals["probe"].(starlark.Callable)
		if !ok {
			cancelProbeErr = fmt.Errorf("cancel probe is %T", globals["probe"])
			return
		}
		cancelProbe = probe
	})
	if cancelProbeErr != nil {
		return cancelProbeErr
	}
	_, err := starlark.Call(thread, cancelProbe, nil, nil)
	return err
}

func parallelDeadline(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return defaultParallelDeadline, nil
	}
	deadline := time.Duration(seconds) * time.Second
	if seconds < 0 || deadline > maxParallelDeadline {
		return 0, fmt.Errorf("parallel: deadline must be between 1 and %d seconds", int(maxParallelDeadline/time.Second))
	}
	return deadline, nil
}

// refuseCustomCommands rejects the batch when any command names a Starlark
// custom command registered in the session.
func refuseCustomCommands(session *security.SessionState, progs []*syntax.File) error {
	if session == nil {
		return nil
	}
	table, ok := session.Globals["__custom_commands__"].(*starlark.Dict)
	if !ok || table.Len() == 0 {
		return nil
	}
	isCustom := func(name string) bool {
		_, found, err := table.Get(starlark.String(name))
		return found || err != nil
	}
	for index, prog := range progs {
		var refused string
		syntax.Walk(prog, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if refused != "" || !ok || len(call.Args) == 0 {
				return refused == ""
			}
			name, _ := staticWord(call.Args[0])
			if isCustom(name) {
				refused = name
				return false
			}
			if !customCommandWrappers[name] {
				return true
			}
			for _, word := range call.Args[1:] {
				text, _ := staticWord(word)
				for _, field := range strings.Fields(text) {
					if isCustom(field) {
						refused = field
						return false
					}
				}
			}
			return true
		})
		if refused != "" {
			return fmt.Errorf("parallel: command %d: sys.parallel cannot run Starlark custom command %q", index, refused)
		}
	}
	return nil
}

// preflightParallel checks every static simple command against the engine
// before any command starts. ExplainCommand writes nothing and requests no
// approval. A denial is re-checked through AuthorizeCommand so it is audited;
// if that gate allows it (for example a remote gate), the run-time gate
// decides.
func preflightParallel(p execParams, progs []*syntax.File) error {
	if p.engine == nil {
		return nil
	}
	sessionID := sessionGateID(p.session)
	for index, prog := range progs {
		var denied error
		syntax.Walk(prog, func(node syntax.Node) bool {
			if denied != nil {
				return false
			}
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			args := make([]string, 0, len(call.Args))
			for _, word := range call.Args {
				text, ok := staticWord(word)
				if !ok {
					return true
				}
				args = append(args, text)
			}
			explanation, err := p.engine.ExplainCommand(sessionID, args)
			if err == nil && explanation.Outcome != "denied" {
				return true
			}
			if gateErr := p.engine.AuthorizeCommand(args, sessionID); gateErr != nil {
				denied = gateErr
				return false
			}
			return true
		})
		if denied != nil {
			return fmt.Errorf("parallel: command %d: exec denied: %w", index, denied)
		}
	}
	return nil
}

// staticWord returns the value of a word that needs no expansion.
func staticWord(word *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "\\*?[~") {
				return "", false
			}
			b.WriteString(part.Value)
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false
			}
			b.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok || strings.Contains(lit.Value, "\\") {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// sessionGateID is the ID the engine gates session under: the fixed
// SessionID, else the SESSION_ID global. It mirrors the unexported
// SessionState.gateSessionID in package security.
func sessionGateID(session *security.SessionState) string {
	if session == nil {
		return ""
	}
	if session.SessionID != "" {
		return session.SessionID
	}
	if id, ok := session.Globals["SESSION_ID"].(starlark.String); ok {
		return string(id)
	}
	return ""
}

func parallelCommandStrings(commands *starlark.List) ([]string, []*syntax.File, error) {
	if commands == nil {
		return nil, nil, fmt.Errorf("parallel: commands are required")
	}
	n := commands.Len()
	if n == 0 {
		return nil, nil, fmt.Errorf("parallel: no commands")
	}
	if n > maxParallelCommands {
		return nil, nil, fmt.Errorf("parallel: %d commands exceeds the limit of %d", n, maxParallelCommands)
	}
	cmds := make([]string, n)
	progs := make([]*syntax.File, n)
	for i := 0; i < n; i++ {
		value := commands.Index(i)
		text, ok := value.(starlark.String)
		if !ok {
			return nil, nil, fmt.Errorf("parallel: command %d is %s, want a string", i, value.Type())
		}
		cmd := strings.TrimSpace(string(text))
		if cmd == "" {
			return nil, nil, fmt.Errorf("parallel: command %d is empty", i)
		}
		if len(cmd) > maxParallelCommandBytes {
			return nil, nil, fmt.Errorf("parallel: command %d is %d bytes, limit is %d", i, len(cmd), maxParallelCommandBytes)
		}
		prog, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
		if err != nil {
			return nil, nil, fmt.Errorf("parallel: command %d: parse error: %v", i, err)
		}
		cmds[i] = cmd
		progs[i] = prog
	}
	return cmds, progs, nil
}

func parallelWorkerCount(requested, commands int) (int, error) {
	if requested < 0 || requested > maxParallelJobs {
		return 0, fmt.Errorf("parallel: jobs must be between 1 and %d", maxParallelJobs)
	}
	jobs := requested
	if jobs == 0 {
		jobs = defaultParallelJobs
	}
	if jobs > commands {
		jobs = commands
	}
	return jobs, nil
}

// isolated returns params whose session globals map is a private copy
// without the custom-command table, so no worker can call into Starlark.
// __aliases__ and __shopts__ are copied one level deep; other nested values
// are shared. The copy is taken under the session's globals lock
// (SessionState.ReadGlobals), so a background shell job of the same session
// running set, alias, unalias or read cannot write the map or those dicts
// while it is copied.
func (p execParams) isolated() (execParams, error) {
	restricted := false
	sessionID := ""
	if p.session != nil {
		restricted = p.session.Restricted
		sessionID = p.session.SessionID
	}
	var copied starlark.StringDict
	err := p.session.ReadGlobals(func(globals starlark.StringDict) error {
		copied = make(starlark.StringDict, len(globals))
		for key, value := range globals {
			switch key {
			case "__custom_commands__":
				continue
			case "__aliases__", "__shopts__":
				// The shell builtins write these dicts in place; each worker
				// gets its own so workers never share one across goroutines.
				if dict, ok := value.(*starlark.Dict); ok {
					copiedDict, err := copyStarlarkDict(dict)
					if err != nil {
						return fmt.Errorf("copy %s: %w", key, err)
					}
					value = copiedDict
				}
			}
			copied[key] = value
		}
		return nil
	})
	if err != nil {
		return execParams{}, err
	}
	p.session = &security.SessionState{Restricted: restricted, SessionID: sessionID, Globals: copied}
	return p, nil
}

// copyStarlarkDict returns a new unfrozen dict with dict's entries. Entries
// are not copied; alias and shopt values are immutable strings and bools.
func copyStarlarkDict(dict *starlark.Dict) (*starlark.Dict, error) {
	out := starlark.NewDict(dict.Len())
	for _, item := range dict.Items() {
		if err := out.SetKey(item[0], item[1]); err != nil {
			return nil, err
		}
	}
	return out, nil
}
