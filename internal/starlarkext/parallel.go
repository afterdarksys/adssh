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
//   - Fan-out. jobs, the command count, each command's size, and each
//     command's output cap are bounded. A value outside the jobs range, an
//     empty list, a non-string, an empty string, or an oversized string is
//     rejected before any command starts.
//   - A bad command hidden by its neighbors. The call returns the first
//     failure in input order. A denial, a timeout, a non-zero exit, or an
//     output overrun fails the call.
//   - Shared session mutation. Each command gets its own top-level globals
//     map, copied before it starts, so one command's `set` does not write
//     the caller's map. Nested dicts that were already in the map are still
//     shared. This is not a transaction: a command that already passed the
//     gate is not rolled back when a later command fails.
// It does not decide which programs are allowed. That stays on the engine.

import (
	"context"
	"fmt"
	"strings"
	"sync"

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
)

type parallelResult struct {
	out string
	err error
}

// createParallel implements
// sys.parallel(commands, jobs=4, timeout=30, max_output=1MiB) -> list[str].
// jobs of 0 selects the default. An explicit jobs value outside 1..64 is an
// error and starts nothing.
func createParallel(opts ExtensionOptions) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var commands *starlark.List
		var jobs, timeoutSecs, maxOutput int
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "commands", &commands, "jobs?", &jobs, "timeout?", &timeoutSecs, "max_output?", &maxOutput); err != nil {
			return nil, err
		}
		cmds, err := parallelCommandStrings(commands)
		if err != nil {
			return nil, err
		}
		workers, err := parallelWorkerCount(jobs, len(cmds))
		if err != nil {
			return nil, err
		}
		params := resolveExecParams(opts, timeoutSecs, maxOutput)
		if params.outputCap > parallelMaxOutputCap {
			params.outputCap = parallelMaxOutputCap
		}

		results := make([]parallelResult, len(cmds))
		indices := make(chan int)
		var wg sync.WaitGroup
		for worker := 0; worker < workers; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for index := range indices {
					out, runErr := runGatedShell(context.Background(), params.isolated(), cmds[index])
					results[index] = parallelResult{out: out, err: runErr}
				}
			}()
		}
		for index := range cmds {
			indices <- index
		}
		close(indices)
		wg.Wait()

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
}

func parallelCommandStrings(commands *starlark.List) ([]string, error) {
	if commands == nil {
		return nil, fmt.Errorf("parallel: commands are required")
	}
	n := commands.Len()
	if n == 0 {
		return nil, fmt.Errorf("parallel: no commands")
	}
	if n > maxParallelCommands {
		return nil, fmt.Errorf("parallel: %d commands exceeds the limit of %d", n, maxParallelCommands)
	}
	cmds := make([]string, n)
	for i := 0; i < n; i++ {
		value := commands.Index(i)
		text, ok := value.(starlark.String)
		if !ok {
			return nil, fmt.Errorf("parallel: command %d is %s, want a string", i, value.Type())
		}
		cmd := strings.TrimSpace(string(text))
		if cmd == "" {
			return nil, fmt.Errorf("parallel: command %d is empty", i)
		}
		if len(cmd) > maxParallelCommandBytes {
			return nil, fmt.Errorf("parallel: command %d is %d bytes, limit is %d", i, len(cmd), maxParallelCommandBytes)
		}
		if _, err := syntax.NewParser().Parse(strings.NewReader(cmd), ""); err != nil {
			return nil, fmt.Errorf("parallel: command %d: parse error: %v", i, err)
		}
		cmds[i] = cmd
	}
	return cmds, nil
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

// isolated returns params whose session globals map is a private copy.
// Nested values are shared. The caller must not mutate the source map
// while copies are taken.
func (p execParams) isolated() execParams {
	restricted := false
	var globals starlark.StringDict
	if p.session != nil {
		restricted = p.session.Restricted
		globals = p.session.Globals
	}
	copied := make(starlark.StringDict, len(globals))
	for key, value := range globals {
		copied[key] = value
	}
	p.session = &security.SessionState{Restricted: restricted, Globals: copied}
	return p
}
