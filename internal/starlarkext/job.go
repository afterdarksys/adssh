package starlarkext

import (
	"context"
	"fmt"

	"go.starlark.net/starlark"
)

// JobValue represents an asynchronous job in Starlark. It runs a command through
// the same hardened, session-gated core as sys.exec_cmd (runGatedShell): the
// per-session engine authorizes every sub-command, the run is timeout-bounded,
// and output is captured into a capped buffer. cancel() (via job.kill) stops it
// early; the captured output and terminal error are published through waitChan
// and read back by wait()/output() after the channel synchronizes them.
type JobValue struct {
	cancel   context.CancelFunc
	waitChan <-chan error
	output   string
	err      error
	done     bool
}

func (j *JobValue) String() string { return "<job>" }
func (j *JobValue) Type() string   { return "job" }
func (j *JobValue) Freeze()        {}

func (j *JobValue) Truth() starlark.Bool { return starlark.Bool(!j.done) }

func (j *JobValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: job")
}

// Attr exposes the job's methods to Starlark.
func (j *JobValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "stop":
		return starlark.NewBuiltin("stop", j.stop), nil
	case "resume":
		return starlark.NewBuiltin("resume", j.resume), nil
	case "wait":
		return starlark.NewBuiltin("wait", j.wait), nil
	case "kill":
		return starlark.NewBuiltin("kill", j.kill), nil
	case "output":
		return starlark.NewBuiltin("output", j.outputAttr), nil
	default:
		return nil, nil
	}
}

func (j *JobValue) AttrNames() []string {
	return []string{"stop", "resume", "wait", "kill", "output"}
}

func (j *JobValue) stop(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("stop not supported for adssh async jobs")
}

func (j *JobValue) resume(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("resume not supported for adssh async jobs")
}

// kill cancels the job's context, which cancels the timeout-bounded run inside
// runGatedShell.
func (j *JobValue) kill(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	if j.cancel != nil {
		j.cancel()
		j.done = true
	}
	return starlark.True, nil
}

// wait blocks until the job finishes, then returns True on success or the error
// string on failure (including a fail-closed timeout or output overrun).
func (j *JobValue) wait(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	j.join()
	if j.err != nil {
		return starlark.String(j.err.Error()), nil
	}
	return starlark.True, nil
}

// outputAttr blocks until the job finishes and returns its captured stdout.
func (j *JobValue) outputAttr(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	j.join()
	return starlark.String(j.output), nil
}

// join waits for the run goroutine exactly once; the channel receive
// happens-after the goroutine's writes to j.output/j.err, so those reads are
// synchronized without an extra mutex.
func (j *JobValue) join() {
	if j.done {
		return
	}
	j.err = <-j.waitChan
	j.done = true
}

// createExecAsync implements sys.exec_async(command, timeout=30, max_output=10MiB)
// -> job. The command runs through runGatedShell in a goroutine, so it is gated,
// timeout-bounded and output-capped exactly like sys.exec_cmd, but returns a job
// handle the script can wait on, read output from, or kill.
func createExecAsync(opts ExtensionOptions) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var command string
		var timeoutSecs, maxOutput int
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "command", &command, "timeout?", &timeoutSecs, "max_output?", &maxOutput); err != nil {
			return nil, err
		}
		params := resolveExecParams(opts, timeoutSecs, maxOutput)

		ctx, cancel := context.WithCancel(context.Background())
		waitChan := make(chan error, 1)
		job := &JobValue{cancel: cancel, waitChan: waitChan}

		go func() {
			out, err := runGatedShell(ctx, params, command)
			job.output = out // published to readers via the waitChan send below
			waitChan <- err
		}()

		return job, nil
	}
}
