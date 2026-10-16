package repl

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"

	"go.starlark.net/starlark"
)

// starlarkInterrupt routes SIGINT to the Starlark line that is running. A
// signal while no line runs (at the prompt, during a shell command) does
// nothing here: readline reads Ctrl-C as a key, and a shell command's child
// gets the signal from the terminal.
type starlarkInterrupt struct {
	mu          sync.Mutex
	running     *starlark.Thread
	interrupted bool
}

// begin marks thread as running and clears any earlier cancellation.
func (s *starlarkInterrupt) begin(thread *starlark.Thread) {
	if s == nil {
		return
	}
	s.mu.Lock()
	thread.Uncancel()
	s.running = thread
	s.interrupted = false
	s.mu.Unlock()
}

// end clears the running thread, resets its cancellation for the next line,
// and reports whether an interrupt canceled this line.
func (s *starlarkInterrupt) end() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != nil {
		s.running.Uncancel()
	}
	s.running = nil
	was := s.interrupted
	s.interrupted = false
	return was
}

// interrupt cancels the running line, if any.
func (s *starlarkInterrupt) interrupt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		return
	}
	s.running.Cancel("interrupted")
	s.interrupted = true
}

func (s *starlarkInterrupt) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running != nil
}

// watchStarlarkInterrupts delivers SIGINT to s until stop is called. The
// signal is caught alongside sys.SetupSignals' drain, not instead of it.
func watchStarlarkInterrupts(s *starlarkInterrupt) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				s.interrupt()
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// evalStarlarkInterruptible is evalStarlark with Ctrl-C: a line canceled by
// SIGINT prints one "interrupted" line and returns 130. A canceled thread
// stops at its next Starlark step; sys.parallel polls the same cancel and
// kills its running commands, so a blocked batch returns promptly too.
func evalStarlarkInterruptible(si *starlarkInterrupt, thread *starlark.Thread, src string, globals starlark.StringDict, errOut io.Writer) int {
	si.begin(thread)
	val, isExpr, newBindings, err := EvalStarlarkOnce(thread, "<stdin>", src, globals)
	if si.end() && err != nil {
		fmt.Fprintln(errOut, "interrupted")
		return 130
	}
	if err != nil {
		fmt.Fprintf(errOut, "Starlark error: %v\n", err)
		return 1
	}
	if isExpr {
		if val != nil && val != starlark.None {
			fmt.Println(val.String())
		}
		return 0
	}
	// Merge new definitions (functions, variables) back into the live globals
	MergeStarlarkBindings(globals, newBindings, errOut)
	return 0
}
