//go:build unix

package repl

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

const busyLoop = "def spin():\n    n = 0\n    for i in range(1 << 40):\n        n += 1\n    return n\nspin()\n"

// A SIGINT delivered while a Starlark line runs cancels that line: one
// "interrupted" line, a non-zero code, and the next line runs normally.
func TestStarlarkInterruptCancelsBusyLoop(t *testing.T) {
	si := &starlarkInterrupt{}
	stop := watchStarlarkInterrupts(si)
	defer stop()

	thread := &starlark.Thread{Name: "test"}
	globals := starlark.StringDict{}
	errOut := &bytes.Buffer{}
	done := make(chan int, 1)
	go func() { done <- evalStarlarkInterruptible(si, thread, busyLoop, globals, errOut) }()

	deadline := time.Now().Add(5 * time.Second)
	for !si.isRunning() {
		if time.Now().After(deadline) {
			t.Fatal("evaluation did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}

	select {
	case code := <-done:
		if code != 130 {
			t.Fatalf("code = %d, want 130", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGINT did not cancel the Starlark evaluation")
	}
	if got := errOut.String(); got != "interrupted\n" {
		t.Fatalf("errOut = %q, want one interrupted line", got)
	}

	errOut.Reset()
	if code := evalStarlarkInterruptible(si, thread, "x = 1 + 1", globals, errOut); code != 0 {
		t.Fatalf("next line after an interrupt: code=%d errOut=%q", code, errOut.String())
	}
	if got, ok := globals["x"].(starlark.Int); !ok || got.String() != "2" {
		t.Fatalf("x = %v, want 2", globals["x"])
	}
}

// An interrupt while nothing evaluates does not cancel the next line.
func TestStarlarkInterruptIdleDoesNotCancelNextLine(t *testing.T) {
	si := &starlarkInterrupt{}
	si.interrupt()
	thread := &starlark.Thread{Name: "test"}
	globals := starlark.StringDict{}
	errOut := &bytes.Buffer{}
	if code := evalStarlarkInterruptible(si, thread, "y = 3", globals, errOut); code != 0 {
		t.Fatalf("code=%d errOut=%q", code, errOut.String())
	}
	if globals["y"] == nil {
		t.Fatal("y was not bound")
	}
}

// A Starlark error that is not an interrupt keeps its normal message.
func TestStarlarkInterruptLeavesOtherErrors(t *testing.T) {
	si := &starlarkInterrupt{}
	errOut := &bytes.Buffer{}
	code := evalStarlarkInterruptible(si, &starlark.Thread{Name: "test"}, "1 // 0", starlark.StringDict{}, errOut)
	if code != 1 || !bytes.Contains(errOut.Bytes(), []byte("Starlark error")) {
		t.Fatalf("code=%d errOut=%q", code, errOut.String())
	}
}
