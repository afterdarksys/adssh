package repl

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
)

func readPaste(t *testing.T, r io.Reader) string {
	t.Helper()
	pr, ok := r.(io.ReadCloser)
	if !ok {
		pr = io.NopCloser(r)
	}
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, pr)
		done <- buf.String()
	}()
	select {
	case s := <-done:
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("paste reader hung")
		return ""
	}
}

func pasteThrough(t *testing.T, input string) (string, *pasteState) {
	t.Helper()
	st := &pasteState{}
	out := readPaste(t, newPasteReader(io.NopCloser(strings.NewReader(input)), st))
	return out, st
}

func TestSingleLinePastePassesThrough(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~echo hi\x1b[201~")
	if out != "echo hi" {
		t.Fatalf("output %q", out)
	}
	if st.text != "" || st.reason != "" {
		t.Fatalf("state held %q reason %q", st.text, st.reason)
	}
}

func TestMultilinePasteDoesNotSubmit(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~echo hi\necho there\n\x1b[201~")
	if strings.Contains(out, "\n") || strings.Contains(out, "\r") {
		t.Fatalf("multiline paste forwarded a newline: %q", out)
	}
	if strings.Contains(out, "echo") {
		t.Fatalf("multiline paste forwarded the command: %q", out)
	}
	if out != "[paste held: 2 lines]" {
		t.Fatalf("output %q", out)
	}
	if st.text != "echo hi\necho there" {
		t.Fatalf("held %q", st.text)
	}
}

func TestTrailingNewlineIsHeld(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~echo hi\n\x1b[201~")
	if strings.Contains(out, "echo") || strings.Contains(out, "\n") {
		t.Fatalf("trailing newline was submitted: %q", out)
	}
	if st.text != "echo hi" || st.lines != 1 {
		t.Fatalf("held %q lines %d", st.text, st.lines)
	}
}

func TestCarriageReturnPasteIsHeld(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~echo hi\recho there\r\x1b[201~")
	if strings.Contains(out, "echo") {
		t.Fatalf("command forwarded: %q", out)
	}
	if st.text != "echo hi\necho there" {
		t.Fatalf("held %q", st.text)
	}
}

func TestTypedNewlineStillSubmits(t *testing.T) {
	out, st := pasteThrough(t, "ls\n")
	if out != "ls\n" {
		t.Fatalf("output %q", out)
	}
	if st.text != "" {
		t.Fatalf("typed line was held: %q", st.text)
	}
}

func TestArrowKeyPasses(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[A")
	if out != "\x1b[A" {
		t.Fatalf("output %q", out)
	}
	if st.reason != "" {
		t.Fatalf("reason %q", st.reason)
	}
}

func TestLoneEscapeDoesNotHang(t *testing.T) {
	out, st := pasteThrough(t, "\x1b")
	if out != "\x1b" {
		t.Fatalf("output %q", out)
	}
	if st.reason != "" || st.text != "" {
		t.Fatalf("state %+v", st)
	}
}

func TestUnclosedPasteRejectsWithoutEcho(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~rm -rf /\n")
	if strings.Contains(out, "rm") {
		t.Fatalf("unclosed paste echoed the body: %q", out)
	}
	if out != "[paste rejected]\n" {
		t.Fatalf("output %q", out)
	}
	if st.text != "" || st.reason != "paste rejected: unclosed" {
		t.Fatalf("state text %q reason %q", st.text, st.reason)
	}
}

func TestControlCharacterPasteIsDiscarded(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~echo\x1bhi\n\x1b[201~")
	if strings.Contains(out, "echo") {
		t.Fatalf("control paste forwarded the body: %q", out)
	}
	if out != "[paste rejected]\n" || st.text != "" || st.reason != "paste rejected: control character" {
		t.Fatalf("output %q text %q reason %q", out, st.text, st.reason)
	}
}

func TestReviewTokenInsidePasteIsDiscarded(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~[paste held: 1 lines]\necho hi\n\x1b[201~")
	if strings.Contains(out, "echo") || st.text != "" {
		t.Fatalf("output %q held %q", out, st.text)
	}
	if st.reason != "paste rejected: review token" {
		t.Fatalf("reason %q", st.reason)
	}
}

func TestOversizedPasteIsDiscarded(t *testing.T) {
	body := strings.Repeat("A", maxBracketPaste+1) + "\n"
	out, st := pasteThrough(t, "\x1b[200~"+body+"\x1b[201~")
	if strings.Contains(out, "A") || st.text != "" {
		t.Fatalf("oversized paste was stored or echoed")
	}
	if out != "[paste rejected]\n" || st.reason != "paste rejected: too large" {
		t.Fatalf("output %q reason %q", out, st.reason)
	}
}

func TestEmptyPasteStoresNothing(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~\n\x1b[201~")
	if out != "" || st.text != "" || st.reason != "" {
		t.Fatalf("output %q text %q reason %q", out, st.text, st.reason)
	}
}

type chunkReader struct {
	chunks [][]byte
	i      int
}

func (c *chunkReader) Read(b []byte) (int, error) {
	if c.i >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(b, c.chunks[c.i])
	if n < len(c.chunks[c.i]) {
		c.chunks[c.i] = c.chunks[c.i][n:]
		return n, nil
	}
	c.i++
	return n, nil
}

func (c *chunkReader) Close() error { return nil }

func TestSplitBracketAcrossFullReadIsHeld(t *testing.T) {
	head := bytes.Repeat([]byte("a"), 4095)
	head = append(head, 0x1b)
	rest := []byte("[200~echo hi\necho there\x1b[201~")
	st := &pasteState{}
	out := readPaste(t, newPasteReader(&chunkReader{chunks: [][]byte{head, rest}}, st))
	if strings.Contains(out, "echo") || strings.Contains(out, "\n") {
		t.Fatalf("split paste forwarded a command: %q", out)
	}
	if !strings.HasSuffix(out, "[paste held: 2 lines]") {
		t.Fatalf("output %q", out)
	}
	if st.text != "echo hi\necho there" {
		t.Fatalf("held %q", st.text)
	}
}

func testPasteRunner(t *testing.T, restricted bool) (pasteRunner, *bytes.Buffer, *bytes.Buffer, starlark.StringDict) {
	t.Helper()
	globals := starlark.StringDict{}
	var out, errOut bytes.Buffer
	sess := &security.SessionState{Restricted: restricted, Globals: globals}
	runner, err := interp.New(
		interp.StdIO(bytes.NewReader(nil), &out, &errOut),
		interp.CallHandler(security.CallInterceptorSession(sess)),
		interp.ExecHandlers(security.BashInterceptorSession(sess)),
	)
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	return pasteRunner{
		state:   sess,
		runner:  runner,
		thread:  &starlark.Thread{Name: "paste-test"},
		globals: globals,
		out:     &out,
		errOut:  &errOut,
	}, &out, &errOut, globals
}

func TestSafePasteRunStarlark(t *testing.T) {
	run, _, errOut, globals := testPasteRunner(t, false)
	st := &pasteState{text: "x = 41 + 1", lines: 1}
	if !handlePasteLine("safepaste run", st, run) {
		t.Fatal("safepaste run was not handled")
	}
	if st.text != "" {
		t.Fatal("paste still held after run")
	}
	got := globals["x"]
	if got == nil || got.String() != "42" {
		t.Fatalf("x = %v stderr %s", got, errOut.String())
	}
	if globals["?"].String() != "0" {
		t.Fatalf("status %v", globals["?"])
	}
}

func TestSafePasteRunShell(t *testing.T) {
	run, out, errOut, globals := testPasteRunner(t, false)
	st := &pasteState{text: "echo paste-ok", lines: 1}
	if !handlePasteLine("safepaste run", st, run) {
		t.Fatal("not handled")
	}
	if !strings.Contains(out.String(), "paste-ok") {
		t.Fatalf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if globals["?"].String() != "0" {
		t.Fatalf("status %v stderr %s", globals["?"], errOut.String())
	}
}

func TestSafePasteRunRestrictedSlashFailsClosed(t *testing.T) {
	run, out, errOut, globals := testPasteRunner(t, true)
	st := &pasteState{text: "/bin/echo should-not-run", lines: 1}
	if !handlePasteLine("safepaste run", st, run) {
		t.Fatal("not handled")
	}
	if strings.Contains(out.String(), "should-not-run") {
		t.Fatalf("restricted paste ran: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "restricted") {
		t.Fatalf("stderr %q", errOut.String())
	}
	if globals["?"].String() == "0" {
		t.Fatal("denied paste reported success")
	}
	if st.text != "" {
		t.Fatal("denied paste stayed held")
	}
}

func TestSafePasteHeldLineDoesNotExecute(t *testing.T) {
	run, out, errOut, _ := testPasteRunner(t, false)
	st := &pasteState{text: "echo should-not-run", lines: 1}
	if !handlePasteLine("[paste held: 1 lines]", st, run) {
		t.Fatal("review token was not intercepted")
	}
	if strings.Contains(out.String(), "should-not-run") {
		t.Fatal("review token executed the paste")
	}
	if st.text != "echo should-not-run" {
		t.Fatal("preview cleared the paste")
	}
	if !strings.Contains(errOut.String(), "safepaste run") {
		t.Fatalf("stderr %q", errOut.String())
	}
}

func TestSafePasteDropAndEmptyRun(t *testing.T) {
	run, _, errOut, _ := testPasteRunner(t, false)
	st := &pasteState{text: "echo hi", lines: 1}
	if !handlePasteLine("safepaste drop", st, run) || st.text != "" {
		t.Fatal("drop failed")
	}
	if !handlePasteLine("safepaste run", st, run) {
		t.Fatal("empty run not handled")
	}
	if !strings.Contains(errOut.String(), "nothing held") {
		t.Fatalf("stderr %q", errOut.String())
	}
	if handlePasteLine("echo hi", st, run) {
		t.Fatal("ordinary line was captured")
	}
}

func TestSafePasteRejectLinePrintsReason(t *testing.T) {
	run, _, errOut, _ := testPasteRunner(t, false)
	st := &pasteState{reason: "paste rejected: control character"}
	if !handlePasteLine("[paste rejected]", st, run) {
		t.Fatal("reject line not handled")
	}
	if !strings.Contains(errOut.String(), "control character") {
		t.Fatalf("stderr %q", errOut.String())
	}
	if st.reason != "" {
		t.Fatal("reason was kept")
	}
}

func TestPasteEndInsideClipboardRejectsWholePaste(t *testing.T) {
	out, st := pasteThrough(t, "\x1b[200~echo hi\x1b[201~\nrm -rf ~\n\x1b[201~")
	if strings.Contains(out, "rm") || strings.Contains(out, "echo") {
		t.Fatalf("data after paste end was forwarded: %q", out)
	}
	if out != pasteRejectedLine+"\n" {
		t.Fatalf("output %q", out)
	}
	if st.text != "" || st.reason != "paste rejected: data after paste end" {
		t.Fatalf("text %q reason %q", st.text, st.reason)
	}
}

func TestStrayPasteEndInLaterReadIsRejected(t *testing.T) {
	st := &pasteState{}
	r := &chunkReader{chunks: [][]byte{
		[]byte("\x1b[200~echo hi\x1b[201~"),
		[]byte("\nrm -rf ~\n\x1b[201~"),
	}}
	out := readPaste(t, newPasteReader(r, st))
	if strings.Contains(out, "rm") || strings.Contains(out, "\n"+"rm") {
		t.Fatalf("stray end let a command through: %q", out)
	}
	if !strings.HasSuffix(out, pasteRejectedLine+"\n") {
		t.Fatalf("output %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("a newline was forwarded before the rejection: %q", out)
	}
}

func TestSplitStartMarkerShortReadsIsHeld(t *testing.T) {
	st := &pasteState{}
	r := &chunkReader{chunks: [][]byte{
		[]byte("\x1b[20"),
		[]byte("0~echo a\necho b\x1b[201~"),
	}}
	out := readPaste(t, newPasteReader(r, st))
	if strings.Contains(out, "echo") || strings.Contains(out, "\n") {
		t.Fatalf("split start marker passed the paste raw: %q", out)
	}
	if out != "[paste held: 2 lines]" || st.text != "echo a\necho b" {
		t.Fatalf("output %q held %q", out, st.text)
	}
}

func TestPartialEscapeIsReleasedWhenIdle(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	p := newPasteReader(pr, &pasteState{})
	go func() { _, _ = pw.Write([]byte("\x1b[2")) }()
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := p.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case s := <-got:
		if s != "\x1b[2" {
			t.Fatalf("got %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a partial escape was held without new bytes")
	}
}

func TestUnclosedPasteIdleTimeoutRejects(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	st := &pasteState{}
	p := newPasteReader(pr, st)
	p.idle = 100 * time.Millisecond
	go func() { _, _ = pw.Write([]byte("\x1b[200~rm -rf /\n")) }()
	read := func() string {
		got := make(chan string, 1)
		go func() {
			buf := make([]byte, 64)
			n, _ := p.Read(buf)
			got <- string(buf[:n])
		}()
		select {
		case s := <-got:
			return s
		case <-time.After(2 * time.Second):
			t.Fatal("unclosed paste kept swallowing input")
			return ""
		}
	}
	if s := read(); s != pasteRejectedLine+"\n" {
		t.Fatalf("got %q", s)
	}
	if st.reason != "paste rejected: unclosed" || st.text != "" {
		t.Fatalf("reason %q text %q", st.reason, st.text)
	}
	go func() { _, _ = pw.Write([]byte("\x03")) }()
	if s := read(); s != "\x03" {
		t.Fatalf("Ctrl-C after timeout %q", s)
	}
}

func TestEditorInputFiltersOnlyWhenBracketed(t *testing.T) {
	in := io.NopCloser(strings.NewReader("x"))
	if got := editorInput(in, false, &pasteState{}); got != in {
		t.Fatalf("filter wrapped a non-bracketed input: %T", got)
	}
	if _, ok := editorInput(in, true, &pasteState{}).(*pasteReader); !ok {
		t.Fatal("bracketed input was not filtered")
	}
}

type fakeLines struct {
	lines  []string
	prompt string
}

func (f *fakeLines) Readline() (string, error) {
	if len(f.lines) == 0 {
		return "", io.EOF
	}
	l := f.lines[0]
	f.lines = f.lines[1:]
	return l, nil
}

func (f *fakeLines) SetPrompt(p string) { f.prompt = p }

func TestReadPendingSkipsPasteToken(t *testing.T) {
	rl := &fakeLines{lines: []string{"[paste held: 2 lines]", "echo x }", "foo " + pasteRejectedLine, "catch { echo y }"}}
	var out bytes.Buffer
	buf, abort, eof, err := readPending(rl, "try {", "adssh> ", &out)
	if err != nil || abort || eof {
		t.Fatalf("abort %v eof %v err %v", abort, eof, err)
	}
	if strings.Contains(buf, "paste") || strings.Contains(buf, "foo") {
		t.Fatalf("review token entered the block: %q", buf)
	}
	if buf != "try {\necho x }\ncatch { echo y }" {
		t.Fatalf("buf %q", buf)
	}
	if !strings.Contains(out.String(), "paste") {
		t.Fatalf("no message: %q", out.String())
	}
}

func TestStarlarkContinuationSkipsPasteToken(t *testing.T) {
	rl := &fakeLines{lines: []string{"[paste held: 3 lines]", "  return 1", ""}}
	var out bytes.Buffer
	buf := readStarlarkBlock(rl, "def f():", &out)
	if buf != "def f():\n  return 1" {
		t.Fatalf("buf %q", buf)
	}
	if !strings.Contains(out.String(), "paste") {
		t.Fatalf("no message: %q", out.String())
	}
}

func TestSafePasteRunTryCatchBlock(t *testing.T) {
	run, out, errOut, globals := testPasteRunner(t, false)
	st := &pasteState{text: "try {\n  false\n} catch {\n  echo CAUGHT\n}", lines: 5}
	handlePasteLine("safepaste run", st, run)
	if out.String() != "CAUGHT\n" {
		t.Fatalf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if globals["?"].String() != "0" {
		t.Fatalf("status %v", globals["?"])
	}
}

func TestSafePasteRunMixedChunks(t *testing.T) {
	run, out, errOut, globals := testPasteRunner(t, false)
	var hooks []string
	globals["__preexec__"] = starlark.NewBuiltin("pre", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		hooks = append(hooks, string(args[0].(starlark.String)))
		return starlark.None, nil
	})
	text := "x = 40 + 2\necho shell-ok\ndef f():\n    y = x + 1\n    return y\nz = f()\nif true { echo flow-ok }"
	st := &pasteState{text: text, lines: 7}
	handlePasteLine("safepaste run", st, run)
	if got := globals["z"]; got == nil || got.String() != "43" {
		t.Fatalf("z = %v stderr %q", got, errOut.String())
	}
	if out.String() != "shell-ok\nflow-ok\n" {
		t.Fatalf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if len(hooks) != 5 {
		t.Fatalf("preexec per chunk: %q", hooks)
	}
	if globals["?"].String() != "0" {
		t.Fatalf("status %v", globals["?"])
	}
}

func TestSafePasteRunStarlarkRunsOnce(t *testing.T) {
	run, _, _, globals := testPasteRunner(t, false)
	calls := 0
	globals["bump"] = starlark.NewBuiltin("bump", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		calls++
		return starlark.None, nil
	})
	st := &pasteState{text: "print(bump() + 1)", lines: 1}
	handlePasteLine("safepaste run", st, run)
	if calls != 1 {
		t.Fatalf("bump ran %d times", calls)
	}
	if globals["?"].String() == "0" {
		t.Fatal("failed expression reported success")
	}
}

func TestSafePasteRunPolicyDenialStopsAndAudits(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	eng, err := security.NewEngine(security.EngineConfig{
		PolicySource: []byte("package adssh.authz\ndefault allow = false\nallow = true { input.command != \"dangerous\" }\ndeny_reason = \"nope\" { input.command == \"dangerous\" }\n"),
		AuditLogPath: auditPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	prev := security.DefaultEngine()
	security.SetDefaultEngine(eng)
	t.Cleanup(func() { security.SetDefaultEngine(prev) })

	run, out, errOut, globals := testPasteRunner(t, false)
	st := &pasteState{text: "echo before\ndangerous --now\necho after", lines: 3}
	handlePasteLine("safepaste run", st, run)
	if !strings.Contains(out.String(), "before") || strings.Contains(out.String(), "after") {
		t.Fatalf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if globals["?"].String() == "0" {
		t.Fatal("denied paste reported success")
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "dangerous") || !strings.Contains(string(data), "allowed=false") {
		t.Fatalf("audit %q", data)
	}
}
