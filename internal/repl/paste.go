package repl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/parser"
	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Threats: a bracketed paste is untrusted terminal input. A newline inside
// the paste must not submit the line. Oversized pastes and pastes that carry
// control bytes other than tab and newline are discarded and never executed.
// Bytes that arrive in the same read as a paste end, and a paste end outside
// a paste, mean the clipboard carried its own end marker: the whole paste is
// rejected. A start marker split across reads is held until the rest arrives
// or the line goes idle. A paste with no end marker is rejected after
// pasteIdleTimeout, so Ctrl-C and Enter work again. The review token is not a
// command, and continuation prompts do not add it to a block. safepaste run
// is the only path that executes a held paste: each chunk goes through the
// same mode choice, policy gate, and hooks as a typed command. This does not
// inspect the clipboard and does not change the OS pasteboard. Bytes that
// arrive after an idle rejection are typed input again.

const (
	bracketPasteStart = "\x1b[200~"
	bracketPasteEnd   = "\x1b[201~"
	pasteHeldPrefix   = "[paste held:"
	pasteRejectedLine = "[paste rejected]"
	maxBracketPaste   = 1 << 20

	pasteReadSize = 4096
	// pasteIdleTimeout ends an open paste that has stopped sending bytes.
	pasteIdleTimeout = 2 * time.Second
	// escapeHoldTimeout is how long a partial start marker waits for the
	// rest. A lone ESC key is released after it.
	escapeHoldTimeout = 100 * time.Millisecond
)

// pasteState is the held multiline paste for one REPL.
type pasteState struct {
	text   string
	lines  int
	reason string
}

func (s *pasteState) clear() {
	s.text = ""
	s.lines = 0
	s.reason = ""
}

// editorInput puts the paste filter in front of the line editor only when
// bracketed-paste mode was enabled. Without it the terminal never marks a
// paste, so there is nothing to filter.
func editorInput(in io.ReadCloser, bracketed bool, state *pasteState) io.ReadCloser {
	if !bracketed {
		return in
	}
	return newPasteReader(in, state)
}

type readResult struct {
	b   []byte
	err error
}

type waitKind int

const (
	waitNone waitKind = iota
	waitEscape
	waitPaste
)

// pasteReader sits in front of the line editor. Bytes outside a bracketed
// paste pass through. A paste that contains a newline is stored and replaced
// with a review token that does not end the line.
type pasteReader struct {
	r         io.ReadCloser
	acc       []byte
	out       []byte
	sawEOF    bool
	collect   bool
	overflow  bool
	discarded int
	lastFull  bool
	pending   chan readResult
	idle      time.Duration
	escHold   time.Duration
	state     *pasteState
}

func newPasteReader(r io.ReadCloser, state *pasteState) *pasteReader {
	if state == nil {
		state = &pasteState{}
	}
	return &pasteReader{r: r, state: state, idle: pasteIdleTimeout, escHold: escapeHoldTimeout}
}

func (p *pasteReader) Close() error {
	if p.r == nil {
		return nil
	}
	return p.r.Close()
}

func (p *pasteReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for len(p.out) == 0 {
		emit, wait := p.crunch()
		p.out = append(p.out, emit...)
		if len(p.out) > 0 {
			break
		}
		if p.sawEOF {
			return 0, io.EOF
		}
		var timeout time.Duration
		switch wait {
		case waitEscape:
			timeout = p.escHold
		case waitPaste:
			timeout = p.idle
		}
		timedOut, err := p.fill(timeout)
		if timedOut {
			if wait == waitPaste {
				p.acc = nil
				p.out = append(p.out, p.reject("paste rejected: unclosed")...)
			} else {
				p.out = append(p.out, p.acc...)
				p.acc = nil
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				p.sawEOF = true
				continue
			}
			return 0, err
		}
	}
	n := copy(b, p.out)
	p.out = p.out[n:]
	return n, nil
}

// fill waits for the next chunk. At most one read is outstanding: when the
// wait times out, the read stays pending and the next fill takes its result.
// timeout 0 waits without a limit.
func (p *pasteReader) fill(timeout time.Duration) (timedOut bool, err error) {
	if p.pending == nil {
		ch := make(chan readResult, 1)
		p.pending = ch
		r := p.r
		go func() {
			buf := make([]byte, pasteReadSize)
			n, err := r.Read(buf)
			ch <- readResult{b: buf[:n], err: err}
		}()
	}
	var expire <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		expire = t.C
	}
	select {
	case res := <-p.pending:
		p.pending = nil
		p.lastFull = len(res.b) == pasteReadSize
		p.acc = append(p.acc, res.b...)
		return false, res.err
	case <-expire:
		return true, nil
	}
}

// reject clears any held paste, records reason, and returns the line that
// tells the REPL to print it.
func (p *pasteReader) reject(reason string) []byte {
	p.collect = false
	p.overflow = false
	p.discarded = 0
	p.state.clear()
	p.state.reason = reason
	return []byte(pasteRejectedLine + "\n")
}

// crunch pulls every complete decision out of acc. wait says what the next
// read is waiting for: the rest of a split start marker, or the rest of an
// open paste.
func (p *pasteReader) crunch() (emit []byte, wait waitKind) {
	for {
		if p.collect {
			idx := bytes.Index(p.acc, []byte(bracketPasteEnd))
			if idx >= 0 {
				body := append([]byte(nil), p.acc[:idx]...)
				trailing := len(p.acc) > idx+len(bracketPasteEnd)
				p.acc = nil
				p.collect = false
				if trailing || p.lastFull {
					reason := "paste rejected: data after paste end"
					if p.overflow || len(body)+p.discarded > maxBracketPaste {
						reason = "paste rejected: too large"
					}
					return append(emit, p.reject(reason)...), waitNone
				}
				return append(emit, p.finishPaste(body)...), waitNone
			}
			if p.sawEOF {
				p.acc = nil
				return append(emit, p.reject("paste rejected: unclosed")...), waitNone
			}
			if p.overflow || len(p.acc)+p.discarded > maxBracketPaste {
				p.overflow = true
				keep := len(bracketPasteEnd) - 1
				if len(p.acc) > keep {
					p.discarded += len(p.acc) - keep
					p.acc = append([]byte(nil), p.acc[len(p.acc)-keep:]...)
				}
			}
			return emit, waitPaste
		}

		start := bytes.Index(p.acc, []byte(bracketPasteStart))
		plain := p.acc
		if start >= 0 {
			plain = p.acc[:start]
		}
		// A paste end outside a paste is the tail of a clipboard that carried
		// its own end marker. Nothing in this read is typed input.
		if bytes.Contains(plain, []byte(bracketPasteEnd)) {
			p.acc = nil
			return append(emit, p.reject("paste rejected: data after paste end")...), waitNone
		}
		if start >= 0 {
			emit = append(emit, p.acc[:start]...)
			p.acc = p.acc[start+len(bracketPasteStart):]
			p.collect = true
			p.overflow = false
			p.discarded = 0
			continue
		}
		if n := partialBracketSuffix(p.acc); n > 0 {
			emit = append(emit, p.acc[:len(p.acc)-n]...)
			p.acc = append([]byte(nil), p.acc[len(p.acc)-n:]...)
			if !p.sawEOF {
				return emit, waitEscape
			}
			emit = append(emit, p.acc...)
			p.acc = nil
			return emit, waitNone
		}
		emit = append(emit, p.acc...)
		p.acc = nil
		return emit, waitNone
	}
}

// bracketPasteTTY is the session output when it is a real terminal.
// Bracketed-paste mode is enabled only for that writer.
func bracketPasteTTY(out io.Writer) *os.File {
	if bc, ok := out.(*sys.OutputBroadcaster); ok {
		return bc.PrimaryTerminalFile()
	}
	f, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil
	}
	return f
}

func partialBracketSuffix(acc []byte) int {
	prefix := bracketPasteStart
	max := len(prefix) - 1
	if len(acc) < max {
		max = len(acc)
	}
	for n := max; n > 0; n-- {
		if bytes.Equal(acc[len(acc)-n:], []byte(prefix[:n])) {
			return n
		}
	}
	return 0
}

func (p *pasteReader) finishPaste(body []byte) []byte {
	defer func() {
		p.overflow = false
		p.discarded = 0
	}()
	if p.overflow || len(body)+p.discarded > maxBracketPaste {
		p.state.clear()
		p.state.reason = "paste rejected: too large"
		return []byte(pasteRejectedLine + "\n")
	}
	if reason := pasteControlReason(body); reason != "" {
		p.state.clear()
		p.state.reason = reason
		return []byte(pasteRejectedLine + "\n")
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if bytes.Contains(body, []byte(pasteHeldPrefix)) || bytes.Contains(body, []byte(pasteRejectedLine)) ||
		strings.Contains(text, pasteHeldPrefix) || strings.Contains(text, pasteRejectedLine) {
		p.state.clear()
		p.state.reason = "paste rejected: review token"
		return []byte(pasteRejectedLine + "\n")
	}
	if !strings.Contains(text, "\n") {
		p.state.clear()
		return body
	}
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		p.state.clear()
		return nil
	}
	lines := strings.Count(text, "\n") + 1
	p.state.text = text
	p.state.lines = lines
	p.state.reason = ""
	// No trailing newline: the editor must not submit this token.
	return []byte(fmt.Sprintf("%s %d lines]", pasteHeldPrefix, lines))
}

func pasteControlReason(body []byte) string {
	for _, b := range body {
		if b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return "paste rejected: control character"
		}
	}
	return ""
}

type pasteRunner struct {
	state    *security.SessionState
	runner   *interp.Runner
	thread   *starlark.Thread
	globals  starlark.StringDict
	out      io.Writer
	errOut   io.Writer
	markBusy func(bool)
}

// handlePasteLine owns review tokens and the safepaste command. Other lines
// return false so the REPL evaluates them as usual.
func handlePasteLine(line string, st *pasteState, run pasteRunner) bool {
	if st == nil {
		return false
	}
	switch {
	case strings.Contains(line, pasteRejectedLine):
		reason := st.reason
		st.clear()
		if reason == "" {
			reason = "paste rejected"
		}
		fmt.Fprintln(run.errOut, reason)
		return true
	case strings.Contains(line, pasteHeldPrefix):
		writePastePreview(run.errOut, st)
		return true
	}
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != "safepaste" {
		return false
	}
	if len(fields) != 2 {
		fmt.Fprintln(run.errOut, "safepaste: usage: safepaste show|run|drop")
		return true
	}
	switch fields[1] {
	case "show":
		if st.text == "" {
			fmt.Fprintln(run.errOut, "safepaste: nothing held")
			return true
		}
		fmt.Fprintln(run.out, st.text)
		return true
	case "drop":
		st.clear()
		fmt.Fprintln(run.errOut, "safepaste: dropped")
		return true
	case "run":
		text := st.text
		if text == "" {
			fmt.Fprintln(run.errOut, "safepaste: nothing held")
			return true
		}
		st.clear()
		code := runHeldPaste(text, run)
		run.globals["?"] = starlark.MakeInt(code)
		return true
	default:
		fmt.Fprintln(run.errOut, "safepaste: usage: safepaste show|run|drop")
		return true
	}
}

func writePastePreview(errOut io.Writer, st *pasteState) {
	if st.text == "" {
		fmt.Fprintln(errOut, "paste: nothing held")
		return
	}
	lines := strings.Split(st.text, "\n")
	limit := 20
	if len(lines) < limit {
		limit = len(lines)
	}
	fmt.Fprintf(errOut, "paste held: %d lines. Review, then safepaste run, safepaste show, or safepaste drop.\n", st.lines)
	for _, line := range lines[:limit] {
		fmt.Fprintf(errOut, "  %s\n", line)
	}
	if len(lines) > 20 {
		fmt.Fprintf(errOut, "  ... %d more lines\n", len(lines)-20)
	}
}

// errPasteStopped ends a held paste after a chunk fails.
var errPasteStopped = errors.New("safepaste: stopped")

// runHeldPaste runs the held text chunk by chunk, as if each chunk had been
// typed: flow blocks, Starlark, and shell each run in their own mode under
// the session gate and hooks. The first failing chunk stops the paste, so a
// later line never runs after a failed or denied one. A chunk with a leading
// "-" may fail and the paste goes on.
func runHeldPaste(text string, run pasteRunner) int {
	code := 0
	err := AccumulateScript(text, func(chunk string, line int, ignore bool) error {
		code = runPasteChunk(run, chunk)
		if code != 0 && !ignore {
			return errPasteStopped
		}
		return nil
	})
	if err != nil && !errors.Is(err, errPasteStopped) {
		fmt.Fprintf(run.errOut, "safepaste: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// runPasteChunk runs one chunk the way the REPL runs a typed chunk and
// returns its exit status.
func runPasteChunk(run pasteRunner, chunk string) int {
	ctx, done := beginSessionCommand(run.globals, chunk)
	defer done()
	callHook(run.globals, "__preexec__", starlark.Tuple{starlark.String(chunk)})
	code := 0
	kind := parser.ClassifyChunk(chunk)
	switch {
	case kind.Kind == parser.ChunkSyntax:
		fmt.Fprintf(run.errOut, "safepaste: %v\n", kind.Err)
		code = 1
	case parser.ClassifyFlow(chunk).Kind == parser.FlowReady:
		if run.markBusy != nil {
			run.markBusy(true)
		}
		err := RunFlow(chunk, FlowExec{
			Gate: func(node syntax.Node) error {
				return security.GateProgramSession(run.state, node)
			},
			Runner: run.runner,
			Ctx:    ctx,
		})
		if run.markBusy != nil {
			run.markBusy(false)
		}
		code = shellStatus(run, err)
	case kind.Mode == parser.ModeStarlark:
		code = evalStarlark(run.thread, chunk, run.globals, run.errOut)
	default:
		code = runShellSource(run, ctx, chunk)
	}
	run.globals["?"] = starlark.MakeInt(code)
	callHook(run.globals, "__postcmd__", starlark.Tuple{starlark.String(chunk), starlark.MakeInt(code)})
	return code
}

// beginSessionCommand gives the chunk a cancelable context on the session,
// as the REPL does for a typed command. done clears it.
func beginSessionCommand(globals starlark.StringDict, cmd string) (context.Context, func()) {
	id, ok := globals["SESSION_ID"].(starlark.String)
	if !ok {
		return context.Background(), func() {}
	}
	session := sys.GetSession(string(id))
	if session == nil {
		return context.Background(), func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	session.SetContext(ctx, cancel)
	session.SetCurrentCommand(cmd)
	return ctx, func() {
		cancel()
		session.SetContext(context.Background(), nil)
		session.SetCurrentCommand("")
	}
}

func runShellSource(run pasteRunner, ctx context.Context, src string) int {
	src = strings.TrimSpace(src)
	if strings.HasPrefix(src, "!") {
		src = strings.TrimSpace(src[1:])
	} else if strings.HasPrefix(src, "$ ") {
		src = strings.TrimSpace(src[2:])
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(src), "paste")
	if err != nil {
		fmt.Fprintf(run.errOut, "Parse error: %v\n", err)
		return 1
	}
	if run.markBusy != nil {
		run.markBusy(true)
		defer run.markBusy(false)
	}
	runErr := security.GateProgramSession(run.state, file)
	if runErr == nil {
		runErr = run.runner.Run(ctx, file)
	}
	return shellStatus(run, runErr)
}

func shellStatus(run pasteRunner, err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(interp.ExitStatus); ok {
		return int(exitErr)
	}
	if errors.Is(err, context.Canceled) {
		return 1
	}
	fmt.Fprintf(run.errOut, "Command error: %v\n", err)
	return 1
}
