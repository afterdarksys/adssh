package repl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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
// The review token is not a command. safepaste run is the only path that
// executes a held paste, and that path uses the same policy gate as a typed
// command. This does not inspect the clipboard and does not change the OS pasteboard.

const (
	bracketPasteStart = "\x1b[200~"
	bracketPasteEnd   = "\x1b[201~"
	pasteHeldPrefix   = "[paste held:"
	pasteRejectedLine = "[paste rejected]"
	maxBracketPaste   = 1 << 20
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
	state     *pasteState
}

func newPasteReader(r io.ReadCloser, state *pasteState) *pasteReader {
	if state == nil {
		state = &pasteState{}
	}
	return &pasteReader{r: r, state: state}
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
		emit, needMore := p.crunch()
		if len(emit) > 0 {
			p.out = append(p.out, emit...)
		}
		if len(p.out) > 0 {
			break
		}
		if !needMore {
			if p.sawEOF {
				return 0, io.EOF
			}
		}
		if err := p.fill(); err != nil {
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

// fill reads the next chunk. lastFull reports whether the buffer was filled,
// which is the only case where a trailing partial bracket is held for the
// next read. A short read is a complete key or a complete paste.
func (p *pasteReader) fill() error {
	buf := make([]byte, 4096)
	n, err := p.r.Read(buf)
	p.lastFull = n == len(buf)
	if n > 0 {
		p.acc = append(p.acc, buf[:n]...)
	}
	return err
}

// crunch pulls every complete decision out of acc. needMore is true when a
// partial escape or an open paste still needs bytes.
func (p *pasteReader) crunch() (emit []byte, needMore bool) {
	for {
		if p.collect {
			idx := bytes.Index(p.acc, []byte(bracketPasteEnd))
			if idx >= 0 {
				body := append([]byte(nil), p.acc[:idx]...)
				p.acc = p.acc[idx+len(bracketPasteEnd):]
				p.collect = false
				emit = append(emit, p.finishPaste(body)...)
				continue
			}
			if p.sawEOF {
				p.collect = false
				p.overflow = false
				p.discarded = 0
				p.acc = nil
				p.state.clear()
				p.state.reason = "paste rejected: unclosed"
				return append(emit, []byte(pasteRejectedLine+"\n")...), false
			}
			if p.overflow || len(p.acc)+p.discarded > maxBracketPaste {
				p.overflow = true
				keep := len(bracketPasteEnd) - 1
				if len(p.acc) > keep {
					p.discarded += len(p.acc) - keep
					p.acc = append([]byte(nil), p.acc[len(p.acc)-keep:]...)
				}
			}
			return emit, true
		}

		start := bytes.Index(p.acc, []byte(bracketPasteStart))
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
			// Hold the fragment only when the producer filled the read
			// buffer. A short read is a finished key, including a lone ESC.
			if p.lastFull && !p.sawEOF {
				return emit, true
			}
			emit = append(emit, p.acc...)
			p.acc = nil
			return emit, false
		}
		emit = append(emit, p.acc...)
		p.acc = nil
		return emit, false
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
	case line == pasteRejectedLine:
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

func runHeldPaste(text string, run pasteRunner) int {
	first := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			first = line
			break
		}
	}
	if parser.DetermineMode(first) == parser.ModeStarlark {
		return evalStarlark(run.thread, text, run.globals, run.errOut)
	}
	return runShellSource(run, text)
}

func runShellSource(run pasteRunner, src string) int {
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
		runErr = run.runner.Run(context.Background(), file)
	}
	if runErr == nil {
		return 0
	}
	if exitErr, ok := runErr.(interp.ExitStatus); ok {
		return int(exitErr)
	}
	fmt.Fprintf(run.errOut, "Command error: %v\n", runErr)
	return 1
}
