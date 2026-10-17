package repl

// Threats: pre-enter highlighting asks the policy about a line the operator
// has not run. It must not run anything, so the line is only parsed (no
// expansion, no command substitution, no alias or function lookup) and the
// policy is asked through ExplainCommand, which evaluates the stages without
// executing the command, creating approval requests, or writing audit
// entries. Because the probe is unaudited, turning highlighting on is itself
// a gated, audited command (`set highlight on` reaches the gate as
// "set highlight on"), so a policy that hides its shape can deny it. The
// color is advice: the gate still decides when the line runs. The policy
// call runs on a timer goroutine after a debounce and never on the input
// path, so a slow policy cannot block typing. Highlighting is off unless
// stdout is a terminal, and the menu REPL never installs it. An SSH session
// child cannot ask its listener's policy without a gate round trip, so there
// only the destructive check colors the line.

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/afterdarksys/adssh/internal/risk"
	"github.com/afterdarksys/adssh/parser"
	"github.com/afterdarksys/adssh/security"

	"mvdan.cc/sh/v3/syntax"
)

type highlightLevel int

const (
	highlightNone highlightLevel = iota
	highlightDestructive
	highlightDenied
	highlightSyntax
)

const (
	highlightDebounce = 150 * time.Millisecond
	// highlightMaxCommands bounds the policy calls for one line.
	highlightMaxCommands = 8
	ansiReset            = "\x1b[0m"
)

// denyFunc reports whether the gate would deny a command (args[0] is the name).
type denyFunc func(args []string) bool

// highlightColor is the ANSI color for a level: red when policy would deny,
// yellow when destructive, underlined magenta when the line cannot parse,
// none otherwise.
func highlightColor(level highlightLevel) string {
	switch level {
	case highlightSyntax:
		return "\x1b[4;35m"
	case highlightDenied:
		return "\x1b[31m"
	case highlightDestructive:
		return "\x1b[33m"
	default:
		return ""
	}
}

// classifyHighlight decides the color of an edited line. Shell lines have
// each simple command checked against denied (literal words only); every line
// gets the shared destructive check.
func classifyHighlight(line string, denied denyFunc) highlightLevel {
	text := strings.TrimSpace(stripANSI(line))
	if text == "" {
		return highlightNone
	}
	// A line neither the shell nor Starlark can parse cannot run at all.
	// An unfinished line (open quote, trailing |, block start) is not flagged.
	if parser.SyntaxError(text) {
		return highlightSyntax
	}
	if denied != nil && parser.DetermineMode(text) != parser.ModeStarlark {
		shell := text
		if strings.HasPrefix(shell, "!") {
			shell = shell[1:]
		} else if strings.HasPrefix(shell, "$ ") {
			shell = shell[2:]
		}
		for _, args := range literalCommands(shell, highlightMaxCommands) {
			if denied(args) {
				return highlightDenied
			}
		}
	}
	if risk.LooksDestructive(text) {
		return highlightDestructive
	}
	return highlightNone
}

// literalCommands parses src and returns up to max simple commands, each cut
// at its first word that is not a plain literal. A command whose name is not
// literal is skipped. Nothing is expanded or run. Commands inside $(...) are
// included because they would run too.
func literalCommands(src string, max int) [][]string {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil
	}
	var cmds [][]string
	syntax.Walk(f, func(node syntax.Node) bool {
		if len(cmds) >= max {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		var args []string
		for _, w := range call.Args {
			lit := w.Lit()
			if lit == "" {
				break
			}
			args = append(args, lit)
		}
		if len(args) > 0 {
			cmds = append(cmds, args)
		}
		return true
	})
	return cmds
}

// highlighter is the readline Painter. Paint returns at once: a line that has
// no decision yet is shown plain while a debounced timer decides it, then the
// editor is refreshed to repaint it.
type highlighter struct {
	enabled  atomic.Bool
	denied   denyFunc
	refresh  func()
	debounce time.Duration

	mu      sync.Mutex
	line    string // the last line Paint was asked to draw
	gen     uint64 // bumped on every new line; stale decisions are dropped
	timer   *time.Timer
	decided string
	level   highlightLevel
}

// Paint implements readline.Painter.
func (h *highlighter) Paint(line []rune, _ int) []rune {
	if !h.enabled.Load() {
		return line
	}
	s := string(line)
	h.mu.Lock()
	defer h.mu.Unlock()
	if s == h.decided {
		if c := highlightColor(h.level); c != "" {
			return []rune(c + s + ansiReset)
		}
		return line
	}
	if s != h.line {
		h.line = s
		h.gen++
		gen := h.gen
		if h.timer != nil {
			h.timer.Stop()
		}
		h.timer = time.AfterFunc(h.debounce, func() { h.decide(s, gen) })
	}
	return line
}

func (h *highlighter) decide(s string, gen uint64) {
	level := classifyHighlight(s, h.denied)
	h.mu.Lock()
	if gen != h.gen {
		h.mu.Unlock()
		return
	}
	h.decided, h.level = s, level
	h.mu.Unlock()
	if level != highlightNone && h.refresh != nil {
		h.refresh()
	}
}

// policyDenyFunc asks the session's policy through ExplainCommand. An SSH
// session child has no local policy and gets nil (destructive check only).
func policyDenyFunc(sessionID string) denyFunc {
	if security.RemoteGateProcess() {
		return nil
	}
	return func(args []string) bool {
		exp, err := security.DefaultEngine().ExplainCommand(sessionID, args)
		return err == nil && exp.Outcome == "denied"
	}
}

// highlightPermitted: only a terminal gets color.
func highlightPermitted(stdoutTTY bool) bool { return stdoutTTY }

// highlightInitial is the starting state from ADSSH_HIGHLIGHT, when permitted.
func highlightInitial(env string, allowed bool) bool {
	return allowed && gitPromptFromEnv(env)
}

// applyHighlight parses `set highlight [on|off]`. Other lines are not handled.
func applyHighlight(line string, on bool) (next, handled bool, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "set" || fields[1] != "highlight" {
		return on, false, nil
	}
	if len(fields) == 2 {
		return on, true, nil
	}
	if len(fields) == 3 {
		switch fields[2] {
		case "on":
			return true, true, nil
		case "off":
			return false, true, nil
		}
	}
	return on, true, errors.New("set highlight: usage: set highlight [on|off]")
}

// handleHighlightLine applies a `set highlight` line. Turning it on needs a
// terminal and the gate's consent for "set highlight on".
func handleHighlightLine(line string, cur, permitted bool, authorize func([]string) error, out, errOut io.Writer) (next, handled bool) {
	next, handled, err := applyHighlight(line, cur)
	if !handled {
		return cur, false
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return cur, true
	}
	if next && !cur {
		if !permitted {
			fmt.Fprintln(errOut, "set highlight: needs a terminal")
			return false, true
		}
		if err := authorize([]string{"set", "highlight", "on"}); err != nil {
			fmt.Fprintf(errOut, "set highlight: %v\n", err)
			return false, true
		}
	}
	state := "off"
	if next {
		state = "on"
	}
	fmt.Fprintf(out, "highlight %s\n", state)
	return next, true
}
