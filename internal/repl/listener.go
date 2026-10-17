package repl

import (
	"fmt"
	"strings"
	"sync"

	"github.com/chzyer/readline"
)

// Threats: a history suggestion is display only. It is drawn by
// suggestionPainter and is never part of the edit buffer, so the line that
// runs is exactly what was typed, plus the suggestion only when → or Ctrl-F
// accepted it at the end of the line. History is written to the terminal, so
// an entry with a control character (an escape sequence saved in the history
// file) is never suggested. The suggestion is cut to the room left on the
// cursor's row; a wrapped suggestion would leave text the next redraw does
// not clear.

// adsshListener accepts a fish-style history suggestion.
type adsshListener struct {
	history *[]string
}

func newAdsshListener(history *[]string) *adsshListener {
	return &adsshListener{history: history}
}

// OnChange is called by readline on every keystroke. It changes the line only
// when → or Ctrl-F is pressed at the end of the line and a suggestion exists.
func (l *adsshListener) OnChange(line []rune, pos int, key rune) ([]rune, int, bool) {
	if key != readline.CharForward || pos != len(line) {
		return nil, 0, false
	}
	rest := historySuggestion(*l.history, string(line))
	if rest == "" {
		return nil, 0, false
	}
	accepted := []rune(string(line) + rest)
	return accepted, len(accepted), true
}

// Ensure adsshListener satisfies readline.Listener at compile time.
var _ readline.Listener = (*adsshListener)(nil)

// historySuggestion returns the rest of the newest history entry that starts
// with line and is longer than it, or "". Entries with a control character
// are skipped.
func historySuggestion(hist []string, line string) string {
	if line == "" {
		return ""
	}
	for i := len(hist) - 1; i >= 0; i-- {
		entry := hist[i]
		if len(entry) <= len(line) || !strings.HasPrefix(entry, line) {
			continue
		}
		if hasControl(entry) {
			continue
		}
		return entry[len(line):]
	}
	return ""
}

// hasControl reports whether s contains a C0 or C1 control character or DEL.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return true
		}
	}
	return false
}

const ansiDim = "\x1b[2m"

// suggestionPainter draws the dim history suggestion after the cursor when
// the cursor is at the end of the line, then moves the cursor back over it.
type suggestionPainter struct {
	inner   readline.Painter
	history *[]string
	width   func() int

	mu     sync.Mutex
	prompt string
}

// setPrompt records the prompt readline draws before the line, so the
// suggestion can be cut to the room left on the row.
func (p *suggestionPainter) setPrompt(s string) {
	p.mu.Lock()
	p.prompt = s
	p.mu.Unlock()
}

func (p *suggestionPainter) Paint(line []rune, pos int) []rune {
	out := line
	if p.inner != nil {
		out = p.inner.Paint(line, pos)
	}
	// An empty line is checked before history is read: the main loop appends
	// to history after Enter, while a highlight refresh can still repaint the
	// empty buffer.
	if len(line) == 0 || pos != len(line) {
		return out
	}
	ghost := []rune(historySuggestion(*p.history, string(line)))
	if len(ghost) == 0 {
		return out
	}
	p.mu.Lock()
	prompt := p.prompt
	p.mu.Unlock()
	if i := strings.LastIndexByte(prompt, '\n'); i >= 0 {
		prompt = prompt[i+1:]
	}
	var rs readline.Runes
	// One column stays free so the cursor never sits past the last column.
	room := p.width() - rs.WidthAll([]rune(stripANSI(prompt))) - rs.WidthAll(line) - 1
	ghost = fitWidth(ghost, room)
	if len(ghost) == 0 {
		return out
	}
	painted := make([]rune, 0, len(out)+len(ghost)+16)
	painted = append(painted, out...)
	painted = append(painted, []rune(ansiDim+string(ghost)+ansiReset)...)
	painted = append(painted, []rune(fmt.Sprintf("\x1b[%dD", rs.WidthAll(ghost)))...)
	return painted
}

// fitWidth returns the longest prefix of r that is at most room columns wide.
func fitWidth(r []rune, room int) []rune {
	if room <= 0 {
		return nil
	}
	var rs readline.Runes
	used := 0
	for i, c := range r {
		w := rs.Width(c)
		if used+w > room {
			return r[:i]
		}
		used += w
	}
	return r
}

// promptEditor is the line editor with prompt changes reported to the
// suggestion painter.
type promptEditor struct {
	*readline.Instance
	painter *suggestionPainter
}

func (e *promptEditor) SetPrompt(s string) {
	e.painter.setPrompt(s)
	e.Instance.SetPrompt(s)
}

// stripANSI removes ANSI escape sequences from s using a simple state machine.
func stripANSI(s string) string {
	out := make([]byte, 0, len(s))
	inEsc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inEsc {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				inEsc = false
			}
			continue
		}
		if c == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			inEsc = true
			i++ // skip '['
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
