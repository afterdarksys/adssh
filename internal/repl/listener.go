package repl

import "github.com/chzyer/readline"

// adsshListener implements readline.Listener for fish-style autosuggestions.
type adsshListener struct {
	history *[]string
}

func newAdsshListener(history *[]string) *adsshListener {
	return &adsshListener{history: history}
}

// OnChange is called by readline on every keystroke.
func (l *adsshListener) OnChange(line []rune, pos int, key rune) ([]rune, int, bool) {
	// Strip any ANSI codes we previously injected.
	actual := stripANSI(string(line))
	actualRunes := []rune(actual)
	actualLen := len(actualRunes)

	if actual == "" {
		return nil, 0, false
	}

	// If cursor is not at end of actual content, return cleaned line with no ghost.
	if pos < actualLen {
		return actualRunes, pos, true
	}

	// If cursor advanced into the ghost region, the user pressed →: accept suggestion.
	if pos > actualLen {
		// Find best suggestion to accept.
		hist := *l.history
		for i := len(hist) - 1; i >= 0; i-- {
			entry := hist[i]
			if len(entry) > len(actual) && entry[:len(actual)] == actual {
				accepted := []rune(entry)
				return accepted, len(accepted), true
			}
		}
		// No suggestion — return actual at end.
		return actualRunes, actualLen, true
	}

	// pos == actualLen: search history backward for prefix match longer than actual.
	hist := *l.history
	var ghost string
	for i := len(hist) - 1; i >= 0; i-- {
		entry := hist[i]
		if len(entry) > len(actual) && entry[:len(actual)] == actual {
			ghost = entry[len(actual):]
			break
		}
	}

	if ghost == "" {
		return actualRunes, actualLen, true
	}

	// Return actual + dim ghost.
	ghosted := []rune(actual + "\x1b[2m" + ghost + "\x1b[0m")
	return ghosted, actualLen, true
}

// Ensure adsshListener satisfies readline.Listener at compile time.
var _ readline.Listener = (*adsshListener)(nil)

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
