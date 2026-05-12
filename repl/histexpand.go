package repl

import (
	"strings"
)

// ExpandHistory expands bash-style history references in line.
// history is the list of previous commands (oldest first).
// Returns the expanded line and whether an expansion happened.
//
// Supported forms:
//
//	!!        — last command
//	!-1       — last command (same as !!)
//	!-N       — Nth most recent command
//	!$        — last word of last command
//	!^        — first word (arg) of last command
//	!*        — all args of last command (everything after first word)
//	^old^new  — substitute old→new in last command (no leading !)
func ExpandHistory(line string, history []string) (string, bool) {
	if len(history) == 0 {
		return line, false
	}

	last := history[len(history)-1]

	// ^old^new substitution
	if strings.HasPrefix(line, "^") {
		rest := line[1:]
		idx := strings.Index(rest, "^")
		if idx >= 0 {
			old := rest[:idx]
			newVal := rest[idx+1:]
			expanded := strings.Replace(last, old, newVal, 1)
			if expanded != last {
				return expanded, true
			}
		}
		return line, false
	}

	if !strings.HasPrefix(line, "!") {
		return line, false
	}

	// Split off the designator: everything up to the first space.
	// Allow "!!ls" to mean "!! ls" (designator is !!, rest is "ls").
	designator := line
	suffix := ""
	if sp := strings.Index(line, " "); sp >= 0 {
		designator = line[:sp]
		suffix = line[sp:] // includes the space
	}

	nthCommand := func(n int) (string, bool) {
		// n=1 → last, n=2 → second to last, etc.
		idx := len(history) - n
		if idx < 0 || idx >= len(history) {
			return "", false
		}
		return history[idx], true
	}

	lastWords := func() []string {
		return strings.Fields(last)
	}

	switch {
	case designator == "!!":
		return last + suffix, true

	case strings.HasPrefix(designator, "!-"):
		numStr := designator[2:]
		if numStr == "" {
			return line, false
		}
		n := 0
		for _, c := range numStr {
			if c < '0' || c > '9' {
				return line, false
			}
			n = n*10 + int(c-'0')
		}
		if cmd, ok := nthCommand(n); ok {
			return cmd + suffix, true
		}
		return line, false

	case designator == "!$":
		words := lastWords()
		if len(words) == 0 {
			return line, false
		}
		return words[len(words)-1] + suffix, true

	case designator == "!^":
		words := lastWords()
		if len(words) < 2 {
			return line, false
		}
		return words[1] + suffix, true

	case designator == "!*":
		words := lastWords()
		if len(words) < 2 {
			return line, false
		}
		return strings.Join(words[1:], " ") + suffix, true
	}

	return line, false
}
