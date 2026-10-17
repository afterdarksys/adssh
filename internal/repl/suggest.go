package repl

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// suggestInitial is the starting state of history suggestions. ADSSH_SUGGEST
// (on/off, 1/0, true/false, yes/no) wins; otherwise they are on in a local
// session and off in an SSH session, where a screen reader would read the
// dim suggestion text after the cursor aloud.
func suggestInitial(env string, sshSession bool) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return !sshSession
}

// applySuggest parses `set suggest [on|off]`. Other lines are not handled.
func applySuggest(line string, on bool) (next, handled bool, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "set" || fields[1] != "suggest" {
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
	return on, true, errors.New("set suggest: usage: set suggest [on|off]")
}

// handleSuggestLine applies a `set suggest` line and reports the state. It
// needs no gate: it changes only what is drawn after the cursor.
func handleSuggestLine(line string, cur bool, out, errOut io.Writer) (next, handled bool) {
	next, handled, err := applySuggest(line, cur)
	if !handled {
		return cur, false
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return cur, true
	}
	state := "off"
	if next {
		state = "on"
	}
	fmt.Fprintf(out, "suggest %s\n", state)
	return next, true
}
