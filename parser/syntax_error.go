package parser

import (
	"strings"

	shsyntax "mvdan.cc/sh/v3/syntax"
)

// SyntaxError reports whether line is invalid as typed: neither the shell
// nor Starlark can parse it, and it is not merely unfinished (an open quote,
// a trailing |, a block or value continued on the next line). A line forced
// to the shell with ! or "$ " is checked as shell only. It needs no session
// state, so a highlighter may call it off the input goroutine.
func SyntaxError(line string) bool {
	text := strings.TrimSpace(line)
	if text == "" {
		return false
	}
	forced := false
	if strings.HasPrefix(text, "$ ") {
		text, forced = text[2:], true
	} else if strings.HasPrefix(text, "!") {
		text, forced = text[1:], true
	}
	if !shellInvalid(text) {
		return false
	}
	if forced {
		return true
	}
	_, err := starlarkLineOptions.Parse("<line>", text, 0)
	if err == nil {
		return false
	}
	msg := err.Error()
	return !strings.Contains(msg, "got end of file") && !strings.Contains(msg, "unexpected EOF")
}

// shellInvalid reports a shell parse error that more input would not fix.
func shellInvalid(text string) bool {
	_, err := shsyntax.NewParser().Parse(strings.NewReader(text), "")
	return err != nil && !shsyntax.IsIncomplete(err)
}
