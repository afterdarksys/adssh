package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Threats: every string adsshadm prints that came from the server was typed
// by some user: a pending command, a session's current command, a ban reason,
// an error message. A raw ESC, CR, or bidi override in it can rewrite what the
// operator sees, so an approval prompt could show "ls" for "rm -rf /data".
// clean renders C0, DEL, C1, format characters (Cf: bidi controls, zero-width
// characters), and invalid UTF-8 visibly instead.

// unsafeRune reports whether r can move the cursor, erase, or reorder text.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == utf8.RuneError:
		return true // invalid UTF-8 decodes to this; never pass raw bytes
	case unicode.Is(unicode.Cf, r):
		return true // bidi overrides and isolates, zero-width and other format characters
	}
	return false
}

// clean returns s with every unsafe rune replaced by a visible escape.
func clean(s string) string {
	if strings.IndexFunc(s, unsafeRune) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafeRune(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// cleanJSON escapes the unsafe runes encoding/json leaves raw (DEL, C1,
// bidi controls) as \uXXXX, which keeps the output valid JSON.
func cleanJSON(b []byte) []byte {
	s := string(b)
	if strings.IndexFunc(s, unsafeRune) < 0 {
		return b
	}
	var out strings.Builder
	for _, r := range s {
		if unsafeRune(r) && r != '\n' {
			fmt.Fprintf(&out, `\u%04x`, r)
			continue
		}
		out.WriteRune(r)
	}
	return []byte(out.String())
}
