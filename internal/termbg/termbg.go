// Package termbg tells lipgloss the terminal background up front, so nothing
// queries the terminal for it.
//
// bubbletea v1's init calls lipgloss.HasDarkBackground, and termenv answers
// that by writing OSC 11 and a cursor-position request to the terminal and
// reading stdin until a reply or a 5 s timeout. Every adssh start, SSH login
// included, then stalls on a client that does not answer (scripts, ssh -tt,
// test clients) and swallows whatever was typed ahead. Setting the background
// explicitly makes lipgloss skip the query.
//
// This must initialize before github.com/charmbracelet/bubbletea. Go
// initializes ready packages in import-path order (spec, since Go 1.21), and
// github.com/afterdarksys/... sorts before github.com/charmbracelet/..., so a
// package that imports both this and bubbletea gets this first. Keep this
// package's imports to lipgloss and the standard library.
//
// ADSSH_TERM_BACKGROUND=light selects a light background; anything else is
// dark.
package termbg

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func init() {
	lipgloss.SetHasDarkBackground(Dark(os.Getenv("ADSSH_TERM_BACKGROUND")))
}

// Dark reports whether an ADSSH_TERM_BACKGROUND value means a dark background.
func Dark(v string) bool {
	return !strings.EqualFold(strings.TrimSpace(v), "light")
}
