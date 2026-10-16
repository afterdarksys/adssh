package vbinui

// Must stay imported here, next to bubbletea: it sets the background before
// bubbletea's init can query the terminal. See internal/termbg.
import _ "github.com/afterdarksys/adssh/internal/termbg"
