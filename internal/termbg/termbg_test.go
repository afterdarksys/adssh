package termbg

import "testing"

func TestDark(t *testing.T) {
	for v, want := range map[string]bool{"": true, "dark": true, "light": false, " LIGHT ": false, "garbage": true} {
		if got := Dark(v); got != want {
			t.Errorf("Dark(%q) = %v, want %v", v, got, want)
		}
	}
}

// The init-order guarantee depends on this path sorting before bubbletea's.
func TestImportPathSortsBeforeBubbletea(t *testing.T) {
	if "github.com/afterdarksys/adssh/internal/termbg" >= "github.com/charmbracelet/bubbletea" {
		t.Fatal("termbg no longer initializes before bubbletea")
	}
}
