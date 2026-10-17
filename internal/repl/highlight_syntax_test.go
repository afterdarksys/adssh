package repl

import "testing"

func TestHighlightFlagsSyntaxErrors(t *testing.T) {
	for _, tc := range []struct {
		line string
		want highlightLevel
	}{
		{"echo )", highlightSyntax},
		{"ls ;; ls", highlightSyntax},
		{`echo "still typing`, highlightNone},
		{"ls -la", highlightNone},
		{"len([1, 2])", highlightNone},
	} {
		if got := classifyHighlight(tc.line, nil); got != tc.want {
			t.Errorf("classifyHighlight(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
	if highlightColor(highlightSyntax) == "" {
		t.Fatal("syntax errors have no color")
	}
}
