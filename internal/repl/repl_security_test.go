package repl

import "testing"

func TestBackgroundSyntaxRemainsInAuthorizedShellProgram(t *testing.T) {
	if command, intercepted := isBackgroundLine("dangerous --arg &"); intercepted {
		t.Fatalf("background command was extracted for direct execution: %q", command)
	}
}
