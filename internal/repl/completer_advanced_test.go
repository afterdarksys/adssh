package repl

import "testing"

func TestAdvancedVBinSubcommandCompletions(t *testing.T) {
	wants := map[string][]string{
		"runbook": {"list", "show", "run"},
		"plugin":  {"list", "load", "reload"},
		"from":    {"json", "jsonl", "csv"},
		"to":      {"json", "jsonl", "csv", "table"},
		"whoami":  {"-v", "--caps", "--json"},
		"mirror":  {"share", "unshare"},
	}
	for command, expected := range wants {
		actual := vbinSubcommands[command]
		for _, wanted := range expected {
			found := false
			for _, value := range actual {
				if value == wanted {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s completions %v do not include %q", command, actual, wanted)
			}
			if command == "mirror" && !containsString(mirrorSubcmds, wanted) {
				t.Errorf("mirror first-argument completions %v do not include %q", mirrorSubcmds, wanted)
			}
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
