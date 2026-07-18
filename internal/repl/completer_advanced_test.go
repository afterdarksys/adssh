package repl

import "testing"

func TestAdvancedVBinSubcommandCompletions(t *testing.T) {
	wants := map[string][]string{
		"runbook": {"list", "show", "run"},
		"from":    {"json", "jsonl", "csv"},
		"to":      {"json", "jsonl", "csv", "table"},
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
		}
	}
}
