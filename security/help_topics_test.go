package security

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

var ansiSeq = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// TestHelpWelcomeTopicsResolve checks that every "help <topic>" the welcome
// screen suggests opens a real topic, and that help start comes first.
func TestHelpWelcomeTopicsResolve(t *testing.T) {
	PopulateVBINHelp()
	var buf bytes.Buffer
	if err := helpWelcome(&buf); err != nil {
		t.Fatalf("helpWelcome: %v", err)
	}
	text := ansiSeq.ReplaceAllString(buf.String(), "")
	first := strings.Index(text, "help ")
	if first < 0 || !strings.HasPrefix(text[first:], "help start") {
		t.Fatalf("welcome does not mention help start first:\n%s", text)
	}
	topic := regexp.MustCompile(`(?:^|\s)help ([a-z0-9-]+)`)
	subcommands := map[string]bool{"list": true, "search": true, "categories": true, "examples": true}
	seen := 0
	for _, m := range topic.FindAllStringSubmatch(text, -1) {
		if subcommands[m[1]] {
			continue
		}
		seen++
		if _, ok := GetHelp(m[1]); !ok {
			t.Errorf("welcome suggests help %s, which has no topic", m[1])
		}
	}
	if seen == 0 {
		t.Fatal("welcome suggests no topics")
	}
}

// TestHelpSeeAlsoResolve checks every SEE ALSO name points at a real topic.
func TestHelpSeeAlsoResolve(t *testing.T) {
	PopulateVBINHelp()
	for _, e := range AllHelpEntries() {
		for _, name := range e.SeeAlso {
			if _, ok := GetHelp(name); !ok {
				t.Errorf("help %s: SEE ALSO %q has no topic", e.Name, name)
			}
		}
	}
}

// TestHelpNewTopicsExist checks the tour and reference topics are registered.
func TestHelpNewTopicsExist(t *testing.T) {
	for _, name := range []string{"start", "shell", "keys", "adssh-starlark", "starlark"} {
		e, ok := GetHelp(name)
		if !ok {
			t.Errorf("help %s is missing", name)
			continue
		}
		if e.Summary == "" || e.Description == "" {
			t.Errorf("help %s has no summary or description", name)
		}
	}
}

// TestHelpTextAvoidsKnownFalseClaims guards corrections to help text that
// once described behavior adssh does not have.
func TestHelpTextAvoidsKnownFalseClaims(t *testing.T) {
	for _, e := range AllHelpEntries() {
		for _, ex := range e.Examples {
			for _, fn := range []string{"exec_cmd([", "exec_async([", "exec_json(["} {
				if strings.Contains(ex.Command, fn) {
					t.Errorf("help %s example passes a list to %s: %s", e.Name, strings.TrimSuffix(fn, "(["), ex.Command)
				}
			}
			if strings.Contains(ex.Command, "export PROMPT") {
				t.Errorf("help %s: PROMPT is a Starlark variable, not exported: %s", e.Name, ex.Command)
			}
		}
	}
}
