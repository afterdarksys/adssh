package main

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrepFailures(t *testing.T) {
	for _, args := range [][]string{{"grep", "["}, {"grep", "x", filepath.Join(t.TempDir(), "missing")}} {
		if err := run(io.NopCloser(strings.NewReader("x\n")), io.Discard, io.Discard, args); err == nil {
			t.Fatalf("%v succeeded", args)
		}
	}
	if err := run(io.NopCloser(strings.NewReader(strings.Repeat("x", 128<<10))), io.Discard, io.Discard, []string{"grep", "x"}); err == nil {
		t.Fatal("oversized line succeeded")
	}
}
func TestGrepNoMatch(t *testing.T) {
	if err := run(io.NopCloser(strings.NewReader("abc\n")), io.Discard, io.Discard, []string{"grep", "zzz"}); !errors.Is(err, errQuiet) {
		t.Fatalf("no-match: %v", err)
	}
}
