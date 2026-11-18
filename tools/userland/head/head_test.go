package main

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeadFailures(t *testing.T) {
	for _, tc := range []struct {
		input string
		files []string
	}{
		{files: []string{filepath.Join(t.TempDir(), "missing")}},
		{input: strings.Repeat("x", 128<<10)},
	} {
		if err := run(strings.NewReader(tc.input), io.Discard, io.Discard, 0, 10, tc.files...); err == nil {
			t.Fatal("input failure reported success")
		}
	}
}
func TestHeadCounts(t *testing.T) {
	var out bytes.Buffer
	if err := run(strings.NewReader("a\nb\n"), &out, io.Discard, 0, 1); err != nil || out.String() != "a\n" {
		t.Fatalf("%q %v", &out, err)
	}
	out.Reset()
	if err := run(strings.NewReader("abc"), &out, io.Discard, 2, 0); err != nil || out.String() != "ab" {
		t.Fatalf("%q %v", &out, err)
	}
}

func TestHeadZeroCountStillRejectsMissingFile(t *testing.T) {
	if err := run(strings.NewReader(""), io.Discard, io.Discard, 0, 0, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted with zero count")
	}
}
