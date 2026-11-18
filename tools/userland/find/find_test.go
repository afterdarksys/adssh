package main

import (
	find "github.com/afterdarksys/adssh/tools/userland/findcmd"
	"path/filepath"
	"testing"
)

func TestFindMissingRootFails(t *testing.T) {
	c := find.New()
	if err := c.Run(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing root reported success")
	}
}
