package main

import (
	"testing"
)

func TestParseSSHSessionArgsPluginDir(t *testing.T) {
	base := []string{
		"adssh", "--ssh-session",
		"--session-id", "sid",
		"--ssh-user", "bob",
		"--monitor-fd", "3",
		"--history", "/h", "--profile", "/p", "--rc", "/r",
	}
	opts, err := parseSSHSessionArgs(append(append([]string(nil), base...), "--plugin-dir", "/srv/adssh/plugins"))
	if err != nil {
		t.Fatal(err)
	}
	if opts.pluginDir != "/srv/adssh/plugins" {
		t.Fatalf("plugin dir = %q", opts.pluginDir)
	}
	for _, bad := range [][]string{
		{"--plugin-dir", "relative/plugins"},
		{"--plugin-dir"},
		{"--plugin-dir", "-x"},
	} {
		if _, err := parseSSHSessionArgs(append(append([]string(nil), base...), bad...)); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}
