package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsSSHSessionArgv(t *testing.T) {
	if !isSSHSessionArgv([]string{"adssh", "--ssh-session"}) {
		t.Fatal("want true")
	}
	if isSSHSessionArgv(nil) {
		t.Fatal("nil")
	}
	if isSSHSessionArgv([]string{"adssh"}) {
		t.Fatal("short")
	}
	if isSSHSessionArgv([]string{"adssh", "script", "--ssh-session"}) {
		t.Fatal("script")
	}
	if isSSHSessionArgv([]string{"adssh", "--restricted", "--ssh-session"}) {
		t.Fatal("flag before mode")
	}
}

func TestParseSSHSessionArgsHappy(t *testing.T) {
	opts, err := parseSSHSessionArgs([]string{
		"adssh", "--ssh-session",
		"--restricted",
		"--session-id", "first",
		"--ssh-user", "bob",
		"--monitor-fd", "3",
		"--menu", "/menu",
		"--history", "/hist",
		"--profile", "/profile",
		"--rc", "/rc",
		"--principal", "p1",
		"--principal", "p2",
		"--session-id", "second",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.restricted || opts.menu != "/menu" || opts.sessionID != "second" || opts.user != "bob" {
		t.Fatalf("%#v", opts)
	}
	if opts.history != "/hist" || opts.profile != "/profile" || opts.rc != "/rc" {
		t.Fatalf("%#v", opts)
	}
	if !reflect.DeepEqual(opts.principals, []string{"p1", "p2"}) {
		t.Fatalf("principals %#v", opts.principals)
	}
}

func TestParseSSHSessionArgsMinimal(t *testing.T) {
	opts, err := parseSSHSessionArgs([]string{
		"adssh", "--ssh-session",
		"--session-id", "sid",
		"--ssh-user", "bob",
		"--monitor-fd", "3",
		"--history", "/hist",
		"--profile", "/profile",
		"--rc", "/rc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.restricted || opts.menu != "" || len(opts.principals) != 0 {
		t.Fatalf("%#v", opts)
	}
	if opts.sessionID != "sid" || opts.user != "bob" || opts.history != "/hist" || opts.profile != "/profile" || opts.rc != "/rc" {
		t.Fatalf("%#v", opts)
	}
}

func TestParseSSHSessionArgsRejects(t *testing.T) {
	base := []string{
		"adssh", "--ssh-session",
		"--session-id", "sid",
		"--ssh-user", "bob",
		"--monitor-fd", "3",
		"--history", "/hist",
		"--profile", "/profile",
		"--rc", "/rc",
	}
	without := func(flag string) []string {
		out := make([]string, 0, len(base))
		for i := 0; i < len(base); i++ {
			if base[i] == flag {
				i++
				continue
			}
			out = append(out, base[i])
		}
		return out
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing user", args: without("--ssh-user"), want: "adssh: ssh session: invalid value"},
		{name: "missing history", args: without("--history"), want: "adssh: ssh session: invalid value"},
		{name: "unknown flag", args: append(append([]string{}, base...), "--nope"), want: "adssh: ssh session: invalid value"},
		{name: "leading dash", args: append(without("--ssh-user"), "--ssh-user", "-sekret"), want: "adssh: ssh session: invalid value"},
		{name: "nul", args: append(without("--ssh-user"), "--ssh-user", "bob\x00sekret"), want: "adssh: ssh session: invalid value"},
		{name: "fd omitted", args: without("--monitor-fd"), want: "adssh: ssh session: invalid value"},
		{name: "fd missing value", args: append(without("--monitor-fd"), "--monitor-fd"), want: "adssh: ssh session: monitor fd must be 3"},
		{name: "fd 4", args: append(without("--monitor-fd"), "--monitor-fd", "4"), want: "adssh: ssh session: monitor fd must be 3"},
		{name: "fd 03", args: append(without("--monitor-fd"), "--monitor-fd", "03"), want: "adssh: ssh session: monitor fd must be 3"},
		{name: "fd dash", args: append(without("--monitor-fd"), "--monitor-fd", "-sekret"), want: "adssh: ssh session: monitor fd must be 3"},
		{name: "fd empty", args: append(without("--monitor-fd"), "--monitor-fd", ""), want: "adssh: ssh session: monitor fd must be 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSSHSessionArgs(tc.args)
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), "sekret") {
				t.Fatal("value leaked")
			}
			if err.Error() != tc.want {
				t.Fatalf("got %q want %q", err.Error(), tc.want)
			}
		})
	}
}

func TestSSHOverlaySessionCarriesPrincipals(t *testing.T) {
	s := newSSHOverlaySession(sshSessionOpts{sessionID: "ov-1", user: "alice", principals: []string{"ops", "dba"}})
	if s.ID != "ov-1" || s.User != "alice" {
		t.Fatalf("session = %+v", s)
	}
	if len(s.Principals) != 2 || s.Principals[0] != "ops" || s.Principals[1] != "dba" {
		t.Fatalf("principals = %v", s.Principals)
	}
}
