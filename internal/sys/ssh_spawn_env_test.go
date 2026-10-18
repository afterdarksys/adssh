//go:build unix

package sys

import (
	"net"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func spawnWithUser(t *testing.T, id string, u *user.User, overlayTerm string) (*exec.Cmd, error) {
	t.Helper()
	saveSpawnHooks(t)
	installSpawnFakes(t)
	lookupUser = func(name string) (*user.User, error) {
		if name != u.Username {
			t.Errorf("lookup %q", name)
		}
		return u, nil
	}
	sess := &Session{ID: id, User: u.Username}
	sess.SetDropPrivileges(true)
	if overlayTerm != "" {
		if err := sess.SetEnv("TERM", overlayTerm); err != nil {
			t.Fatal(err)
		}
	}
	if err := RegisterSession(sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { UnregisterSession(id) })
	var got *exec.Cmd
	runSSHCommand = func(cmd *exec.Cmd) error {
		got = cmd
		return nil
	}
	SetSSHMonitorServer(func(net.Conn, string) {})
	err := SpawnSSHSession(SSHSessionSpec{SessionID: id, User: u.Username, PTY: openSpawnPTY(t)})
	return got, err
}

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func argAfter(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

func TestSpawnSSHSessionChildEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ADSSH_AGENT_TOKEN", "listener-secret-token")
	t.Setenv("ADSSH_AUDIT_TOKEN", "listener-audit-token")
	t.Setenv("ADSSH_POLICY", "/root/policy.rego")
	t.Setenv("HOME", "/var/root")
	t.Setenv("USER", "root")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/root-agent")
	t.Setenv("PATH", "/usr/bin:relative/bin::/bin")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("ADSSH_SESSION_NOFILE", "99")
	cmd, err := spawnWithUser(t, "spawn-env", &user.User{Username: "bob", Uid: "1000", Gid: "1000", HomeDir: home}, "vt220")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"HOME":                 home,
		"USER":                 "bob",
		"LOGNAME":              "bob",
		"SHELL":                "/fake/adssh",
		"PATH":                 "/usr/bin:/bin",
		"TERM":                 "vt220",
		"LANG":                 "en_US.UTF-8",
		"ADSSH_SESSION_NOFILE": "99",
	}
	for k, v := range want {
		if got, ok := envValue(cmd.Env, k); !ok || got != v {
			t.Fatalf("%s = %q (%v), want %q; env=%q", k, got, ok, v, cmd.Env)
		}
	}
	for _, kv := range cmd.Env {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := want[k]; !ok {
			t.Fatalf("unexpected variable %q in the session environment", k)
		}
		if strings.Contains(kv, "listener-secret-token") || strings.Contains(kv, "/var/root") {
			t.Fatalf("listener value leaked: %q", kv)
		}
	}
	if cmd.Dir != home {
		t.Fatalf("Dir = %q, want %q", cmd.Dir, home)
	}
	if got := argAfter(cmd.Args, "--history"); got != filepath.Join(home, ".adssh", "history") {
		t.Fatalf("--history = %q", got)
	}
	if got := argAfter(cmd.Args, "--profile"); got != filepath.Join(home, ".adsshprofile") {
		t.Fatalf("--profile = %q", got)
	}
	if got := argAfter(cmd.Args, "--rc"); got != filepath.Join(home, ".adsshrc") {
		t.Fatalf("--rc = %q", got)
	}
}

func TestSpawnSSHSessionEnvironmentDefaults(t *testing.T) {
	t.Setenv("PATH", "relative:also/relative")
	t.Setenv("LANG", "")
	t.Setenv("LC_ALL", "")
	missing := filepath.Join(t.TempDir(), "gone")
	cmd, err := spawnWithUser(t, "spawn-env-default", &user.User{Username: "carol", Uid: "1001", Gid: "1001", HomeDir: missing}, "")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := envValue(cmd.Env, "TERM"); v != "xterm" {
		t.Fatalf("TERM = %q, want xterm", v)
	}
	if v, _ := envValue(cmd.Env, "PATH"); v != defaultSessionPath {
		t.Fatalf("PATH = %q, want the default", v)
	}
	if cmd.Dir != "/" {
		t.Fatalf("Dir = %q, want / for a missing home", cmd.Dir)
	}
	if v, _ := envValue(cmd.Env, "HOME"); v != missing {
		t.Fatalf("HOME = %q", v)
	}
}

func TestSpawnSSHSessionRejectsUnusableHome(t *testing.T) {
	for i, home := range []string{"", "relative/home", "-/x"} {
		id := "spawn-bad-home-" + string(rune('a'+i))
		_, err := spawnWithUser(t, id, &user.User{Username: "dave", Uid: "1002", Gid: "1002", HomeDir: home}, "")
		if err == nil {
			t.Fatalf("home %q was accepted", home)
		}
	}
}

func TestSSHSessionEnvClientLocaleReplacesListener(t *testing.T) {
	t.Setenv("LANG", "C")
	t.Setenv("LC_ALL", "POSIX")
	env := sshSessionEnv(&user.User{Username: "carol"}, "carol", "/home/carol", "/bin/adssh", "xterm", "LANG=en_US.UTF-8")
	if v, _ := envValue(env, "LANG"); v != "en_US.UTF-8" {
		t.Fatalf("LANG = %q, want the client's", v)
	}
	if v, _ := envValue(env, "LC_ALL"); v != "POSIX" {
		t.Fatalf("LC_ALL = %q, want the listener's when the client sent none", v)
	}
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "LANG=") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("LANG appears %d times", n)
	}
}
