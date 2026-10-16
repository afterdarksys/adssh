//go:build unix

package sys

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func saveSpawnHooks(t *testing.T) {
	t.Helper()
	prevRun := runSSHCommand
	prevExe := executable
	prevEuid := geteuid
	prevLookup := lookupUser
	prevGroups := userGroupIDs
	prevTest := runningUnderTest
	prevLimits := sessionLimits()
	prevHook := currentSSHMonitorServer()
	t.Cleanup(func() {
		runSSHCommand = prevRun
		executable = prevExe
		geteuid = prevEuid
		lookupUser = prevLookup
		userGroupIDs = prevGroups
		runningUnderTest = prevTest
		setSessionLimitsForTest(prevLimits)
		SetSSHMonitorServer(prevHook)
	})
}

func installSpawnFakes(t *testing.T) {
	t.Helper()
	if defaultSessionCPU != 14400 {
		t.Fatalf("defaultSessionCPU = %d, want 14400", defaultSessionCPU)
	}
	runningUnderTest = func() bool { return false }
	executable = func() (string, error) { return "/fake/adssh", nil }
	geteuid = func() int { return 1 }
	lookupUser = func(string) (*user.User, error) {
		t.Errorf("lookupUser called")
		return nil, errors.New("not found")
	}
	userGroupIDs = func(*user.User) ([]string, error) {
		t.Errorf("userGroupIDs called")
		return nil, errors.New("no groups")
	}
	setSessionLimitsForTest(hostLimits{
		nofile: defaultSessionNOFILE,
		nproc:  defaultSessionNPROC,
		as:     defaultSessionAS,
		fsize:  defaultSessionFSIZE,
		cpu:    defaultSessionCPU,
	})
}

func markSpawnSession(t *testing.T, id, userName string, drop bool) {
	t.Helper()
	sess := &Session{ID: id, User: userName}
	sess.SetDropPrivileges(drop)
	if err := RegisterSession(sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { UnregisterSession(id) })
}

func openSpawnPTY(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

type spawnSnap struct {
	args                  []string
	setsid, setctty       bool
	ctty                  int
	cred                  *syscall.Credential
	extra                 int
	stdin, stdout, stderr *os.File
	envSet                bool
	dir                   string
	path                  string
}

func snapshotSpawn(cmd *exec.Cmd) spawnSnap {
	got := spawnSnap{
		args:   append([]string(nil), cmd.Args...),
		extra:  len(cmd.ExtraFiles),
		envSet: cmd.Env != nil,
		dir:    cmd.Dir,
		path:   cmd.Path,
	}
	got.stdin, _ = cmd.Stdin.(*os.File)
	got.stdout, _ = cmd.Stdout.(*os.File)
	got.stderr, _ = cmd.Stderr.(*os.File)
	if cmd.SysProcAttr != nil {
		got.setsid = cmd.SysProcAttr.Setsid
		got.setctty = cmd.SysProcAttr.Setctty
		got.ctty = cmd.SysProcAttr.Ctty
		if cmd.SysProcAttr.Credential != nil {
			c := *cmd.SysProcAttr.Credential
			c.Groups = append([]uint32(nil), cmd.SysProcAttr.Credential.Groups...)
			got.cred = &c
		}
	}
	return got
}

func assertSpawnErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "sekret") {
		t.Fatal("value leaked")
	}
	if err.Error() != want {
		t.Fatalf("got %q want %q", err.Error(), want)
	}
}

func TestSpawnSSHSessionWrapsAndHooks(t *testing.T) {
	saveSpawnHooks(t)
	installSpawnFakes(t)
	id := "spawn-wrap"
	userName := "bob"
	markSpawnSession(t, id, userName, true)
	pty := openSpawnPTY(t)
	var got spawnSnap
	runSSHCommand = func(cmd *exec.Cmd) error {
		got = snapshotSpawn(cmd)
		return nil
	}
	hookCh := make(chan string, 1)
	SetSSHMonitorServer(func(conn net.Conn, sessionID string) {
		if conn == nil || conn.LocalAddr() == nil || conn.LocalAddr().Network() != "unix" || conn.LocalAddr().String() != "ssh-monitor" {
			hookCh <- "bad"
			return
		}
		hookCh <- sessionID
	})
	if err := SpawnSSHSession(SSHSessionSpec{
		SessionID:   id,
		User:        userName,
		Principals:  []string{"p1", "p2"},
		Restricted:  true,
		MenuPath:    "/menu",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
		PTY:         pty,
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/fake/adssh", "--session-child",
		"nofile=256", "nproc=64", "as=1073741824", "fsize=1073741824", "cpu=14400",
		"--", "/fake/adssh",
		"/fake/adssh", "--ssh-session",
		"--session-id", id,
		"--ssh-user", userName,
		"--monitor-fd", "3",
		"--restricted",
		"--menu", "/menu",
		"--history", "/hist",
		"--profile", "/profile",
		"--rc", "/rc",
		"--principal", "p1",
		"--principal", "p2",
	}
	if got.path != "/fake/adssh" || !reflect.DeepEqual(got.args, want) {
		t.Fatalf("path=%s args=%#v", got.path, got.args)
	}
	if got.extra != 1 || got.stdin != pty || got.stdout != pty || got.stderr != pty {
		t.Fatal("stdio")
	}
	if !got.setsid || !got.setctty || got.ctty != 0 || got.cred != nil || !got.envSet || got.dir != "" {
		t.Fatal("proc attr")
	}
	select {
	case hooked := <-hookCh:
		if hooked != id {
			t.Fatalf("hook = %s", hooked)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hook did not run")
	}
}

func TestSpawnSSHSessionOmitsOptionalFlags(t *testing.T) {
	saveSpawnHooks(t)
	installSpawnFakes(t)
	id := "spawn-plain"
	userName := "bob"
	markSpawnSession(t, id, userName, true)
	pty := openSpawnPTY(t)
	var got spawnSnap
	runSSHCommand = func(cmd *exec.Cmd) error {
		got = snapshotSpawn(cmd)
		return nil
	}
	SetSSHMonitorServer(func(net.Conn, string) {})
	if err := SpawnSSHSession(SSHSessionSpec{
		SessionID:   id,
		User:        userName,
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
		PTY:         pty,
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/fake/adssh", "--session-child",
		"nofile=256", "nproc=64", "as=1073741824", "fsize=1073741824", "cpu=14400",
		"--", "/fake/adssh",
		"/fake/adssh", "--ssh-session",
		"--session-id", id,
		"--ssh-user", userName,
		"--monitor-fd", "3",
		"--history", "/hist",
		"--profile", "/profile",
		"--rc", "/rc",
	}
	if !reflect.DeepEqual(got.args, want) {
		t.Fatalf("args=%#v", got.args)
	}
}

func TestSpawnSSHSessionCredentialSurvives(t *testing.T) {
	saveSpawnHooks(t)
	installSpawnFakes(t)
	geteuid = func() int { return 0 }
	lookupUser = func(name string) (*user.User, error) {
		if name != "dropme" {
			t.Errorf("lookup name")
		}
		return &user.User{Uid: "1000", Gid: "1000", Username: name}, nil
	}
	userGroupIDs = func(*user.User) ([]string, error) {
		return []string{"1000"}, nil
	}
	id := "spawn-cred"
	markSpawnSession(t, id, "dropme", true)
	pty := openSpawnPTY(t)
	var got spawnSnap
	runSSHCommand = func(cmd *exec.Cmd) error {
		got = snapshotSpawn(cmd)
		return nil
	}
	SetSSHMonitorServer(func(net.Conn, string) {})
	if err := SpawnSSHSession(SSHSessionSpec{
		SessionID:   id,
		User:        "dropme",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
		PTY:         pty,
	}); err != nil {
		t.Fatal(err)
	}
	if got.cred == nil || got.cred.Uid != 1000 || got.cred.Gid != 1000 || !got.setsid {
		t.Fatal("credential")
	}
	found := false
	for _, g := range got.cred.Groups {
		if g == 1000 {
			found = true
		}
	}
	if !found {
		t.Fatal("groups")
	}
}

func TestSpawnSSHSessionLookupFailure(t *testing.T) {
	saveSpawnHooks(t)
	installSpawnFakes(t)
	geteuid = func() int { return 0 }
	lookupUser = func(string) (*user.User, error) {
		return nil, errors.New("not found")
	}
	id := "spawn-lookup"
	markSpawnSession(t, id, "dropme", true)
	pty := openSpawnPTY(t)
	var started atomic.Int32
	runSSHCommand = func(*exec.Cmd) error {
		started.Add(1)
		return nil
	}
	var hooked atomic.Int32
	SetSSHMonitorServer(func(net.Conn, string) { hooked.Add(1) })
	err := SpawnSSHSession(SSHSessionSpec{
		SessionID:   id,
		User:        "dropme",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
		PTY:         pty,
	})
	assertSpawnErr(t, err, "adssh: session user: not found")
	if strings.Contains(err.Error(), "dropme") {
		t.Fatal("value leaked")
	}
	if hooked.Load() != 0 || started.Load() != 0 {
		t.Fatal("hook or start ran")
	}
}

func TestSpawnSSHSessionFailClosed(t *testing.T) {
	saveSpawnHooks(t)
	installSpawnFakes(t)

	var started atomic.Int32
	runSSHCommand = func(*exec.Cmd) error {
		started.Add(1)
		return nil
	}
	var hooked atomic.Int32
	SetSSHMonitorServer(nil)

	err := SpawnSSHSession(SSHSessionSpec{User: "bob"})
	assertSpawnErr(t, err, "adssh: ssh session: invalid value")
	if hooked.Load() != 0 || started.Load() != 0 {
		t.Fatal("invalid spec called the hook")
	}

	SetSSHMonitorServer(func(net.Conn, string) { hooked.Add(1) })
	err = SpawnSSHSession(SSHSessionSpec{
		SessionID:   "-sekret",
		User:        "bob",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
	})
	assertSpawnErr(t, err, "adssh: ssh session: invalid value")
	err = SpawnSSHSession(SSHSessionSpec{
		SessionID:   "ok",
		User:        "sekret\x00",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
	})
	assertSpawnErr(t, err, "adssh: ssh session: invalid value")
	if hooked.Load() != 0 || started.Load() != 0 {
		t.Fatal("bad value called the hook")
	}

	SetSSHMonitorServer(nil)
	id := "spawn-nil-hook"
	markSpawnSession(t, id, "bob", true)
	err = SpawnSSHSession(SSHSessionSpec{
		SessionID:   id,
		User:        "bob",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
		PTY:         openSpawnPTY(t),
	})
	assertSpawnErr(t, err, "adssh: ssh session: monitor is not configured")
	if started.Load() != 0 {
		t.Fatal("nil hook started")
	}

	SetSSHMonitorServer(func(net.Conn, string) { hooked.Add(1) })
	err = SpawnSSHSession(SSHSessionSpec{
		SessionID:   "spawn-missing",
		User:        "bob",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
		PTY:         openSpawnPTY(t),
	})
	assertSpawnErr(t, err, "adssh: ssh session: refusing unmarked session")

	markSpawnSession(t, "spawn-unmarked", "bob", false)
	err = SpawnSSHSession(SSHSessionSpec{
		SessionID:   "spawn-unmarked",
		User:        "bob",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
		PTY:         openSpawnPTY(t),
	})
	assertSpawnErr(t, err, "adssh: ssh session: refusing unmarked session")

	markSpawnSession(t, "spawn-nil-pty", "bob", true)
	err = SpawnSSHSession(SSHSessionSpec{
		SessionID:   "spawn-nil-pty",
		User:        "bob",
		HistoryFile: "/hist",
		ProfilePath: "/profile",
		RCPath:      "/rc",
	})
	assertSpawnErr(t, err, "adssh: ssh session: pty is not a file")
	if hooked.Load() != 0 || started.Load() != 0 {
		t.Fatal("refused spawn called the hook")
	}
}

func TestCloexecSocketpair(t *testing.T) {
	fds, err := cloexecSocketpair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	for _, fd := range fds {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("fd %d is not cloexec", fd)
		}
	}
}

func TestOpenMonitorFDRejectsOtherNumbers(t *testing.T) {
	for _, fd := range []int{0, 4} {
		_, err := OpenMonitorFD(fd)
		assertSpawnErr(t, err, "adssh: ssh session: monitor fd must be 3")
		if fd == 4 && strings.Contains(err.Error(), "4") {
			t.Fatal("value leaked")
		}
	}
}
