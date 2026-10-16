//go:build unix

package sys

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareChildCredentialFailClosed(t *testing.T) {
	origEuid := geteuid
	origLookup := lookupUser
	origGroups := userGroupIDs
	origTest := runningUnderTest
	t.Cleanup(func() {
		geteuid = origEuid
		lookupUser = origLookup
		userGroupIDs = origGroups
		runningUnderTest = origTest
	})
	runningUnderTest = func() bool { return true }

	unmarked := &Session{ID: "cred-unmarked", User: "nobody"}
	geteuid = func() int { t.Fatal("unmarked session called geteuid"); return 0 }
	cmd := &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(cmd, unmarked); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Fatal("unmarked session set a credential")
	}

	marked := &Session{ID: "cred-marked", User: "nobody"}
	marked.SetDropPrivileges(true)
	geteuid = func() int { return 1 }
	lookupUser = func(string) (*user.User, error) { t.Fatal("non-root called lookup"); return nil, nil }
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(cmd, marked); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Fatal("non-root session set a credential")
	}

	geteuid = func() int { return 0 }
	lookupUser = func(string) (*user.User, error) { t.Fatal("empty user called lookup"); return nil, nil }
	empty := &Session{ID: "cred-empty", User: ""}
	empty.SetDropPrivileges(true)
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}, SysProcAttr: &syscall.SysProcAttr{Setsid: true}}
	if err := PrepareChild(cmd, empty); err == nil {
		t.Fatal("empty user was accepted")
	}
	if cmd.SysProcAttr.Credential != nil || !cmd.SysProcAttr.Setsid {
		t.Fatalf("SysProcAttr = %+v", cmd.SysProcAttr)
	}

	lookupUser = func(string) (*user.User, error) { return nil, fmt.Errorf("no such user") }
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}, SysProcAttr: &syscall.SysProcAttr{Setsid: true}}
	if err := PrepareChild(cmd, marked); err == nil {
		t.Fatal("lookup failure was accepted")
	}
	if cmd.SysProcAttr.Credential != nil {
		t.Fatal("lookup failure set a credential")
	}

	lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "nope", Gid: "1"}, nil
	}
	userGroupIDs = func(*user.User) ([]string, error) { t.Fatal("uid parse called GroupIds"); return nil, nil }
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(cmd, marked); err == nil || (cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil) {
		t.Fatalf("uid parse err=%v cred=%v", err, cmd.SysProcAttr)
	}

	lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "1", Gid: "nope"}, nil
	}
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(cmd, marked); err == nil || (cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil) {
		t.Fatalf("gid parse err=%v cred=%v", err, cmd.SysProcAttr)
	}

	lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "1", Gid: "2"}, nil
	}
	userGroupIDs = func(*user.User) ([]string, error) { return nil, fmt.Errorf("groups down") }
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(cmd, marked); err == nil || (cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil) {
		t.Fatalf("GroupIds err=%v cred=%v", err, cmd.SysProcAttr)
	}

	userGroupIDs = func(*user.User) ([]string, error) { return []string{"2", "bad"}, nil }
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(cmd, marked); err == nil || (cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil) {
		t.Fatalf("group parse err=%v cred=%v", err, cmd.SysProcAttr)
	}

	lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "0", Gid: "0"}, nil
	}
	userGroupIDs = func(*user.User) ([]string, error) { return []string{"0"}, nil }
	root := &Session{ID: "cred-root", User: "root"}
	root.SetDropPrivileges(true)
	cmd = &exec.Cmd{Path: "/bin/true", Args: []string{"true"}, SysProcAttr: &syscall.SysProcAttr{Setsid: true}}
	if err := PrepareChild(cmd, root); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid != 0 || !cmd.SysProcAttr.Setsid {
		t.Fatalf("root credential = %+v", cmd.SysProcAttr)
	}
}

func TestRequireResolvableSSHUserFailClosed(t *testing.T) {
	origLookup := lookupUser
	t.Cleanup(func() { lookupUser = origLookup })
	if err := RequireResolvableSSHUser(""); err == nil {
		t.Fatal("empty ssh user was accepted")
	}
	lookupUser = func(string) (*user.User, error) { return nil, fmt.Errorf("missing") }
	if err := RequireResolvableSSHUser("ghost"); err == nil {
		t.Fatal("unresolvable ssh user was accepted")
	}
}

func TestPrepareChildNilCommand(t *testing.T) {
	if err := PrepareChild(nil, nil); err == nil {
		t.Fatal("nil command was accepted")
	}
}

func TestWrapSessionLimits(t *testing.T) {
	origTest := runningUnderTest
	origExe := executable
	origLimits := setSessionLimitsForTest(hostLimits{nofile: 256, nproc: 64, as: 1 << 30, fsize: 1 << 30, cpu: 0})
	t.Cleanup(func() {
		runningUnderTest = origTest
		executable = origExe
		setSessionLimitsForTest(origLimits)
	})
	runningUnderTest = func() bool { return false }

	cmd := &exec.Cmd{Path: "/bin/ls", Args: []string{"ls", "-l"}}
	executable = func() (string, error) { return "/fake/adssh", nil }
	if err := PrepareChild(cmd, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"/fake/adssh", "--session-child", "nofile=256", "nproc=64", "as=1073741824", "fsize=1073741824", "cpu=0", "--", "/bin/ls", "ls", "-l"}
	if cmd.Path != "/fake/adssh" || !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("wrapped path=%s args=%#v", cmd.Path, cmd.Args)
	}

	executable = func() (string, error) { return "", fmt.Errorf("no exe") }
	plain := &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(plain, nil); err == nil {
		t.Fatal("executable failure was ignored")
	}
	if plain.Path != "/bin/true" || !reflect.DeepEqual(plain.Args, []string{"true"}) {
		t.Fatalf("executable failure rewrote %#v %s", plain.Args, plain.Path)
	}

	executable = func() (string, error) { t.Fatal("wrap ran for an existing --session-child"); return "", nil }
	already := &exec.Cmd{Path: "/bin/true", Args: []string{"adssh", "--session-child", "nofile=1", "--", "/bin/true"}}
	if err := PrepareChild(already, nil); err != nil {
		t.Fatal(err)
	}

	setSessionLimitsForTest(hostLimits{})
	executable = func() (string, error) { t.Fatal("wrap ran with zero limits"); return "", nil }
	zero := &exec.Cmd{Path: "/bin/true", Args: []string{"true"}}
	if err := PrepareChild(zero, nil); err != nil {
		t.Fatal(err)
	}
	if zero.Path != "/bin/true" {
		t.Fatalf("zero limits rewrote path to %s", zero.Path)
	}
}

func TestApplyOneLimit(t *testing.T) {
	origGet := getRlimit
	origSet := setRlimit
	t.Cleanup(func() {
		getRlimit = origGet
		setRlimit = origSet
	})

	var got unix.Rlimit
	called := false
	getRlimit = func(res int, rlim *unix.Rlimit) error {
		rlim.Cur = 64
		rlim.Max = 32
		return nil
	}
	setRlimit = func(res int, rlim *unix.Rlimit) error {
		called = true
		got = *rlim
		return nil
	}
	if err := applyOneLimit("nofile", 100); err != nil {
		t.Fatal(err)
	}
	if !called || got.Cur != 32 || got.Max != 32 {
		t.Fatalf("clamp got %+v called=%v", got, called)
	}

	getRlimit = func(res int, rlim *unix.Rlimit) error {
		rlim.Cur = 16
		rlim.Max = unix.RLIM_INFINITY
		return nil
	}
	if err := applyOneLimit("nofile", 100); err != nil {
		t.Fatal(err)
	}
	if got.Cur != 100 || got.Max != unix.RLIM_INFINITY {
		t.Fatalf("infinity clamp got %+v", got)
	}

	setRlimit = func(int, *unix.Rlimit) error { t.Fatal("zero limit called setrlimit"); return nil }
	if err := applyOneLimit("nofile", 0); err != nil {
		t.Fatal(err)
	}
	getRlimit = func(int, *unix.Rlimit) error { t.Fatal("unknown key called getrlimit"); return nil }
	if err := applyOneLimit("nope", 1); err == nil {
		t.Fatal("unknown limit was accepted")
	}
}

func TestRunSessionChildFailClosed(t *testing.T) {
	origGet := getRlimit
	origSet := setRlimit
	origExec := execProcess
	t.Cleanup(func() {
		getRlimit = origGet
		setRlimit = origSet
		execProcess = origExec
	})
	getRlimit = func(res int, rlim *unix.Rlimit) error {
		rlim.Cur = 1024
		rlim.Max = unix.RLIM_INFINITY
		return nil
	}
	setRlimit = func(int, *unix.Rlimit) error { return nil }

	getRlimit = func(int, *unix.Rlimit) error { t.Fatal("unknown key called getrlimit"); return nil }
	if err := runSessionChild([]string{"adssh", "--session-child", "nope=1", "--", "/bin/true"}); err == nil {
		t.Fatal("unknown key was accepted")
	}

	execProcess = func(string, []string, []string) error { t.Fatal("setrlimit failure exec'd"); return nil }
	setRlimit = func(int, *unix.Rlimit) error { return fmt.Errorf("boom") }
	getRlimit = func(res int, rlim *unix.Rlimit) error {
		rlim.Max = unix.RLIM_INFINITY
		return nil
	}
	if err := runSessionChild([]string{"adssh", "--session-child", "nofile=1", "--", "/bin/true"}); err == nil {
		t.Fatal("setrlimit failure was ignored")
	}

	execProcess = func(string, []string, []string) error { t.Fatal("missing -- exec'd"); return nil }
	setRlimit = func(int, *unix.Rlimit) error { t.Fatal("nofile=0 called setrlimit"); return nil }
	if err := runSessionChild([]string{"adssh", "--session-child", "nofile=0"}); err == nil || !strings.Contains(err.Error(), "--") {
		t.Fatalf("missing --: %v", err)
	}

	var gotPath string
	var gotArgv []string
	var gotEnv []string
	execProcess = func(path string, argv []string, env []string) error {
		gotPath = path
		gotArgv = append([]string(nil), argv...)
		gotEnv = append([]string(nil), env...)
		return nil
	}
	if err := runSessionChild([]string{"adssh", "--session-child", "nofile=0", "--", "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bin/true" || !reflect.DeepEqual(gotArgv, []string{"/bin/true"}) || !reflect.DeepEqual(gotEnv, os.Environ()) {
		t.Fatalf("exec path=%s argv=%#v", gotPath, gotArgv)
	}
}

func TestSessionChildReexecNOFILE(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	var cur unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &cur); err != nil {
		t.Fatal(err)
	}
	want := cur.Cur
	if want > 64 {
		want = 64
	}
	if cur.Max != unix.RLIM_INFINITY && want > cur.Max {
		want = cur.Max
	}
	if want == 0 {
		t.Skip("RLIMIT_NOFILE soft limit is 0")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(limit uint64) (string, error) {
		cmd := exec.Command(exe, "--session-child",
			fmt.Sprintf("nofile=%d", limit),
			"nproc=0", "as=0", "fsize=0", "cpu=0",
			"--", "/bin/sh", "sh", "-c", "ulimit -n")
		out, runErr := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), runErr
	}
	out, err := run(want)
	if err != nil && want != cur.Cur {
		want = cur.Cur
		out, err = run(want)
	}
	if err != nil {
		t.Fatalf("session child (%s): %v\n%s", runtime.GOARCH, err, out)
	}
	if out != strconv.FormatUint(want, 10) {
		t.Fatalf("ulimit -n = %q, want %d", out, want)
	}
}
