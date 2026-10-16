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
	"time"

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

	executable = func() (string, error) { return "/fake/adssh", nil }
	alreadyArgs := []string{"/fake/adssh", "--session-child", "nofile=1", "--", "/bin/true"}
	already := &exec.Cmd{Path: "/fake/adssh", Args: append([]string(nil), alreadyArgs...)}
	if err := PrepareChild(already, nil); err != nil {
		t.Fatal(err)
	}
	if already.Path != "/fake/adssh" || !reflect.DeepEqual(already.Args, alreadyArgs) {
		t.Fatalf("an existing wrap was wrapped again: %#v", already.Args)
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
	// The hard limit drops with the soft one, so the dropped user cannot
	// raise it back.
	if got.Cur != 100 || got.Max != 100 {
		t.Fatalf("infinity clamp got %+v", got)
	}

	getRlimit = func(res int, rlim *unix.Rlimit) error {
		rlim.Cur = 16
		rlim.Max = 4096
		return nil
	}
	if err := applyOneLimit("nofile", 100); err != nil {
		t.Fatal(err)
	}
	if got.Cur != 100 || got.Max != 100 {
		t.Fatalf("finite hard limit got %+v", got)
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

func sessionChildCmd(t *testing.T, limits []string, tail ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"--session-child"}, limits...)
	args = append(args, "--")
	args = append(args, tail...)
	return exec.Command(exe, args...)
}

func TestSessionChildCannotRaiseLimit(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	limits := []string{"nofile=64", "nproc=0", "as=0", "fsize=0", "cpu=0"}
	out, err := sessionChildCmd(t, limits, "/bin/sh", "sh", "-c", "ulimit -Hn").CombinedOutput()
	if err != nil {
		t.Fatalf("ulimit -Hn: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "64" {
		t.Fatalf("hard nofile = %q, want 64", got)
	}
	out, err = sessionChildCmd(t, limits, "/bin/sh", "sh", "-c", "ulimit -n 200 && echo raised").CombinedOutput()
	if err == nil || strings.Contains(string(out), "raised") {
		t.Fatalf("session child raised its nofile limit: err=%v out=%q", err, out)
	}
}

func TestRunSessionChildOnlyAsArgv1(t *testing.T) {
	origSet := setRlimit
	origExec := execProcess
	t.Cleanup(func() {
		setRlimit = origSet
		execProcess = origExec
	})
	setRlimit = func(int, *unix.Rlimit) error { t.Fatal("limit applied"); return nil }
	execProcess = func(string, []string, []string) error { t.Fatal("exec ran"); return nil }
	for _, args := range [][]string{
		{"adssh", "script.star", "--session-child", "nofile=1", "--", "/bin/true"},
		{"adssh", "-c", "echo", "--session-child"},
		{"--session-child", "nofile=1", "--", "/bin/true"},
	} {
		if err := runSessionChild(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestWrapSessionLimitsIgnoresUserArgument(t *testing.T) {
	origTest := runningUnderTest
	origExe := executable
	origLimits := setSessionLimitsForTest(hostLimits{nofile: 256})
	t.Cleanup(func() {
		runningUnderTest = origTest
		executable = origExe
		setSessionLimitsForTest(origLimits)
	})
	runningUnderTest = func() bool { return false }
	executable = func() (string, error) { return "/fake/adssh", nil }
	cmd := &exec.Cmd{Path: "/bin/sleep", Args: []string{"sleep", "9", "--session-child"}}
	if err := PrepareChild(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/fake/adssh" || len(cmd.Args) < 2 || cmd.Args[1] != "--session-child" {
		t.Fatalf("user argument skipped the limit wrap: path=%s args=%#v", cmd.Path, cmd.Args)
	}
}

// A shell started with SIGINT ignored (as a session child inherits from the
// listener) execs the session-child wrapper; the command it runs must get
// the default SIGINT disposition again.
func TestSessionChildRestoresDefaultSignals(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []string{"INT", "QUIT"} {
		script := fmt.Sprintf("trap '' %s; exec \"$0\" --session-child nofile=0 nproc=0 as=0 fsize=0 cpu=0 -- /bin/sh sh -c 'kill -%s $$; echo survived'", sig, sig)
		cmd := exec.Command("/bin/sh", "-c", script, exe)
		done := make(chan struct{})
		var out []byte
		go func() {
			out, _ = cmd.CombinedOutput()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("SIG%s: helper hung", sig)
		}
		if strings.Contains(string(out), "survived") {
			t.Fatalf("SIG%s stayed ignored through the session-child exec: %q", sig, out)
		}
	}
}

// RLIMIT_NPROC counts every thread the user owns system-wide. The child must
// not need a new thread after applying it, or a login on a busy host aborts
// in pthread_create before the shell starts.
func TestSessionChildStartsUnderTinyNPROC(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	out, err := sessionChildCmd(t, []string{"nproc=1"}, "/bin/sh", "sh", "-c", "echo started").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "started" {
		t.Fatalf("session child under nproc=1: err=%v out=%q", err, out)
	}
}
