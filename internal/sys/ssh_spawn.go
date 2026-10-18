//go:build unix

package sys

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// Threats: the listener is the monitor. One exec per SSH login. Policy and
// the audit chain stay in the listener. Stateless virtual binaries run in
// the child after allow; the state-changing ones run in the listener over a
// monitor Run frame (see security/ssh_monitor.go). The listener's plugin
// directory, when configured, reaches the child as --plugin-dir, an
// absolute path; the child lists plugins there but does not load them. A memory exploit in the setuid child can still execve.
// Starlark file, network, and cloud calls that do not pass the gate are
// privilege-safe after setuid and crash-contained by RLIMIT_AS and CPU, but
// they are policy-bypassable. The pair is FD_CLOEXEC from creation (darwin:
// under syscall.ForkLock); the child sets FD_CLOEXEC on fd 3 again in
// OpenMonitorFD, so commands it runs do not inherit the socket. The
// listener end is non-blocking, so closing it at teardown releases the
// monitor goroutine even if a leaked copy of the child end stays open. The
// child does not inherit the listener's environment or working directory:
// it gets an allowlist (HOME, USER, LOGNAME, SHELL, a PATH of absolute
// entries, TERM, LANG, LC_ALL, and the ADSSH_SESSION_* and
// ADSSH_MAX_SESSIONS limits) built from the target user, starts in that
// user's home (or / when it is missing), and reads its profile, rc, and
// history under that home. A target user without an absolute home fails
// closed. There is no cgroup on darwin. RLIMIT_NPROC is per unix uid. The
// listener is not rlimited. A nil monitor fails closed with no in-process
// fallback. Payloads are not logged. SCM_RIGHTS for monitor-spawned
// pipelines is deferred.

// SpawnSSHSession execs one SSH login. The listener keeps the socket, the
// host key, the session table, and the audit files. A nil monitor, an
// unmarked session, or a session that cannot be its own process fails closed.
// There is no in-process fallback.
func SpawnSSHSession(spec SSHSessionSpec) error {
	if err := validateSSHSessionSpec(spec); err != nil {
		return err
	}
	hook := currentSSHMonitorServer()
	if hook == nil {
		return errors.New("adssh: ssh session: monitor is not configured")
	}
	session := GetSession(spec.SessionID)
	if session == nil || !session.DropPrivileges() {
		return errors.New("adssh: ssh session: refusing unmarked session")
	}
	if spec.PTY == nil {
		return errors.New("adssh: ssh session: pty is not a file")
	}
	exe, err := executable()
	if err != nil {
		return err
	}
	target, err := lookupUser(session.User)
	if err != nil {
		return fmt.Errorf("adssh: session user: %w", err)
	}
	home := target.HomeDir
	if !filepath.IsAbs(home) || !validSessionToken(home) {
		return errors.New("adssh: ssh session: user home is not an absolute path")
	}
	home = filepath.Clean(home)
	term, _ := session.OverlayGet("TERM")
	var locale []string
	for _, k := range clientLocaleVars {
		if v, ok := session.OverlayGet(k); ok {
			locale = append(locale, k+"="+v)
		}
	}
	// CLOEXEC keeps the pair out of unrelated children. ForkExec clears
	// CLOEXEC on the ExtraFiles copy, and the session-child exec keeps fd 3.
	parent, child, err := newMonitorPair()
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	defer func() { _ = child.Close() }()

	cmd := buildSSHSessionCmd(exe, spec, home)
	cmd.Env = sshSessionEnv(target, session.User, home, exe, term, locale...)
	cmd.Dir = "/"
	if fi, err := os.Stat(home); err == nil && fi.IsDir() {
		cmd.Dir = home
	}
	cmd.Stdin = spec.PTY
	cmd.Stdout = spec.PTY
	cmd.Stderr = spec.PTY
	cmd.ExtraFiles = []*os.File{child}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := PrepareChild(cmd, session); err != nil {
		return err
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid || !cmd.SysProcAttr.Setctty {
		return errors.New("adssh: ssh session: cannot set session")
	}
	go hook(NewMonitorConn(parent), spec.SessionID)
	return runSSHCommand(cmd)
}

// newMonitorPair returns the listener end and the child end of a monitor
// socketpair. The listener end is non-blocking before os.NewFile, so the
// runtime poller owns it: Close and deadlines release a blocked reader even
// while a leaked copy of the child end keeps the socket open. The child end
// stays blocking for the session process.
func newMonitorPair() (*os.File, *os.File, error) {
	fds, err := cloexecSocketpair()
	if err != nil {
		return nil, nil, err
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "ssh-monitor"), os.NewFile(uintptr(fds[1]), "ssh-monitor"), nil
}

// pollablePTY returns a non-blocking copy of a pty master and closes f. On a
// blocking master, Close is deferred while another goroutine is blocked in
// Read, so the slave never sees the hangup and a disconnected client leaves
// its session process running. A poller-owned master closes at once.
func pollablePTY(f *os.File) (*os.File, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	dup := -1
	var dupErr error
	syscall.ForkLock.RLock()
	ctlErr := raw.Control(func(fd uintptr) {
		dup, dupErr = unix.Dup(int(fd))
		if dupErr == nil {
			unix.CloseOnExec(dup)
		}
	})
	syscall.ForkLock.RUnlock()
	if ctlErr != nil {
		return nil, ctlErr
	}
	if dupErr != nil {
		return nil, dupErr
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		_ = unix.Close(dup)
		return nil, err
	}
	name := f.Name()
	_ = f.Close()
	return os.NewFile(uintptr(dup), name), nil
}

// setPTYSize sets the window size through SyscallConn. pty.Setsize calls
// Fd, which puts a pollable file back into blocking mode.
func setPTYSize(f *os.File, ws *pty.Winsize) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioErr error
	if err := raw.Control(func(fd uintptr) {
		ioErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: ws.Rows, Col: ws.Cols})
	}); err != nil {
		return err
	}
	return ioErr
}

// OpenMonitorFD takes ownership of the session monitor socket. The protocol
// uses fd 3, the first ExtraFiles entry. Any other number fails closed.
// ForkExec cleared FD_CLOEXEC on fd 3 to hand it over; it is set again here
// so no command the session runs inherits the socket.
func OpenMonitorFD(fd int) (*os.File, error) {
	if fd != 3 {
		return nil, errors.New("adssh: ssh session: monitor fd must be 3")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		return nil, errors.New("adssh: ssh monitor: closed")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return nil, errors.New("adssh: ssh monitor: closed")
	}
	return os.NewFile(uintptr(fd), "ssh-monitor"), nil
}

// defaultSessionPath is the session PATH when the listener has no usable
// absolute entries.
const defaultSessionPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// sessionEnvPassthrough are the listener variables a session child needs:
// locale, and the limits ConfigureHostFromEnv reads in the child.
var sessionEnvPassthrough = []string{
	"LANG",
	"LC_ALL",
	"ADSSH_MAX_SESSIONS",
	"ADSSH_SESSION_NOFILE",
	"ADSSH_SESSION_NPROC",
	"ADSSH_SESSION_AS",
	"ADSSH_SESSION_FSIZE",
	"ADSSH_SESSION_CPU_SECONDS",
}

// sshSessionEnv builds the session child's environment from the target user.
// Nothing else from the listener's environment is copied. locale holds the
// client's accepted LANG and LC_* assignments; each replaces the listener's
// value for that name.
func sshSessionEnv(target *user.User, login, home, shell, term string, locale ...string) []string {
	name := target.Username
	if name == "" {
		name = login
	}
	if term == "" {
		term = "xterm"
	}
	env := []string{
		"HOME=" + home,
		"USER=" + name,
		"LOGNAME=" + name,
		"SHELL=" + shell,
		"PATH=" + sanitizeSessionPath(os.Getenv("PATH")),
		"TERM=" + term,
	}
	fromClient := map[string]bool{}
	for _, kv := range locale {
		fromClient[kv[:strings.IndexByte(kv, '=')]] = true
	}
	for _, key := range sessionEnvPassthrough {
		if fromClient[key] {
			continue
		}
		if v := os.Getenv(key); v != "" && strings.IndexByte(v, 0) < 0 {
			env = append(env, key+"="+v)
		}
	}
	return append(env, locale...)
}

// sanitizeSessionPath keeps the absolute entries of path. An empty result is
// the default PATH.
func sanitizeSessionPath(path string) string {
	var keep []string
	for _, dir := range strings.Split(path, ":") {
		if filepath.IsAbs(dir) {
			keep = append(keep, dir)
		}
	}
	if len(keep) == 0 {
		return defaultSessionPath
	}
	return strings.Join(keep, ":")
}

func validateSSHSessionSpec(spec SSHSessionSpec) error {
	if !validSessionToken(spec.SessionID) || !validSessionToken(spec.User) {
		return errors.New("adssh: ssh session: invalid value")
	}
	if spec.MenuPath != "" && !validSessionToken(spec.MenuPath) {
		return errors.New("adssh: ssh session: invalid value")
	}
	for _, principal := range spec.Principals {
		if !validSessionToken(principal) {
			return errors.New("adssh: ssh session: invalid value")
		}
	}
	if spec.PluginDir != "" && (!filepath.IsAbs(spec.PluginDir) || !validSessionToken(spec.PluginDir)) {
		return errors.New("adssh: ssh session: invalid value")
	}
	return nil
}

func buildSSHSessionCmd(exe string, spec SSHSessionSpec, home string) *exec.Cmd {
	args := []string{
		"--ssh-session",
		"--session-id", spec.SessionID,
		"--ssh-user", spec.User,
		"--monitor-fd", "3",
	}
	if spec.Restricted {
		args = append(args, "--restricted")
	}
	if spec.MenuPath != "" {
		args = append(args, "--menu", spec.MenuPath)
	}
	args = append(args,
		"--history", filepath.Join(home, ".adssh", "history"),
		"--profile", filepath.Join(home, ".adsshprofile"),
		"--rc", filepath.Join(home, ".adsshrc"),
	)
	for _, principal := range spec.Principals {
		args = append(args, "--principal", principal)
	}
	if spec.PluginDir != "" {
		args = append(args, "--plugin-dir", filepath.Clean(spec.PluginDir))
	}
	return exec.Command(exe, args...)
}

func defaultRunSSHCommand(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	if len(cmd.ExtraFiles) > 0 && cmd.ExtraFiles[0] != nil {
		_ = cmd.ExtraFiles[0].Close()
	}
	return cmd.Wait()
}

var runSSHCommand = defaultRunSSHCommand
