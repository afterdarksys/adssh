//go:build unix

package sys

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Threats: the listener is the monitor. One exec per SSH login. Policy and
// the audit chain stay in the listener. Virtual binaries run in the child
// after allow. A memory exploit in the setuid child can still execve.
// Starlark file, network, and cloud calls that do not pass the gate are
// privilege-safe after setuid and crash-contained by RLIMIT_AS and CPU, but
// they are policy-bypassable. Darwin sets FD_CLOEXEC after socketpair; a
// fork in that window can inherit the monitor socket. There is no cgroup
// on darwin. RLIMIT_NPROC is per unix uid. The listener is not rlimited.
// A nil monitor fails closed
// with no in-process fallback. Payloads are not logged. SCM_RIGHTS for
// monitor-spawned pipelines is deferred.

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
	// CLOEXEC keeps the pair out of unrelated children. ForkExec clears
	// CLOEXEC on the ExtraFiles copy, and the session-child exec keeps fd 3.
	fds, err := cloexecSocketpair()
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(fds[0]), "ssh-monitor")
	child := os.NewFile(uintptr(fds[1]), "ssh-monitor")
	defer func() { _ = parent.Close() }()
	defer func() { _ = child.Close() }()

	cmd := buildSSHSessionCmd(exe, spec)
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

// OpenMonitorFD takes ownership of the session monitor socket. The protocol
// uses fd 3, the first ExtraFiles entry. Any other number fails closed.
func OpenMonitorFD(fd int) (*os.File, error) {
	if fd != 3 {
		return nil, errors.New("adssh: ssh session: monitor fd must be 3")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		return nil, errors.New("adssh: ssh monitor: closed")
	}
	return os.NewFile(uintptr(fd), "ssh-monitor"), nil
}

func validateSSHSessionSpec(spec SSHSessionSpec) error {
	if !validSessionToken(spec.SessionID) || !validSessionToken(spec.User) ||
		!validSessionToken(spec.HistoryFile) || !validSessionToken(spec.ProfilePath) ||
		!validSessionToken(spec.RCPath) {
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
	return nil
}

func validSessionToken(v string) bool {
	return v != "" && strings.IndexByte(v, 0) < 0 && !strings.HasPrefix(v, "-")
}

func buildSSHSessionCmd(exe string, spec SSHSessionSpec) *exec.Cmd {
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
		"--history", spec.HistoryFile,
		"--profile", spec.ProfilePath,
		"--rc", spec.RCPath,
	)
	for _, principal := range spec.Principals {
		args = append(args, "--principal", principal)
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
