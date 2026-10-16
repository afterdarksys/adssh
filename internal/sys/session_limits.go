//go:build unix

package sys

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// Threats: a root listener must not exec a shell child as root for an SSH
// session. The credential is applied only when that session is marked, the
// process is root, and the unix user and groups resolve. A lookup, parse, or
// GroupIds error returns before Credential is set, and the caller must not
// start the process. A requested rlimit above the current hard limit is
// clamped down; the hard limit is never raised. A zero limit is not applied.
// In-process Starlark and virtual binaries share this process and are not
// covered. An SSH session process is already under these rlimits and its
// in-process virtual binaries share that process, not the listener. The
// re-exec cannot raise uid: the child is already the dropped uid
// when it sets rlimits and execs. RLIMIT_NPROC is per unix uid, so sessions
// of one user share it. FSIZE and AS can break a large build. There is no
// cgroup on darwin.
var (
	geteuid      = os.Geteuid
	lookupUser   = user.Lookup
	userGroupIDs = func(u *user.User) ([]string, error) { return u.GroupIds() }
	setRlimit    = unix.Setrlimit
	getRlimit    = unix.Getrlimit
	executable   = os.Executable
	execProcess  = syscall.Exec
)

// PrepareChild applies an SSH session's unix credential and the process
// rlimit re-exec to cmd. A nil session, or a session that was not marked,
// keeps the listener uid. Under go test the re-exec wrap is skipped so
// existing exec tests still run; the credential is still applied when the
// injected euid is 0 and the session is marked.
func PrepareChild(cmd *exec.Cmd, session *Session) error {
	if cmd == nil {
		return fmt.Errorf("adssh: session child: nil command")
	}
	if cmd.Env == nil && session != nil {
		cmd.Env = session.Environ()
	}
	if session != nil && session.DropPrivileges() {
		if err := applyCredential(cmd, session); err != nil {
			return err
		}
	}
	return wrapSessionLimits(cmd)
}

// applyCredential resolves the session user before it assigns
// SysProcAttr.Credential. A lookup, parse, or GroupIds failure leaves
// Credential unset.
func applyCredential(cmd *exec.Cmd, session *Session) error {
	if geteuid() != 0 {
		return nil
	}
	name := session.User
	if name == "" {
		return fmt.Errorf("adssh: session user is empty")
	}
	u, err := lookupUser(name)
	if err != nil {
		return fmt.Errorf("adssh: session user: %w", err)
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("adssh: session uid: %w", err)
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("adssh: session gid: %w", err)
	}
	groups, err := userGroupIDs(u)
	if err != nil {
		return fmt.Errorf("adssh: session groups: %w", err)
	}
	gids := make([]uint32, 0, len(groups))
	for _, g := range groups {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return fmt.Errorf("adssh: session group: %w", err)
		}
		gids = append(gids, uint32(n))
	}
	cred := &syscall.Credential{
		Uid:    uint32(uid64),
		Gid:    uint32(gid64),
		Groups: gids,
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = cred
	return nil
}

// RequireResolvableSSHUser fails closed when the SSH login name is empty or
// does not resolve. The check runs even when this process is not root, so a
// later drop cannot discover the failure after the session goroutines start.
func RequireResolvableSSHUser(name string) error {
	if name == "" {
		return fmt.Errorf("adssh: ssh user is empty")
	}
	if _, err := lookupUser(name); err != nil {
		return fmt.Errorf("adssh: ssh user: %w", err)
	}
	return nil
}
