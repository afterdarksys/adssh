//go:build ee

package main

// sah/1 stdio (internal/sah) is part of the enterprise layer (ee/LICENSE).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sah"
	"github.com/afterdarksys/adssh/security"
)

// sahDisabled answers sah/1 with sah_disabled when ADSSH_SAH is off.
func sahDisabled() int { return sah.Handle(false, nil, os.Stdout, nil) }

func runSAH(sec *security.Engine, sessionID string) int {
	return sah.Handle(true, os.Stdin, os.Stdout, func(command []string, leaseID string) (string, string, int, error) {
		return sahExecute(sec, sessionID, command, leaseID)
	})
}

// sahRun is the OS child. Tests replace it and restore it with t.Cleanup.
var sahRun = func(command []string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	// The child sees an allowlisted environment, never the listener's
	// ADSSH_* settings or tokens, and its output is capped while it runs so a
	// policy-allowed `yes` cannot grow memory for the 30 seconds.
	cmd.Env = sahChildEnv()
	cmd.WaitDelay = 2 * time.Second
	stdout := &sahCappedBuffer{limit: sahOutputCap}
	stderr := &sahCappedBuffer{limit: sahOutputCap}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := cmd.Run()
	out := security.RedactSensitiveText(stdout.String())
	errOut := security.RedactSensitiveText(stderr.String())
	if runErr == nil {
		return out, errOut, 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return out, errOut, exitErr.ExitCode(), nil
	}
	return "", "", 0, errors.New("execute_failed")
}

func sahExecute(sec *security.Engine, sessionID string, command []string, lease string) (string, string, int, error) {
	if sec == nil || !sec.PolicyLoaded() {
		return "", "", 0, errors.New("policy_required")
	}
	argv0 := command[0]
	base := argv0
	if strings.Contains(argv0, "/") {
		base = filepath.Base(argv0)
	}
	switch base {
	case "adssh", "sah", "adssh-mcp":
		return "", "", 0, errors.New("command_rejected")
	}
	if _, ok := sec.Lookup(argv0); ok {
		return "", "", 0, errors.New("command_rejected")
	}
	if envTruthy(os.Getenv("ADSSH_SAH_REQUIRE_LEASE")) {
		if lease == "" {
			return "", "", 0, errors.New("lease_required")
		}
		verified, err := security.VerifyExecLease(lease, security.LeaseOptions{
			KeysFile: os.Getenv("ADSSH_SAH_LEASE_KEYS"),
			Issuer:   os.Getenv("ADSSH_SAH_ISSUER"),
			HostID:   os.Getenv("ADSSH_SAH_HOST_ID"),
			Scope:    "exec",
			Command:  command,
		})
		if err != nil {
			if isLeaseCode(err) {
				return "", "", 0, err
			}
			return "", "", 0, errors.New("execute_failed")
		}
		if err := sec.LogEvent(fmt.Sprintf("LEASE_OK jti=%s fp=%s", verified.JTI, security.LeaseFingerprint(lease))); err != nil {
			return "", "", 0, errors.New("execute_failed")
		}
		if err := security.CommitLeaseJTI(sahLeaseStateDir(), verified.JTI, verified.Exp, time.Time{}); err != nil {
			if isLeaseCode(err) {
				return "", "", 0, err
			}
			return "", "", 0, errors.New("execute_failed")
		}
		if err := sec.AuthorizeCommandWithExtra(command, sessionID, security.PolicyContextExtra{ExecLease: verified.Claim()}); err != nil {
			return "", "", 0, err
		}
	} else if err := sec.AuthorizeCommand(command, sessionID); err != nil {
		return "", "", 0, errors.New("policy_denied")
	}
	return sahRun(command)
}

func isLeaseCode(err error) bool {
	switch err.Error() {
	case "lease_required", "lease_rejected", "lease_expired", "lease_replayed", "lease_command_mismatch":
		return true
	default:
		return false
	}
}

func sahLeaseStateDir() string {
	if v := os.Getenv("ADSSH_SAH_LEASE_STATE"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "sah-lease")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "state", "sah-lease")
}

// sahOutputCap bounds each of stdout and stderr captured from a sah child.
// The frame response caps again at 4 KiB; this cap exists so the buffer
// stops growing while the child is still running.
const sahOutputCap = 64 * 1024

// sahChildEnv is the environment a sah child receives: locale and path only,
// plus the caller's HOME, USER and LOGNAME. Nothing named ADSSH_* and no
// token-looking variable crosses into the child.
func sahChildEnv() []string {
	env := make([]string, 0, 8)
	for _, name := range []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TERM"} {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// sahCappedBuffer keeps the first limit bytes written and reports every write
// as complete so the child is not killed with EPIPE.
type sahCappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *sahCappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.buf.Write(p)
	}
	return n, nil
}

func (b *sahCappedBuffer) String() string { return b.buf.String() }
