package sys

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

// Threats: a shared host must not accept unbounded sessions, and a garbage
// cap must refuse new sessions rather than fall open. Rlimits are read once
// from the process environment at startup; a session overlay cannot raise
// them. Empty ADSSH_SESSION_CPU_SECONDS is 14400 CPU seconds per process,
// not wall clock. "0" does not set that limit. The listener is not rlimited.
// Idle SSH does not consume it. One core for four CPU-hours gets SIGXCPU.
// SSH session processes are separate. Local REPL, MCP, and grid still share
// the listener heap. In-process Starlark and virtual binaries in the listener
// are not covered by the session rlimit. Darwin RLIMIT_AS is the cgroup
// stand-in. Darwin RLIMIT_NPROC is per unix user, so sessions of one user
// share it. There is no cgroup. The FSIZE and AS defaults can break a large
// build until the operator raises them.
//
//	ADSSH_MAX_SESSIONS          empty = 128, 0 = unlimited, garbage = refuse
//	ADSSH_SESSION_NOFILE        empty = 256, 0 = do not set
//	ADSSH_SESSION_NPROC         empty = 64,  0 = do not set
//	ADSSH_SESSION_AS            empty = 1 GiB, 0 = do not set
//	ADSSH_SESSION_FSIZE         empty = 1 GiB, 0 = do not set
//	ADSSH_SESSION_CPU_SECONDS   empty = 14400, 0 = do not set
const (
	defaultSessionCap    = 128
	defaultSessionNOFILE = 256
	defaultSessionNPROC  = 64
	defaultSessionAS     = 1 << 30
	defaultSessionFSIZE  = 1 << 30
	defaultSessionCPU    = 14400
)

var (
	sessionCap       uint64 = defaultSessionCap
	sessionCapRefuse bool
	limitNOFILE      uint64 = defaultSessionNOFILE
	limitNPROC       uint64 = defaultSessionNPROC
	limitAS          uint64 = defaultSessionAS
	limitFSIZE       uint64 = defaultSessionFSIZE
	limitCPU         uint64 = defaultSessionCPU
)

// runningUnderTest reports whether this process is a `go test` binary.
// The check is at call time: testing registers test.v before tests run,
// and a production binary never imports testing.
var runningUnderTest = func() bool {
	return flag.Lookup("test.v") != nil
}

type hostLimits struct {
	nofile uint64
	nproc  uint64
	as     uint64
	fsize  uint64
	cpu    uint64
}

func sessionLimits() hostLimits {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return hostLimits{
		nofile: limitNOFILE,
		nproc:  limitNPROC,
		as:     limitAS,
		fsize:  limitFSIZE,
		cpu:    limitCPU,
	}
}

func (l hostLimits) any() bool {
	return l.nofile != 0 || l.nproc != 0 || l.as != 0 || l.fsize != 0 || l.cpu != 0
}

// SessionCapReady reports whether new sessions may be registered. EnableSSH
// refuses to listen when a garbage cap has tripped the refuse flag.
func SessionCapReady() error {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	if sessionCapRefuse {
		return fmt.Errorf("adssh: session cap is invalid; refusing new sessions")
	}
	return nil
}

// ConfigureHostFromEnv reads the session cap and child rlimits once.
// A garbage cap sets the refuse flag before returning, so a caller that
// ignores the error still fails closed. A valid cap with a garbage limit
// changes neither the cap nor the limits.
func ConfigureHostFromEnv() error {
	capN, capErr := parseSessionCap(os.Getenv("ADSSH_MAX_SESSIONS"))
	if capErr != nil {
		sessionsMu.Lock()
		sessionCapRefuse = true
		sessionsMu.Unlock()
		return capErr
	}
	nofile, err := parseLimitEnv("ADSSH_SESSION_NOFILE", defaultSessionNOFILE)
	if err != nil {
		return err
	}
	nproc, err := parseLimitEnv("ADSSH_SESSION_NPROC", defaultSessionNPROC)
	if err != nil {
		return err
	}
	as, err := parseLimitEnv("ADSSH_SESSION_AS", defaultSessionAS)
	if err != nil {
		return err
	}
	fsize, err := parseLimitEnv("ADSSH_SESSION_FSIZE", defaultSessionFSIZE)
	if err != nil {
		return err
	}
	cpu, err := parseLimitEnv("ADSSH_SESSION_CPU_SECONDS", defaultSessionCPU)
	if err != nil {
		return err
	}
	sessionsMu.Lock()
	sessionCap = capN
	sessionCapRefuse = false
	limitNOFILE = nofile
	limitNPROC = nproc
	limitAS = as
	limitFSIZE = fsize
	limitCPU = cpu
	sessionsMu.Unlock()
	return nil
}

func parseSessionCap(raw string) (uint64, error) {
	if raw == "" {
		return defaultSessionCap, nil
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("adssh: ADSSH_MAX_SESSIONS: %w", err)
	}
	return n, nil
}

func parseLimitEnv(name string, fallback uint64) (uint64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("adssh: %s: %w", name, err)
	}
	return n, nil
}

func setSessionCapForTest(n uint64, refuse bool) (prev uint64, prevRefuse bool) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	prev, prevRefuse = sessionCap, sessionCapRefuse
	sessionCap, sessionCapRefuse = n, refuse
	return prev, prevRefuse
}

func setSessionLimitsForTest(next hostLimits) hostLimits {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	prev := hostLimits{limitNOFILE, limitNPROC, limitAS, limitFSIZE, limitCPU}
	limitNOFILE = next.nofile
	limitNPROC = next.nproc
	limitAS = next.as
	limitFSIZE = next.fsize
	limitCPU = next.cpu
	return prev
}
