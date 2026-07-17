//go:build e2e

// Package e2e contains black-box end-to-end tests that drive the compiled
// `adssh` and `adssh-mcp` binaries as real subprocesses. Every file in this
// package is tagged `//go:build e2e` so the normal `go test ./...` run never
// compiles or executes it — these tests are opt-in via `go test -tags e2e`.
//
// TestMain builds both binaries once per run into a temp directory. Set
// ADSSH_E2E_NO_REBUILD=1 together with ADSSH_E2E_BIN_DIR=<dir> to reuse
// pre-built binaries and skip the (slow) build step.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Paths to the binaries under test, populated by TestMain.
var (
	adsshBin string
	mcpBin   string
)

func TestMain(m *testing.M) {
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: cannot locate repo root: %v\n", err)
		os.Exit(1)
	}

	binDir := os.Getenv("ADSSH_E2E_BIN_DIR")
	cleanup := func() {}
	if binDir == "" {
		tmp, err := os.MkdirTemp("", "adssh-e2e-bin-")
		if err != nil {
			fmt.Fprintf(os.Stderr, "e2e: mkdir temp bin dir: %v\n", err)
			os.Exit(1)
		}
		binDir = tmp
		cleanup = func() { _ = os.RemoveAll(tmp) }
	}

	adsshBin = filepath.Join(binDir, "adssh")
	mcpBin = filepath.Join(binDir, "adssh-mcp")

	noRebuild := truthy(os.Getenv("ADSSH_E2E_NO_REBUILD"))
	if !(noRebuild && fileExists(adsshBin) && fileExists(mcpBin)) {
		if err := buildBinary(root, adsshBin, "."); err != nil {
			cleanup()
			fmt.Fprintf(os.Stderr, "e2e: build adssh: %v\n", err)
			os.Exit(1)
		}
		if err := buildBinary(root, mcpBin, "./cmd/adssh-mcp"); err != nil {
			cleanup()
			fmt.Fprintf(os.Stderr, "e2e: build adssh-mcp: %v\n", err)
			os.Exit(1)
		}
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

// buildBinary runs `go build -o out pkg` from the module root.
func buildBinary(root, out, pkg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, pkg)
	cmd.Dir = root
	cmd.Env = os.Environ()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// repoRoot walks up from the current working directory until it finds go.mod.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(dir, "go.mod")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s upward", dir)
		}
		dir = parent
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// sandbox is an isolated environment (temp HOME + XDG dirs + audit paths) for a
// single test. It never touches the operator's real ~/.adssh.
type sandbox struct {
	t         *testing.T
	dir       string // root temp dir
	home      string
	xdgConfig string
	xdgData   string
	auditLog  string // ADSSH_AUDIT_LOG; the HMAC ledger lives at auditLog+".chain"
	policy    string // ADSSH_POLICY, "" means none (default allow)
}

// newSandbox creates a fresh isolated sandbox rooted at t.TempDir().
func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	dir := t.TempDir()
	sb := &sandbox{
		t:         t,
		dir:       dir,
		home:      filepath.Join(dir, "home"),
		xdgConfig: filepath.Join(dir, "config"),
		xdgData:   filepath.Join(dir, "data"),
		auditLog:  filepath.Join(dir, "audit.log"),
	}
	for _, d := range []string{sb.home, sb.xdgConfig, sb.xdgData} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	return sb
}

// chainPath is the HMAC ledger path derived by main.go from the audit log.
func (sb *sandbox) chainPath() string { return sb.auditLog + ".chain" }

// keyPath is the HMAC key path (XDGDataHome/adssh/audit.key) derived by main.go.
func (sb *sandbox) keyPath() string { return filepath.Join(sb.xdgData, "adssh", "audit.key") }

// writePolicy writes a Rego policy file into the sandbox and points
// ADSSH_POLICY at it for subsequent runs.
func (sb *sandbox) writePolicy(rego string) {
	sb.t.Helper()
	p := filepath.Join(sb.dir, "policy.rego")
	if err := os.WriteFile(p, []byte(rego), 0o600); err != nil {
		sb.t.Fatalf("write policy: %v", err)
	}
	sb.policy = p
}

// seedChainKey pre-creates the 32-byte HMAC key so that concurrently launched
// processes do not race to generate (and clobber) it.
func (sb *sandbox) seedChainKey() {
	sb.t.Helper()
	if err := os.MkdirAll(filepath.Dir(sb.keyPath()), 0o700); err != nil {
		sb.t.Fatalf("mkdir key dir: %v", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		sb.t.Fatalf("gen key: %v", err)
	}
	if err := os.WriteFile(sb.keyPath(), key, 0o600); err != nil {
		sb.t.Fatalf("write key: %v", err)
	}
}

// env returns the process environment for an adssh invocation, overriding the
// audit-log path (defaults to sb.auditLog; pass a value to override for the
// concurrency soak, which uses one ledger per process).
func (sb *sandbox) env(auditLogOverride string) []string {
	auditLog := sb.auditLog
	if auditLogOverride != "" {
		auditLog = auditLogOverride
	}
	overrides := map[string]string{
		"HOME":               sb.home,
		"XDG_CONFIG_HOME":    sb.xdgConfig,
		"XDG_DATA_HOME":      sb.xdgData,
		"XDG_CACHE_HOME":     filepath.Join(sb.dir, "cache"),
		"ADSSH_AUDIT_LOG":    auditLog,
		"ADSSH_HISTORY":      filepath.Join(sb.dir, "history"),
		"ADSSH_PROFILE":      filepath.Join(sb.home, ".adsshprofile"),
		"ADSSH_RC":           filepath.Join(sb.home, ".adsshrc"),
		"ADSSH_RESTRICTED":   "",
		"ADSSH_AUDIT_URL":    "",
		"ADSSH_AUDIT_TOKEN":  "",
		"ADSSH_ENTITLEMENTS": "",
		"ADSSH_SERVE":        "",
	}
	if sb.policy != "" {
		overrides["ADSSH_POLICY"] = sb.policy
	} else {
		// Point at a path that does not exist -> LoadPolicy degrades to allow-all.
		overrides["ADSSH_POLICY"] = filepath.Join(sb.dir, "no-such-policy.rego")
	}
	return mergeEnv(os.Environ(), overrides)
}

// mergeEnv overlays overrides onto base, replacing any existing KEY=... entry.
func mergeEnv(base []string, overrides map[string]string) []string {
	out := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if _, ok := overrides[key]; ok {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

// runResult captures the outcome of a subprocess invocation.
type runResult struct {
	stdout   string
	stderr   string
	exitCode int
}

// run executes the given binary with args and env, feeding stdin, and returns
// stdout/stderr/exit code. A 30s timeout guards against hangs.
func run(t *testing.T, bin string, env []string, stdin string, args ...string) runResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	err := cmd.Run()
	res := runResult{stdout: out.String(), stderr: errb.String()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run %s %v: %v (stderr: %s)", bin, args, err, errb.String())
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("run %s %v timed out", bin, args)
	}
	return res
}

// runADSSH is a convenience wrapper for the main shell binary.
func runADSSH(t *testing.T, sb *sandbox, stdin string, args ...string) runResult {
	return run(t, adsshBin, sb.env(""), stdin, args...)
}

// readFileString reads a whole file into a string.
func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// nonEmptyLines splits s on newlines and drops blank lines.
func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
