//go:build e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestShellPipelineToVBin runs a shell pipeline whose sink is the in-process
// `jq` virtual binary, proving pipelines resolve through the interceptor and
// vbin registry.
func TestShellPipelineToVBin(t *testing.T) {
	sb := newSandbox(t)
	res := runADSSH(t, sb, "", "-c", `echo '{"name":"adssh"}' | jq '.name'`)
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, "adssh") {
		t.Fatalf("expected jq output to contain \"adssh\", got stdout=%q stderr=%q", res.stdout, res.stderr)
	}
}

// TestPolicyDenyBlocksCommand loads a Rego policy that denies a specific
// command and asserts the command is rejected before execution: nonzero exit
// and an explanatory message on stderr.
func TestPolicyDenyBlocksCommand(t *testing.T) {
	sb := newSandbox(t)
	sb.writePolicy(`package adssh.authz

default allow = true
default deny_reason = ""

allow = false {
    input.command == "forbiddencmd"
}

deny_reason = "blocked by e2e policy" {
    input.command == "forbiddencmd"
}
`)

	res := runADSSH(t, sb, "", "-c", "forbiddencmd")
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit for denied command, got 0 (stdout: %s)", res.stdout)
	}
	if !strings.Contains(res.stderr, "access denied") {
		t.Fatalf("expected 'access denied' on stderr, got %q", res.stderr)
	}
	if !strings.Contains(res.stderr, "blocked by e2e policy") {
		t.Fatalf("expected deny reason on stderr, got %q", res.stderr)
	}

	// Control: with the same policy an unlisted command is allowed to run.
	ok := runADSSH(t, sb, "", "-c", "echo allowed-through")
	if ok.exitCode != 0 || !strings.Contains(ok.stdout, "allowed-through") {
		t.Fatalf("expected allowed command to succeed, got exit=%d stdout=%q stderr=%q",
			ok.exitCode, ok.stdout, ok.stderr)
	}
}

// TestRestrictedModeBlocksPathCommand asserts restricted mode refuses commands
// that contain a path separator (a core sandbox guarantee).
func TestRestrictedModeBlocksPathCommand(t *testing.T) {
	sb := newSandbox(t)

	// Via the -r flag.
	res := runADSSH(t, sb, "", "-r", "-c", "/bin/echo should-not-run")
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit for /-prefixed command in restricted mode, got 0 (stdout: %s)", res.stdout)
	}
	if !strings.Contains(res.stderr, "restricted") {
		t.Fatalf("expected 'restricted' message on stderr, got %q", res.stderr)
	}
	if strings.Contains(res.stdout, "should-not-run") {
		t.Fatalf("restricted command produced output; it should have been blocked: %q", res.stdout)
	}

	// Via the ADSSH_RESTRICTED env var (same behavior, different entry point).
	env := mergeEnv(sb.env(""), map[string]string{"ADSSH_RESTRICTED": "1"})
	envRes := run(t, adsshBin, env, "", "-c", "/bin/echo should-not-run")
	if envRes.exitCode == 0 || !strings.Contains(envRes.stderr, "restricted") {
		t.Fatalf("expected ADSSH_RESTRICTED=1 to block, got exit=%d stderr=%q", envRes.exitCode, envRes.stderr)
	}
}

// TestStarlarkOneLiner evaluates Starlark expressions via -c, covering both a
// value-returning expression (printed to stdout by main.go) and the print()
// builtin (whose output goes to the Starlark thread's default writer, stderr).
func TestStarlarkOneLiner(t *testing.T) {
	sb := newSandbox(t)

	expr := runADSSH(t, sb, "", "-c", "6 * 7 == 42")
	if expr.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", expr.exitCode, expr.stderr)
	}
	if !strings.Contains(expr.stdout, "True") {
		t.Fatalf("expected Starlark expression result 'True' on stdout, got %q", expr.stdout)
	}

	pr := runADSSH(t, sb, "", "-c", `print("STARLARK_MARKER_OK")`)
	if pr.exitCode != 0 {
		t.Fatalf("expected exit 0 for print(), got %d (stderr: %s)", pr.exitCode, pr.stderr)
	}
	if !strings.Contains(pr.stdout+pr.stderr, "STARLARK_MARKER_OK") {
		t.Fatalf("expected print() marker in output, got stdout=%q stderr=%q", pr.stdout, pr.stderr)
	}
}

// TestAuditChainAccumulatesAndVerifies runs several commands that share one
// audit ledger (sequential processes, same ADSSH_AUDIT_LOG + XDG_DATA_HOME),
// then verifies chain integrity two ways:
//  1. Through the CLI: `audit verify` reports PASS.
//  2. Structurally: the JSONL ledger has contiguous seq numbers and prev_hash
//     continuity (each entry's prev_hash equals the previous entry's hash).
func TestAuditChainAccumulatesAndVerifies(t *testing.T) {
	sb := newSandbox(t)

	// Generate ledger activity across independent processes sharing one chain.
	for _, cmd := range []string{
		"echo chain-entry-one",
		`echo '{"k":1}' | jq '.k'`,
		"6 * 7 == 42",
	} {
		res := runADSSH(t, sb, "", "-c", cmd)
		if res.exitCode != 0 {
			t.Fatalf("command %q failed: exit=%d stderr=%q", cmd, res.exitCode, res.stderr)
		}
	}

	// 1. CLI-driven verification.
	verify := runADSSH(t, sb, "", "-c", "audit verify")
	if verify.exitCode != 0 {
		t.Fatalf("audit verify exited %d (stderr: %s)", verify.exitCode, verify.stderr)
	}
	if !strings.Contains(verify.stdout, "PASS") {
		t.Fatalf("expected audit verify to report PASS, got stdout=%q stderr=%q", verify.stdout, verify.stderr)
	}

	// 2. Structural verification of the JSONL ledger.
	assertChainStructurallyIntact(t, sb.chainPath())
}

// chainEntry mirrors the on-disk ledger JSON (security.ChainEntry) for the
// fields this test inspects.
type chainEntry struct {
	Seq      int64  `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// assertChainStructurallyIntact parses a ledger file and checks that seq numbers
// are contiguous from 0 and that prev_hash forms an unbroken linked list.
func assertChainStructurallyIntact(t *testing.T, path string) {
	t.Helper()
	data, err := readFileString(path)
	if err != nil {
		t.Fatalf("read chain %s: %v", path, err)
	}
	lines := nonEmptyLines(data)
	if len(lines) == 0 {
		t.Fatalf("chain ledger %s is empty", path)
	}

	var prevHash string
	var prevSeq int64 = -1
	for i, line := range lines {
		var e chainEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d is not valid JSON: %v (%q)", i, err, line)
		}
		if e.Hash == "" {
			t.Fatalf("line %d (seq %d) has empty hash", i, e.Seq)
		}
		if i == 0 {
			if e.Seq != 0 {
				t.Fatalf("first entry seq = %d, want 0", e.Seq)
			}
			if e.PrevHash != "" {
				t.Fatalf("genesis entry prev_hash = %q, want empty", e.PrevHash)
			}
		} else {
			if e.Seq != prevSeq+1 {
				t.Fatalf("line %d seq = %d, want %d (non-contiguous)", i, e.Seq, prevSeq+1)
			}
			if e.PrevHash != prevHash {
				t.Fatalf("line %d prev_hash = %q, want %q (broken link)", i, e.PrevHash, prevHash)
			}
		}
		prevHash = e.Hash
		prevSeq = e.Seq
	}
}
