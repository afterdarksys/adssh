//go:build ee

package security

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chainPaths(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "ledger"), filepath.Join(dir, "key")
}

func fourLogChain(t *testing.T) (*Engine, string, string) {
	t.Helper()
	eng := policyEngine(t, allowAllPolicy)
	chain, key := chainPaths(t)
	if err := eng.InitChain(chain, key, "s"); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogPolicyDecision("u", "id", true, ""); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogCommand("BASH", "id -u"); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogPolicyDecision("u", "rm -rf", false, "no"); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("HOST_PROFILE host=host-1 users=alice units=nginx.service policy=abc adminkeys=def"); err != nil {
		t.Fatal(err)
	}
	return eng, chain, key
}

func TestAsofReplay(t *testing.T) {
	guardPlane(t)
	_, chain, key := fourLogChain(t)
	got, err := AsofAt(chain, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "allowlist=id\nunits=\nusers=\n" {
		t.Fatalf("seq 1:\n%s", got)
	}
	got, err = AsofAt(chain, key, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got != "allowlist=id\nunits=nginx.service\nusers=alice\n" {
		t.Fatalf("seq 3:\n%s", got)
	}
	if _, err := AsofAt(chain, key, 99); !errors.Is(err, errAsofRejected) {
		t.Fatalf("future: %v", err)
	}

	eng := policyEngine(t, allowAllPolicy)
	cmdChain, cmdKey := chainPaths(t)
	if err := eng.InitChain(cmdChain, cmdKey, "s"); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogCommand("BASH", "id -u"); err != nil {
		t.Fatal(err)
	}
	got, err = AsofAt(cmdChain, cmdKey, 0)
	if err != nil || got != "allowlist=\nunits=\nusers=\n" {
		t.Fatalf("cmd only: %v %q", err, got)
	}
}

func TestAsofRejectsBadKeyAndChain(t *testing.T) {
	guardPlane(t)
	_, chain, key := fourLogChain(t)
	if _, err := AsofAt("", key, 0); !errors.Is(err, errAsofUsage) {
		t.Fatalf("empty chain path: %v", err)
	}
	if _, err := AsofAt(chain, "", 0); !errors.Is(err, errAsofUsage) {
		t.Fatalf("empty key path: %v", err)
	}
	if _, err := AsofAt(chain, key, -1); !errors.Is(err, errAsofUsage) {
		t.Fatalf("negative: %v", err)
	}

	dir := t.TempDir()
	zero := filepath.Join(dir, "zero")
	if err := os.WriteFile(zero, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	walked := false
	walkClose = func(f *os.File) error {
		walked = true
		return f.Close()
	}
	if _, err := AsofAt(chain, zero, 0); !errors.Is(err, errAsofRejected) || walked {
		t.Fatalf("zero key: %v walked %v", err, walked)
	}
	walkClose = nil

	wide := filepath.Join(dir, "wide")
	body, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wide, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AsofAt(chain, wide, 0); !errors.Is(err, errAsofRejected) {
		t.Fatalf("wide key: %v", err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, body[:16], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AsofAt(chain, short, 0); !errors.Is(err, errAsofRejected) {
		t.Fatalf("short key: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := AsofAt(chain, link, 0); !errors.Is(err, errAsofRejected) {
		t.Fatalf("symlink: %v", err)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AsofAt(empty, key, 0); !errors.Is(err, errAsofRejected) {
		t.Fatalf("empty chain: %v", err)
	}

	trunc := filepath.Join(dir, "trunc")
	src, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trunc, append(src, []byte("not-json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AsofAt(trunc, key, 0); !errors.Is(err, errAsofRejected) {
		t.Fatalf("truncated: %v", err)
	}

	decoy := filepath.Join(dir, "decoy")
	if err := os.WriteFile(decoy, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rewriteDecoy(t, decoy, key); err != nil {
		t.Fatal(err)
	}
	if _, err := AsofAt(decoy, key, 0); !errors.Is(err, errAsofRejected) {
		t.Fatalf("decoy: %v", err)
	}

	walkClose = func(f *os.File) error {
		return errors.Join(f.Close(), errors.New("close failed"))
	}
	if _, err := AsofAt(chain, key, 0); !errors.Is(err, errAsofRejected) {
		t.Fatalf("close: %v", err)
	}
}

func rewriteDecoy(t *testing.T, chain, keyPath string) error {
	t.Helper()
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	text, err := os.ReadFile(chain)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(text), "\n"), "\n")
	var entry ChainEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		return err
	}
	entry.PrevHash = "decoy"
	sum, err := computeHash(key, "decoy", entry)
	if err != nil {
		return err
	}
	entry.Hash = sum
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	lines[0] = string(raw)
	return os.WriteFile(chain, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func TestAsofVerb(t *testing.T) {
	eng, ctx, sid := adminFix(t)
	if err := (asofBinary{}).Run(context.Background(), []string{"asof", "--help"}); err != nil {
		t.Fatal(err)
	}
	usage := [][]string{
		{"asof"},
		{"asof", "--chain", "c", "--key", "k"},
		{"asof", "--chain", "c", "--chain", "d", "--key", "k", "--seq", "0"},
		{"asof", "--chain", "c", "--key", "k", "--seq", "-1"},
		{"asof", "--chain", "", "--key", "k", "--seq", "0"},
	}
	for _, args := range usage {
		if err := (asofBinary{}).Run(ctx, args); !errors.Is(err, errAsofUsage) {
			t.Fatalf("%v: %v", args, err)
		}
	}
	_, chain, key := fourLogChain(t)
	equalErr(t, (asofBinary{}).Run(context.Background(), []string{"asof", "--chain", chain, "--key", key, "--seq", "0"}), "asof: requires a session")
	out, err := runVBin(t, eng, sid, []string{"asof", "--chain", chain, "--key", key, "--seq", "3"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "allowlist=id\nunits=nginx.service\nusers=alice\n" {
		t.Fatalf("vbin:\n%s", out)
	}
}
