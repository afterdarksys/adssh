package security

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func TestLeaseHelperProcess(t *testing.T) {
	if os.Getenv("ADSSH_LEASE_HELPER") != "1" {
		return
	}
	if os.Getenv("TOKEN") != "super-secret" {
		os.Exit(3)
	}
	if _, inherited := os.LookupEnv("ADSSH_LEASE_SOURCE"); inherited {
		os.Exit(4)
	}
	os.Exit(0)
}

func runLeaseVBin(t *testing.T, eng *Engine, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(ctx, leaseBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := syntax.NewParser().Parse(strings.NewReader("lease-test"), "")
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func TestLeaseInjectsSecretOnlyIntoGovernedChildEnvironment(t *testing.T) {
	t.Setenv("ADSSH_LEASE_SOURCE", "super-secret")
	t.Setenv("ADSSH_LEASE_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ledger := filepath.Join(dir, "chain")
	eng, _ := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: filepath.Join(dir, "key")})
	output, err := runLeaseVBin(t, eng, []string{
		"lease", "--from", "env:ADSSH_LEASE_SOURCE", "--as", "TOKEN", "--", binary, "-test.run=^TestLeaseHelperProcess$",
	})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "super-secret") || bytes.Contains(chain, []byte("super-secret")) {
		t.Fatal("leased secret leaked into output or audit chain")
	}
}

func TestLeaseRedactsSecretPrintedByChild(t *testing.T) {
	t.Setenv("ADSSH_LEASE_SOURCE", "super-secret")
	eng, _ := NewEngine(EngineConfig{})
	output, err := runLeaseVBin(t, eng, []string{
		"lease", "--from", "env:ADSSH_LEASE_SOURCE", "--as", "TOKEN", "--", "/usr/bin/env",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "super-secret") || !strings.Contains(output, "TOKEN=[REDACTED]") {
		t.Fatalf("secret output was not redacted: %q", output)
	}
}

func TestLeaseRejectsInsecureSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, _ := NewEngine(EngineConfig{})
	_, err := runLeaseVBin(t, eng, []string{"lease", "--from", "file:" + path, "--as", "TOKEN", "--", "/usr/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("insecure secret file was accepted: %v", err)
	}
}
