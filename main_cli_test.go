package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const cliHelperEnv = "ADSSH_TEST_CLI_HELPER"

// TestHelperCLIMain runs main() in a child process with the arguments in
// cliHelperEnv (separated by \x1f), so tests see the real exit status.
func TestHelperCLIMain(t *testing.T) {
	spec, ok := os.LookupEnv(cliHelperEnv)
	if !ok {
		t.Skip("helper process only")
	}
	os.Args = []string{"adssh"}
	if spec != "" {
		os.Args = append(os.Args, strings.Split(spec, "\x1f")...)
	}
	main()
	os.Exit(0)
}

// runCLI runs adssh with args and stdin in a scratch HOME and returns its
// stdout, stderr and exit status.
func runCLI(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperCLIMain$")
	env := []string{cliHelperEnv + "=" + strings.Join(args, "\x1f"), "HOME=" + home, "XDG_CONFIG_HOME=" + home + "/.config", "XDG_DATA_HOME=" + home + "/.local/share", "XDG_STATE_HOME=" + home + "/.local/state"}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "ADSSH_") && !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "XDG_") {
			env = append(env, kv)
		}
	}
	cmd.Env = env
	cmd.Dir = home
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	return out.String(), errOut.String(), code
}

func TestCLIExitStatusFromDashC(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want int
	}{
		{"exit 3", 3},
		{"false", 1},
		{"true", 0},
		{"echo hi; exit 7", 7},
		{"if true; then exit 4; fi", 4},
	} {
		_, stderr, code := runCLI(t, "", "-c", tc.src)
		if code != tc.want {
			t.Errorf("-c %q: exit %d, want %d (stderr %q)", tc.src, code, tc.want, stderr)
		}
		if strings.Contains(stderr, "exit status") {
			t.Errorf("-c %q printed the exit status: %q", tc.src, stderr)
		}
	}
}

func TestCLIExitStatusFromREPL(t *testing.T) {
	for _, tc := range []struct {
		stdin string
		want  int
	}{
		{"exit 3\n", 3},
		{"exit 3\necho not-reached\n", 3},
		{"false\n", 1},
		{"true\n", 0},
		{"false\nexit\n", 1},
		{"false\ntrue\nexit\n", 0},
		{"x = 1\nexit 5\n", 5},
	} {
		stdout, stderr, code := runCLI(t, tc.stdin)
		if code != tc.want {
			t.Errorf("stdin %q: exit %d, want %d (stderr %q)", tc.stdin, code, tc.want, stderr)
		}
		if strings.Contains(stdout, "not-reached") {
			t.Errorf("stdin %q: ran a line after exit", tc.stdin)
		}
	}
}

func TestCLIUnknownOptionExits2(t *testing.T) {
	for _, arg := range []string{"--bogus", "-x", "--serve"} {
		_, stderr, code := runCLI(t, "", arg)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 (stderr %q)", arg, code, stderr)
		}
		if !strings.Contains(stderr, "adssh: ") || !strings.Contains(stderr, "adssh --help") {
			t.Errorf("%s: stderr %q, want the error and the usage hint", arg, stderr)
		}
	}
	if _, stderr, _ := runCLI(t, "", "--bogus"); !strings.Contains(stderr, "adssh: unknown option: --bogus") {
		t.Errorf("stderr %q", stderr)
	}
	// Known flags still work.
	for _, args := range [][]string{
		{"-r", "-c", "echo ok"},
		{"--restricted", "-c", "echo ok"},
		{"-l", "-c", "echo ok"},
		{"--login", "-c", "echo ok"},
		{"--policy", "/nonexistent.rego", "-c", "echo ok"},
	} {
		stdout, stderr, code := runCLI(t, "", args...)
		if code != 0 || !strings.Contains(stdout, "ok") {
			t.Errorf("%v: exit %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
	if stdout, _, code := runCLI(t, "", "--help"); code != 0 || !strings.Contains(stdout, "USAGE") {
		t.Errorf("--help: exit %d", code)
	}
}
