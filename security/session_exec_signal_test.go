//go:build unix

package security

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const sessionExecSignalHelperEnv = "ADSSH_TEST_SESSION_EXEC_SIGNAL_HELPER"

func TestHelperSessionExecSignals(t *testing.T) {
	if os.Getenv(sessionExecSignalHelperEnv) != "1" {
		t.Skip("helper process")
	}
	sys.SetupSignals()
	var out bytes.Buffer
	r, err := interp.New(
		interp.Env(expand.ListEnviron(os.Environ()...)),
		interp.StdIO(nil, &out, &out),
		interp.ExecHandlers(SessionExecHandler),
	)
	if err != nil {
		os.Stdout.WriteString("interp: " + err.Error())
		os.Exit(2)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(`/bin/sh -c 'kill -INT $$; echo survived'`), "t.sh")
	if err != nil {
		os.Exit(2)
	}
	_ = r.Run(context.Background(), file)
	os.Stdout.Write(out.Bytes())
	os.Stdout.WriteString("done\n")
	os.Exit(0)
}

func TestSessionExecHandlerSignalChildDiesOnSIGINT(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSessionExecSignals$")
	cmd.Env = append(os.Environ(), sessionExecSignalHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "done") || strings.Contains(string(out), "survived") {
		t.Fatalf("a SessionExecHandler child survived SIGINT after SetupSignals: %q", out)
	}
}
