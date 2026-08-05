package security

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runMirrorVBin(t *testing.T, eng *Engine, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(ctx, mirrorBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("mirror-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func TestMirrorListShowsSessionMetadataWithRedactedCommand(t *testing.T) {
	session := &sys.Session{ID: "mirror-list", User: "alice", Principals: []string{"ops"}}
	sys.RegisterSession(session)
	defer sys.UnregisterSession(session.ID)
	session.SetCurrentCommand("deploy token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ")

	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := runMirrorVBin(t, eng, []string{"mirror", "list"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mirror-list", "user=alice", "principals=ops", "command=\"deploy token=[REDACTED]\""} {
		if !strings.Contains(output, want) {
			t.Fatalf("mirror list output missing %q: %q", want, output)
		}
	}
	if strings.Contains(output, "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ") {
		t.Fatalf("mirror list leaked token-shaped command: %q", output)
	}
}

func TestMirrorKillCancelsSessionAndAudits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &sys.Session{ID: "mirror-kill", User: "alice"}
	session.SetContext(ctx, cancel)
	sys.RegisterSession(session)
	defer sys.UnregisterSession(session.ID)

	dir := t.TempDir()
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    "supervisor",
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err := runMirrorVBin(t, eng, []string{"mirror", "kill", "mirror-kill"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Terminated session mirror-kill") {
		t.Fatalf("kill output = %q", output)
	}
	if ctx.Err() != context.Canceled {
		t.Fatalf("session context was not canceled: %v", ctx.Err())
	}
	if !sys.GetSession("mirror-kill").Info().Terminated {
		t.Fatal("session was not marked terminated")
	}
	chain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chain), "MIRROR_KILL: session=mirror-kill") {
		t.Fatalf("kill was not audited: %s", chain)
	}
}
