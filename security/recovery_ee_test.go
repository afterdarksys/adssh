//go:build ee

package security

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type countReader struct {
	n int
	r io.Reader
}

func (c *countReader) Read(p []byte) (int, error) {
	c.n++
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}

type boomReader struct{}

func (boomReader) Read([]byte) (int, error) { return 0, errors.New("scan broke") }

func TestRecoveryRefusesBeforeRead(t *testing.T) {
	eng, _, sid := adminFix(t)
	cr := &countReader{}
	code, err := RunRecovery(t.Context(), nil, sid, cr, io.Discard)
	if code != 2 || err != nil || cr.n != 0 {
		t.Fatalf("nil engine code %d err %v reads %d", code, err, cr.n)
	}
	cr = &countReader{}
	code, err = RunRecovery(t.Context(), eng, sid, cr, io.Discard)
	if code != 2 || err != nil || cr.n != 0 {
		t.Fatalf("chain off code %d err %v reads %d", code, err, cr.n)
	}
	breakAudit(t, eng)
	cr = &countReader{}
	code, err = RunRecovery(t.Context(), eng, sid, cr, io.Discard)
	if code != 2 || err == nil || !strings.Contains(err.Error(), "directory") || cr.n != 0 {
		t.Fatalf("broken chain code %d err %v reads %d", code, err, cr.n)
	}
}

func TestRecoveryOpenAndMenu(t *testing.T) {
	eng, _, sid := adminFix(t)
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger")
	if err := eng.InitChain(ledger, filepath.Join(dir, "key"), sid); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	code, err := RunRecovery(t.Context(), eng, sid, nil, &out)
	if code != 2 || err != nil || out.Len() != 0 {
		t.Fatalf("nil in code %d err %v out %q", code, err, out.String())
	}
	body, err := os.ReadFile(ledger)
	if err != nil || !strings.Contains(string(body), "RECOVERY_OPEN") {
		t.Fatalf("open log: %v %q", err, body)
	}

	out.Reset()
	code, err = RunRecovery(t.Context(), eng, sid, strings.NewReader("quit\n"), &out)
	if code != 0 || err != nil || !strings.HasPrefix(out.String(), "network\ndisk\njournal\nrestart\nquit\n") {
		t.Fatalf("quit code %d err %v out %q", code, err, out.String())
	}

	out.Reset()
	code, err = RunRecovery(t.Context(), eng, sid, boomReader{}, &out)
	if code != 2 || err == nil || !strings.Contains(err.Error(), "scan broke") {
		t.Fatalf("scan code %d err %v", code, err)
	}
}

func TestRecoveryMenuDispatchesAgentUnit(t *testing.T) {
	eng, _, sid := adminFix(t)
	dir := t.TempDir()
	if err := eng.InitChain(filepath.Join(dir, "ledger"), filepath.Join(dir, "key"), sid); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_AGENT_UNIT", "agent.service")
	var argv []string
	unitRun = func(_ context.Context, got []string) (string, int, error) {
		argv = append([]string{}, got...)
		return "ok", 0, nil
	}
	script := "bash\nrestart extrafield\nrestart bash\nrestart sshd\nquit now\nrestart agent.service\nquit\n"
	var out strings.Builder
	code, err := RunRecovery(t.Context(), eng, sid, strings.NewReader(script), &out)
	if code != 0 || err != nil {
		t.Fatalf("code %d err %v out %q", code, err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "recovery: refused") || !strings.Contains(text, "ok\n") {
		t.Fatalf("out %q", text)
	}
	want := []string{"systemctl", "restart", "agent.service"}
	if len(argv) != len(want) {
		t.Fatalf("argv %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv %v", argv)
		}
	}
}

func TestRecoveryRejectsShellAndSshd(t *testing.T) {
	eng, _, sid := adminFix(t)
	dir := t.TempDir()
	if err := eng.InitChain(filepath.Join(dir, "ledger"), filepath.Join(dir, "key"), sid); err != nil {
		t.Fatal(err)
	}
	ran := false
	unitRun = func(context.Context, []string) (string, int, error) {
		ran = true
		return "no", 0, nil
	}
	for _, name := range []string{"bash", "sshd"} {
		ran = false
		t.Setenv("ADSSH_AGENT_UNIT", name)
		var out strings.Builder
		code, err := RunRecovery(t.Context(), eng, sid, strings.NewReader("restart "+name+"\nquit\n"), &out)
		if code != 0 || err != nil || ran || !strings.Contains(out.String(), "recovery: refused") {
			t.Fatalf("%s code %d err %v ran %v out %q", name, code, err, ran, out.String())
		}
	}
}

func TestRecoveryMissingVerb(t *testing.T) {
	eng, _, sid := adminFix(t)
	err := recoveryDispatch(t.Context(), eng, sid, []string{"not-a-verb"}, io.Discard)
	if !errors.Is(err, errRecoveryRefused) {
		t.Fatalf("missing verb: %v", err)
	}
	err = recoveryDispatch(t.Context(), eng, sid, nil, io.Discard)
	if !errors.Is(err, errRecoveryRefused) {
		t.Fatalf("empty argv: %v", err)
	}
}
