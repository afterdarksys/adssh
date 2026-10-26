//go:build ee

package security

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitUsageSessionAndQuarantine(t *testing.T) {
	eng, ctx, sid := adminFix(t)
	usage := "unit: usage: unit <status|restart|stop|logs|check|timers> [NAME]"
	equalErr(t, (unitBinary{}).Run(context.Background(), []string{"unit", "status", "nginx.service"}), "unit: requires a session")
	for _, args := range [][]string{
		{"unit"},
		{"unit", "status"},
		{"unit", "nope", "nginx.service"},
		{"unit", "check", "nginx.service"},
		{"unit", "status", "nginx.service", "extra"},
	} {
		equalErr(t, (unitBinary{}).Run(ctx, args), usage)
	}
	var invoked [][]string
	unitInvoke = func(args []string) { invoked = append(invoked, append([]string(nil), args...)) }
	if err := (unitBinary{}).Run(ctx, []string{"unit", "--help"}); err != nil {
		t.Fatal(err)
	}
	if len(invoked) != 1 || invoked[0][1] != "--help" {
		t.Fatalf("invoke %v", invoked)
	}
	ran := false
	unitRun = func(context.Context, []string) (string, int, error) {
		ran = true
		return "ok", 0, nil
	}
	t.Setenv("ADSSH_QUARANTINE", "1")
	equalErr(t, (unitBinary{}).Run(ctx, []string{"unit", "stop", "nginx.service"}), "unit: refused")
	if !ran && len(invoked) != 2 {
		t.Fatal("stop skipped invoke")
	}
	if ran {
		t.Fatal("stop ran")
	}
	t.Setenv("ADSSH_AGENT_UNIT", "agent.service")
	equalErr(t, (unitBinary{}).Run(ctx, []string{"unit", "restart", "nginx.service"}), "unit: refused")
	if err := (unitBinary{}).Run(ctx, []string{"unit", "restart", "agent.service"}); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("agent restart did not run")
	}
	if err := eng.AuthorizeCommand([]string{"unit", "logs", "nginx.service"}, sid); err != nil {
		t.Fatal(err)
	}
	_ = sid
}

func TestUnitArgvAuditAndExit(t *testing.T) {
	eng, ctx, sid := adminFix(t)
	var got [][]string
	unitRun = func(_ context.Context, argv []string) (string, int, error) {
		got = append(got, append([]string(nil), argv...))
		return "ok", 0, nil
	}
	cases := []struct {
		args []string
		argv []string
	}{
		{[]string{"unit", "status", "nginx.service"}, []string{"systemctl", "status", "nginx.service"}},
		{[]string{"unit", "restart", "nginx.service"}, []string{"systemctl", "restart", "nginx.service"}},
		{[]string{"unit", "stop", "nginx.service"}, []string{"systemctl", "stop", "nginx.service"}},
		{[]string{"unit", "logs", "nginx.service"}, []string{"journalctl", "-u", "nginx.service", "--no-pager", "-n", "200"}},
		{[]string{"unit", "check"}, []string{"systemd-analyze", "verify"}},
		{[]string{"unit", "timers"}, []string{"systemctl", "list-timers"}},
	}
	for _, tc := range cases {
		if err := (unitBinary{}).Run(ctx, tc.args); err != nil {
			t.Fatal(err)
		}
		last := got[len(got)-1]
		if strings.Join(last, " ") != strings.Join(tc.argv, " ") {
			t.Fatalf("argv %v want %v", last, tc.argv)
		}
	}
	unitRun = func(context.Context, []string) (string, int, error) { return "bad", 7, nil }
	out, err := runVBin(t, eng, sid, []string{"unit", "status", "nginx.service"})
	if err != nil || !strings.Contains(out, "bad") {
		t.Fatalf("status: %v %q", err, out)
	}
	equalErr(t, (unitBinary{}).Run(ctx, []string{"unit", "restart", "nginx.service"}), "unit: exit 7")
	unitRun = func(context.Context, []string) (string, int, error) { return "secret", 0, errors.New("boom") }
	equalErr(t, (unitBinary{}).Run(ctx, []string{"unit", "status", "nginx.service"}), "unit: unavailable")
	ran := false
	unitRun = func(context.Context, []string) (string, int, error) { ran = true; return "", 0, nil }
	breakAudit(t, eng)
	err = (unitBinary{}).Run(ctx, []string{"unit", "timers"})
	if err == nil || !strings.HasPrefix(err.Error(), "adssh: audit log failed:") || ran {
		t.Fatalf("audit %v ran=%v", err, ran)
	}
}

func TestUnitMissedTimerReturnsRawAudit(t *testing.T) {
	eng, _, sid := adminFix(t)
	dir := t.TempDir()
	if err := eng.InitChain(filepath.Join(dir, "chain"), filepath.Join(dir, "key"), sid); err != nil {
		t.Fatal(err)
	}
	unitRun = func(context.Context, []string) (string, int, error) {
		eng.chainPath = dir
		return "timer missed\n", 0, nil
	}
	out, err := runVBin(t, eng, sid, []string{"unit", "timers"})
	if err == nil || strings.Contains(err.Error(), "adssh: audit log failed") || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("missed: %v", err)
	}
	if strings.Contains(out, "missed") {
		t.Fatalf("printed %q", out)
	}
}

func TestJournalFormatAndFailures(t *testing.T) {
	eng, ctx, sid := adminFix(t)
	usage := "journal: usage: journal [from NAME] [where PRED] [select FIELDS]"
	equalErr(t, (journalBinary{}).Run(context.Background(), []string{"journal"}), "journal: requires a session")
	for _, args := range [][]string{
		{"journal", "where"},
		{"journal", "where", ""},
		{"journal", "select", ""},
		{"journal", "select", "a,,b"},
		{"journal", "from", "bad name"},
		{"journal", "from", "nginx.service", "from", "nginx.service"},
		{"journal", "nope", "x"},
	} {
		equalErr(t, (journalBinary{}).Run(ctx, args), usage)
	}
	var argv []string
	journalRun = func(_ context.Context, got []string) (string, int, error) {
		argv = append([]string(nil), got...)
		return "{\"MESSAGE\":\"keep-me\"}\n{\"MESSAGE\":\"drop-me\"}\n", 0, nil
	}
	out, err := runVBin(t, eng, sid, []string{"journal", "from", "nginx.service", "where", `row["MESSAGE"] == "keep-me"`, "select", "MESSAGE"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "keep-me") || strings.Contains(out, "drop-me") {
		t.Fatalf("format %q", out)
	}
	if !strings.Contains(strings.Join(argv, " "), "-u nginx.service") {
		t.Fatalf("argv %v", argv)
	}
	journalRun = func(context.Context, []string) (string, int, error) { return "not-json\n", 0, nil }
	out, err = runVBin(t, eng, sid, []string{"journal"})
	if err != nil || !strings.Contains(out, "not-json") {
		t.Fatalf("raw: %v %q", err, out)
	}
	journalRun = func(context.Context, []string) (string, int, error) { return "raw-err\n", 3, nil }
	out, err = runVBin(t, eng, sid, []string{"journal"})
	if err != nil || !strings.Contains(out, "raw-err") {
		t.Fatalf("nonzero: %v %q", err, out)
	}
	journalRun = func(context.Context, []string) (string, int, error) { return "hidden", 0, errors.New("boom") }
	equalErr(t, (journalBinary{}).Run(ctx, []string{"journal"}), "journal: unavailable")
}
