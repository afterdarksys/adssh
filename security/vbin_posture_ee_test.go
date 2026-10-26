//go:build ee

package security

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestListenLines(t *testing.T) {
	cases := []struct{ in, want string }{
		{"tcp4 0 0 127.0.0.1.22 *.* LISTEN", "listen 127.0.0.1:22"},
		{"tcp4 0 0 *.22 *.* LISTEN", "listen 0.0.0.0:22"},
		{"tcp6 0 0 ::1.22 *.* LISTEN", "listen [::1]:22"},
		{"tcp6 0 0 ::.22 *.* LISTEN", "listen [::]:22"},
		{"tcp4 0 0 127.0.0.1:80 *.* LISTEN", "listen 127.0.0.1:80"},
		{"tcp6 0 0 [::1]:22 *.* LISTEN", "listen [::1]:22"},
		{"tcp6 0 0 [::]:443 *.* LISTEN", "listen [::]:443"},
		{"tcp4 0 0 127.0.0.1.http *.* LISTEN", "listen open"},
		{"tcp4 0 0 127.0.0.1.22 *.* ESTABLISHED", "listen none"},
	}
	for _, tc := range cases {
		if got := listenLines(tc.in); got != tc.want {
			t.Fatalf("%q → %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestNetAndDisk(t *testing.T) {
	eng, ctx, sid := adminFix(t)
	equalErr(t, (netBinary{}).Run(context.Background(), []string{"net"}), "net: requires a session")
	equalErr(t, (netBinary{}).Run(ctx, []string{"net", "extra"}), "net: usage: net")
	if err := (netBinary{}).Run(context.Background(), []string{"net", "--help"}); err != nil {
		t.Fatal(err)
	}
	netRun = func(context.Context, []string) (string, int, error) { return "LISTEN junk", 3, nil }
	out, err := runVBin(t, eng, sid, []string{"net"})
	if err != nil || out != "LISTEN junk\n" {
		t.Fatalf("net: %v %q", err, out)
	}
	netRun = func(context.Context, []string) (string, int, error) { return "hidden", 0, errors.New("boom") }
	equalErr(t, (netBinary{}).Run(ctx, []string{"net"}), "net: unavailable")

	equalErr(t, (diskBinary{}).Run(context.Background(), []string{"disk"}), "disk: requires a session")
	equalErr(t, (diskBinary{}).Run(ctx, []string{"disk", "extra"}), "disk: usage: disk")
	if err := (diskBinary{}).Run(context.Background(), []string{"disk", "--help"}); err != nil {
		t.Fatal(err)
	}
	var argv []string
	diskRun = func(_ context.Context, got []string) (string, int, error) {
		argv = append([]string(nil), got...)
		return "df-ok", 0, nil
	}
	out, err = runVBin(t, eng, sid, []string{"disk"})
	if err != nil || out != "df-ok\n" || strings.Join(argv, " ") != "df -P" {
		t.Fatalf("disk: %v %q %v", err, out, argv)
	}
	diskRun = func(context.Context, []string) (string, int, error) { return "full", 2, nil }
	out, err = runVBin(t, eng, sid, []string{"disk"})
	if err != nil || out != "full\n" {
		t.Fatalf("disk nonzero: %v %q", err, out)
	}
	diskRun = func(context.Context, []string) (string, int, error) { return "hidden", 0, errors.New("boom") }
	equalErr(t, (diskBinary{}).Run(ctx, []string{"disk"}), "disk: unavailable")
}

func TestPostureBuckets(t *testing.T) {
	eng, ctx, sid := adminFix(t)
	equalErr(t, (postureBinary{}).Run(context.Background(), []string{"posture"}), "posture: requires a session")
	equalErr(t, (postureBinary{}).Run(ctx, []string{"posture", "extra"}), "posture: usage: posture")
	cases := []struct {
		text string
		code int
		err  error
		env  string
		want string
	}{
		{"listen 0.0.0.0:22\n", 0, nil, "", "ssh=open admin=closed listeners=open chain=0\n"},
		{"", 0, nil, "", "ssh=open admin=open listeners=open chain=0\n"},
		{"", 0, errors.New("probe"), "", "ssh=open admin=open listeners=open chain=0\n"},
		{"listen 127.0.0.1:22\n", 0, nil, "", "ssh=closed admin=closed listeners=closed chain=0\n"},
		{"listen 0.0.0.0:9443\n", 0, nil, "127.0.0.1:9443", "ssh=closed admin=open listeners=open chain=0\n"},
		{"listen none", 0, nil, "", "ssh=closed admin=closed listeners=closed chain=0\n"},
	}
	for _, tc := range cases {
		t.Setenv("ADSSH_ADMIN_LISTEN", tc.env)
		netShow = func(context.Context) (string, int, error) { return tc.text, tc.code, tc.err }
		out, err := runVBin(t, eng, sid, []string{"posture"})
		if err != nil || out != tc.want {
			t.Fatalf("posture %q: %v got %q", tc.text, err, out)
		}
	}
	dir := t.TempDir()
	if err := eng.InitChain(filepath.Join(dir, "chain"), filepath.Join(dir, "key"), sid); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("HOST_PROFILE host=host-1 users=alice units=nginx.service policy=abc adminkeys=def"); err != nil {
		t.Fatal(err)
	}
	netShow = func(context.Context) (string, int, error) { return "listen 0.0.0.0:22\n", 0, nil }
	t.Setenv("ADSSH_ADMIN_LISTEN", "")
	out, err := runVBin(t, eng, sid, []string{"posture"})
	if err != nil || out != "ssh=open admin=closed listeners=open chain=1\n" {
		t.Fatalf("chain: %v %q", err, out)
	}
}
