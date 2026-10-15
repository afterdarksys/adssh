package guard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T) {
	t.Helper()
	ResetForTest()
	prev := now
	t.Cleanup(func() {
		now = prev
		ResetForTest()
	})
}

func writeMode(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the process umask and does not change the mode of
	// an existing file. The requested mode is the one the jail must see.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// configureDoc installs a jail. An empty doc leaves the config file missing
// so the built-in defaults apply.
func configureDoc(t *testing.T, doc, sw string) (dir, state string) {
	t.Helper()
	setup(t)
	dir = t.TempDir()
	cfgPath := filepath.Join(dir, "missing-guard.yaml")
	if doc != "" {
		cfgPath = filepath.Join(dir, "guard.yaml")
		writeMode(t, cfgPath, doc, 0o644)
	}
	state = filepath.Join(dir, "guard-state.json")
	if err := Configure(Options{ConfigPath: cfgPath, StatePath: state, Switch: sw}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	return dir, state
}

func failHandshake(t *testing.T, addr string) {
	t.Helper()
	d := Admit(addr)
	if !d.Allow {
		t.Fatalf("admit %s before failure: %+v", addr, d)
	}
	NoteHandshake(addr, false)
}

func TestHandshakeBansOnFifthFailure(t *testing.T) {
	configureDoc(t, "", "")
	const addr = "203.0.113.10"
	for i := 0; i < 5; i++ {
		failHandshake(t, addr)
	}
	d := Admit(addr)
	if d.Allow || d.Reason != "banned" || d.Addr != addr {
		t.Fatalf("after 5 failures: %+v", d)
	}
	st := Status()
	if len(st.Bans) != 1 || st.Bans[0].Addr != addr || st.Bans[0].Reason != "handshake" {
		t.Fatalf("bans: %+v", st.Bans)
	}
}

func TestSuccessDoesNotClearStrikes(t *testing.T) {
	configureDoc(t, "max_retry: 3\nrate_limit: 100\n", "")
	const addr = "203.0.113.11"
	failHandshake(t, addr)
	failHandshake(t, addr)
	NoteHandshake(addr, true)
	failHandshake(t, addr)
	d := Admit(addr)
	if d.Allow || d.Reason != "banned" {
		t.Fatalf("success pardoned strikes: %+v", d)
	}
	if Status().Bans[0].Reason != "handshake" {
		t.Fatalf("bans: %+v", Status().Bans)
	}
}

func TestExpiryAllowsTheNextAttempt(t *testing.T) {
	configureDoc(t, "max_retry: 1\nban_time: 1s\nrate_limit: 100\n", "")
	clock := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return clock }
	const addr = "203.0.113.12"
	failHandshake(t, addr)
	if d := Admit(addr); d.Allow || d.Reason != "banned" {
		t.Fatalf("fresh ban: %+v", d)
	}
	clock = clock.Add(2 * time.Second)
	if d := Admit(addr); !d.Allow {
		t.Fatalf("expired ban still denied: %+v", d)
	}
}

func TestLoopbackIsIgnoredByDefault(t *testing.T) {
	configureDoc(t, "max_retry: 1\nrate_limit: 100\n", "")
	for _, addr := range []string{"127.0.0.1", "127.8.8.8", "::1", "::ffff:127.0.0.1", "[::1]:2222"} {
		failHandshake(t, addr)
		if d := Admit(addr); !d.Allow {
			t.Fatalf("%s was counted: %+v", addr, d)
		}
	}
	const pub = "203.0.113.13"
	failHandshake(t, pub)
	if d := Admit(pub); d.Allow || d.Reason != "banned" {
		t.Fatalf("public peer: %+v", d)
	}
}

func TestExplicitEmptyIgnoreDoesNotSpareLoopback(t *testing.T) {
	for _, doc := range []string{
		"max_retry: 1\nrate_limit: 100\nignore: []\n",
		"max_retry: 1\nrate_limit: 100\nignore: null\n",
		"max_retry: 1\nrate_limit: 100\nignore:\n",
	} {
		t.Run(doc, func(t *testing.T) {
			configureDoc(t, doc, "")
			failHandshake(t, "127.0.0.1")
			d := Admit("127.0.0.1")
			if d.Allow || d.Reason != "banned" {
				t.Fatalf("loopback spared: %+v", d)
			}
		})
	}
}

func TestDisabledFileDoesNotCount(t *testing.T) {
	configureDoc(t, "enabled: false\nmax_retry: 1\nrate_limit: 1\n", "")
	const addr = "203.0.113.14"
	for i := 0; i < 3; i++ {
		if d := Admit(addr); !d.Allow {
			t.Fatalf("disabled admit: %+v", d)
		}
		NoteHandshake(addr, false)
	}
	st := Status()
	if len(st.Bans) != 0 || st.Enabled {
		t.Fatalf("status: %+v", st)
	}
}

func TestBadConfigAndStateFailClosed(t *testing.T) {
	setup(t)
	clock := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return clock }
	far := clock.Add(367 * 24 * time.Hour).UTC().Format(time.RFC3339)
	cases := []struct {
		name  string
		cfg   string
		state string
		mode  os.FileMode
		want  string
	}{
		{"far until", "enabled: true\n", fmt.Sprintf(`{"v":1,"bans":[{"addr":"203.0.113.8","until":%q,"reason":"handshake"}]}`, far), 0o600, "too far"},
		{"zero until", "enabled: true\n", `{"v":1,"bans":[{"addr":"203.0.113.8","until":"0001-01-01T00:00:00Z","reason":"handshake"}]}`, 0o600, "zero"},
		{"bad version", "enabled: true\n", `{"v":2}`, 0o600, "version"},
		{"unknown field", "enabled: true\n", `{"v":1,"extra":true}`, 0o600, "extra"},
		{"loose mode", "enabled: true\n", `{"v":1}`, 0o666, "mode"},
		{"unknown yaml", "nope: 1\n", "", 0, "nope"},
		{"max retry zero", "max_retry: 0\n", "", 0, "max_retry"},
		{"ignore v4 slash zero", "ignore: [\"0.0.0.0/0\"]\n", "", 0, "mask size 0"},
		{"ignore v6 slash zero", "ignore: [\"::/0\"]\n", "", 0, "mask size 0"},
		{"hostname ignore", "ignore: [\"example.com\"]\n", "", 0, "example.com"},
		{"empty config", "", "", 0, "empty"},
		{"comment only", "# only a comment\n", "", 0, "empty"},
		{"whitespace config", "\n\n", "", 0, "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setup(t)
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "guard.yaml")
			statePath := filepath.Join(dir, "guard-state.json")
			if tc.cfg != "" || tc.name == "empty config" || tc.name == "whitespace config" {
				mode := os.FileMode(0o644)
				if err := os.WriteFile(cfgPath, []byte(tc.cfg), mode); err != nil {
					t.Fatal(err)
				}
			}
			if tc.state != "" {
				writeMode(t, statePath, tc.state, tc.mode)
			}
			err := Configure(Options{ConfigPath: cfgPath, StatePath: statePath})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("configure error %v, want substring %q", err, tc.want)
			}
			if ready := Ready(); ready == nil {
				t.Fatal("tripped jail reported ready")
			}
		})
	}
}

func TestOversizedAndSymlinkFilesFailClosed(t *testing.T) {
	setup(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guard.yaml")
	statePath := filepath.Join(dir, "guard-state.json")
	if err := os.WriteFile(cfgPath, bytes.Repeat([]byte("a"), int(maxConfigBytes)+1), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Configure(Options{ConfigPath: cfgPath, StatePath: statePath})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized config: %v", err)
	}

	setup(t)
	dir = t.TempDir()
	cfgPath = filepath.Join(dir, "guard.yaml")
	statePath = filepath.Join(dir, "guard-state.json")
	writeMode(t, cfgPath, "enabled: true\n", 0o644)
	if err := os.WriteFile(statePath, append([]byte(`{"v":1}`), bytes.Repeat([]byte(" "), int(maxStateBytes))...), 0o600); err != nil {
		t.Fatal(err)
	}
	err = Configure(Options{ConfigPath: cfgPath, StatePath: statePath})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized state: %v", err)
	}

	setup(t)
	dir = t.TempDir()
	cfgPath = filepath.Join(dir, "guard.yaml")
	statePath = filepath.Join(dir, "guard-state.json")
	real := filepath.Join(dir, "real.json")
	writeMode(t, cfgPath, "enabled: true\n", 0o644)
	writeMode(t, real, `{"v":1}`, 0o600)
	if err := os.Symlink(real, statePath); err != nil {
		t.Fatal(err)
	}
	err = Configure(Options{ConfigPath: cfgPath, StatePath: statePath})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink state: %v", err)
	}
	if Ready() == nil {
		t.Fatal("symlink state left the listener ready")
	}
}

func TestUnbanClearsStrikes(t *testing.T) {
	configureDoc(t, "max_retry: 2\nrate_limit: 100\n", "")
	const addr = "203.0.113.15"
	if _, err := Unban(addr); !errors.Is(err, ErrNotBanned) {
		t.Fatalf("unknown unban: %v", err)
	}
	failHandshake(t, addr)
	failHandshake(t, addr)
	key, err := Unban(addr + ":22")
	if err != nil || key != addr {
		t.Fatalf("unban %s: %v", key, err)
	}
	failHandshake(t, addr)
	if d := Admit(addr); !d.Allow {
		t.Fatalf("one failure after unban re-banned: %+v", d)
	}
}

func TestUnbanMappedAddressLiftsCanonicalBan(t *testing.T) {
	configureDoc(t, "max_retry: 1\nrate_limit: 100\n", "")
	failHandshake(t, "1.2.3.4")
	key, err := Unban("::ffff:1.2.3.4")
	if err != nil || key != "1.2.3.4" {
		t.Fatalf("unban mapped: key=%s err=%v", key, err)
	}
	if d := Admit("1.2.3.4"); !d.Allow {
		t.Fatalf("canonical still banned: %+v", d)
	}
}

func TestRateLimitBansOnSecondAdmit(t *testing.T) {
	configureDoc(t, "rate_limit: 2\nmax_retry: 50\n", "")
	const addr = "203.0.113.16"
	if d := Admit(addr); !d.Allow {
		t.Fatalf("first: %+v", d)
	}
	d := Admit(addr)
	if d.Allow || d.Reason != "rate" {
		t.Fatalf("second: %+v", d)
	}
	if len(Status().Bans) != 1 || Status().Bans[0].Reason != "rate" {
		t.Fatalf("bans: %+v", Status().Bans)
	}
}

func TestMappedIPv4SharesABucket(t *testing.T) {
	configureDoc(t, "max_retry: 2\nrate_limit: 100\n", "")
	NoteHandshake("1.2.3.4", false)
	NoteHandshake("[::ffff:1.2.3.4]:22", false)
	for _, addr := range []string{"1.2.3.4", "::ffff:1.2.3.4"} {
		d := Admit(addr)
		if d.Allow || d.Reason != "banned" || d.Addr != "1.2.3.4" {
			t.Fatalf("%s: %+v", addr, d)
		}
	}
}

func TestTableFullDeniesASecondAddress(t *testing.T) {
	configureDoc(t, "max_entries: 1\nmax_retry: 1\nrate_limit: 100\n", "")
	failHandshake(t, "203.0.113.1")
	d := Admit("203.0.113.2")
	if d.Allow || d.Reason != "table_full" {
		t.Fatalf("second address: %+v", d)
	}
	NoteHandshake("203.0.113.2", false)
	st := Status()
	if len(st.Bans) != 1 || st.Bans[0].Addr != "203.0.113.1" {
		t.Fatalf("bans: %+v", st.Bans)
	}
}

func TestSwitchOffSkipsCorruptFiles(t *testing.T) {
	setup(t)
	dir := t.TempDir()
	writeMode(t, filepath.Join(dir, "guard.yaml"), "not: [yaml\n", 0o644)
	writeMode(t, filepath.Join(dir, "guard-state.json"), "nope", 0o666)
	err := Configure(Options{
		ConfigPath: filepath.Join(dir, "guard.yaml"),
		StatePath:  filepath.Join(dir, "guard-state.json"),
		Switch:     "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := Admit("not-an-ip"); !d.Allow {
		t.Fatalf("forced off counted a bad peer: %+v", d)
	}
	if d := Admit("203.0.113.1"); !d.Allow {
		t.Fatalf("forced off denied: %+v", d)
	}
	NoteHandshake("203.0.113.1", false)
	if d := Admit("203.0.113.1"); !d.Allow {
		t.Fatalf("forced off banned: %+v", d)
	}
	if Ready() != nil {
		t.Fatal(Ready())
	}
	if _, err := Unban("203.0.113.1"); !errors.Is(err, ErrInactive) {
		t.Fatalf("unban while forced off: %v", err)
	}
}

func TestBadPeerIsDenied(t *testing.T) {
	configureDoc(t, "", "")
	for _, addr := range []string{"not-an-ip", "fe80::1%eth0"} {
		d := Admit(addr)
		if d.Allow || d.Reason != "bad_peer" {
			t.Fatalf("%s: %+v", addr, d)
		}
	}
}

func TestFileUnbanClearsStrikes(t *testing.T) {
	_, state := configureDoc(t, "max_retry: 2\nrate_limit: 100\n", "")
	const addr = "203.0.113.17"
	failHandshake(t, addr)
	failHandshake(t, addr)
	if d := Admit(addr); d.Reason != "banned" {
		t.Fatalf("expected ban: %+v", d)
	}
	writeMode(t, state, `{"v":1,"bans":[]}`, 0o600)
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(state, future, future); err != nil {
		t.Fatal(err)
	}
	if d := Admit(addr); !d.Allow {
		t.Fatalf("file unban did not lift: %+v", d)
	}
	NoteHandshake(addr, false)
	if d := Admit(addr); !d.Allow {
		t.Fatalf("one failure after file unban re-banned: %+v", d)
	}
}

func TestReloadKeepsPreviousConfigWhenTheFileIsBad(t *testing.T) {
	dir, _ := configureDoc(t, "max_retry: 2\nrate_limit: 100\n", "")
	if err := os.WriteFile(filepath.Join(dir, "guard.yaml"), []byte("max_retry: 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Reload(); err == nil || !strings.Contains(err.Error(), "max_retry") {
		t.Fatalf("reload: %v", err)
	}
	if Status().MaxRetry != 2 {
		t.Fatalf("max_retry changed to %d", Status().MaxRetry)
	}
	const addr = "203.0.113.18"
	failHandshake(t, addr)
	if d := Admit(addr); !d.Allow {
		t.Fatalf("one failure banned under the old max_retry: %+v", d)
	}
	failHandshake(t, addr)
	if d := Admit(addr); d.Allow || d.Reason != "banned" {
		t.Fatalf("two failures: %+v", d)
	}
}

func TestReloadAppliesAGoodConfig(t *testing.T) {
	dir, _ := configureDoc(t, "max_retry: 5\nrate_limit: 100\n", "")
	if err := os.WriteFile(filepath.Join(dir, "guard.yaml"), []byte("max_retry: 1\nrate_limit: 100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Reload(); err != nil {
		t.Fatal(err)
	}
	if Status().MaxRetry != 1 {
		t.Fatalf("max_retry %d", Status().MaxRetry)
	}
	const addr = "203.0.113.19"
	failHandshake(t, addr)
	if d := Admit(addr); d.Allow || d.Reason != "banned" {
		t.Fatalf("after reload: %+v", d)
	}
}

func TestPersistFailureTripsTheJail(t *testing.T) {
	dir, _ := configureDoc(t, "max_retry: 1\nrate_limit: 100\n", "")
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	const addr = "203.0.113.20"
	if d := Admit(addr); !d.Allow {
		t.Fatalf("first admit: %+v", d)
	}
	NoteHandshake(addr, false)
	d := Admit(addr)
	if d.Allow || d.Reason != "guard_unavailable" {
		t.Fatalf("after persist failure: %+v", d)
	}
	if !strings.Contains(Status().Tripped, "guard_unavailable") {
		t.Fatalf("tripped: %q", Status().Tripped)
	}
	if loop := Admit("127.0.0.1"); !loop.Allow {
		t.Fatalf("loopback denied while tripped: %+v", loop)
	}
}

func TestRecorderSeesOnlyTheCrossingFailure(t *testing.T) {
	configureDoc(t, "max_retry: 2\nrate_limit: 100\n", "")
	var got []Event
	SetRecorder(func(ev Event) { got = append(got, ev) })
	const addr = "203.0.113.21"
	failHandshake(t, addr)
	if len(got) != 0 {
		t.Fatalf("non-crossing events: %+v", got)
	}
	failHandshake(t, addr)
	if len(got) != 2 || got[0].Action != "threshold" || got[1].Action != "ban" {
		t.Fatalf("events: %+v", got)
	}
	for _, ev := range got {
		if ev.Addr != addr || ev.Reason != "handshake" {
			t.Fatalf("event: %+v", ev)
		}
		blob := ev.Action + ev.Addr + ev.Reason
		if strings.Contains(blob, "PRIVATE") || strings.Contains(blob, "BEGIN") {
			t.Fatalf("event carried key material: %+v", ev)
		}
	}
}

func TestStatusDoesNotInstallTheLazyJail(t *testing.T) {
	setup(t)
	st := Status()
	if !st.Enabled || st.ConfigPath != "" || len(st.Bans) != 0 {
		t.Fatalf("unconfigured status: %+v", st)
	}
	if _, err := Unban("203.0.113.22"); !errors.Is(err, ErrInactive) {
		t.Fatalf("unban before admit: %v", err)
	}
	if Ready() != nil {
		t.Fatal(Ready())
	}
	if d := Admit("203.0.113.22"); !d.Allow {
		t.Fatalf("lazy admit: %+v", d)
	}
	if _, err := Unban("203.0.113.22"); !errors.Is(err, ErrNotBanned) {
		t.Fatalf("unban after lazy admit: %v", err)
	}
}

func TestEmptyDocumentUsesDefaults(t *testing.T) {
	configureDoc(t, "{}\n", "")
	st := Status()
	if !st.Enabled || st.MaxRetry != 5 || st.FindTime != "10m0s" || st.BanTime != "1h0m0s" {
		t.Fatalf("defaults: %+v", st)
	}
	if len(st.Ignore) != 2 || st.Ignore[0] != "127.0.0.0/8" || st.Ignore[1] != "::1/128" {
		t.Fatalf("ignore: %#v", st.Ignore)
	}
}

func TestSlashOneCIDRIsAccepted(t *testing.T) {
	configureDoc(t, "ignore: [\"10.0.0.0/1\"]\n", "")
	st := Status()
	if len(st.Ignore) != 1 || st.Ignore[0] != "10.0.0.0/1" {
		t.Fatalf("ignore: %#v", st.Ignore)
	}
}

func TestForceOnOverridesDisabledFile(t *testing.T) {
	configureDoc(t, "enabled: false\nmax_retry: 1\nrate_limit: 100\n", "on")
	if !Status().Enabled {
		t.Fatal("force on left the jail disabled")
	}
	failHandshake(t, "203.0.113.23")
	if d := Admit("203.0.113.23"); d.Allow || d.Reason != "banned" {
		t.Fatalf("force on did not ban: %+v", d)
	}
}

func TestEmitStripsControlsAndDropsUnknownTokens(t *testing.T) {
	setup(t)
	var got []Event
	SetRecorder(func(ev Event) { got = append(got, ev) })
	emitAll([]Event{{Action: "ba\nn", Addr: "1.2.3.4\x00", Reason: "hand\x7fshake"}})
	emitAll([]Event{{Action: "nope", Addr: "1.2.3.4", Reason: "handshake"}})
	emitAll([]Event{{Action: "ban", Addr: "1.2.3.4", Reason: "injected"}})
	if len(got) != 1 {
		t.Fatalf("events: %+v", got)
	}
	if got[0].Action != "ban" || got[0].Addr != "1.2.3.4" || got[0].Reason != "handshake" {
		t.Fatalf("stripped event: %+v", got[0])
	}
}

func TestCheckersDoNotReplaceTheLiveJail(t *testing.T) {
	dir, state := configureDoc(t, "max_retry: 4\n", "")
	if err := CheckConfig(filepath.Join(dir, "absent.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := CheckState(filepath.Join(dir, "absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing state: %v", err)
	}
	if err := CheckState(""); err == nil {
		t.Fatal("empty state path accepted")
	}
	if Status().MaxRetry != 4 || Status().StatePath != state {
		t.Fatalf("checkers replaced the jail: %+v", Status())
	}
}

func TestWorldReadableConfigIsAccepted(t *testing.T) {
	setup(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guard.yaml")
	writeMode(t, cfgPath, "max_retry: 3\n", 0o755)
	if err := Configure(Options{ConfigPath: cfgPath, StatePath: filepath.Join(dir, "guard-state.json")}); err != nil {
		t.Fatal(err)
	}
	writeMode(t, cfgPath, "max_retry: 3\n", 0o664)
	if err := CheckConfig(cfgPath); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group writable config: %v", err)
	}
}
