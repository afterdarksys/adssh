package sys

import (
	"strings"
	"testing"
)

func TestLastEnvWinsKeepsTheLastValue(t *testing.T) {
	got := LastEnvWins([]string{"A=1", "B=2", "A=3", "", "=nope", "C"})
	want := []string{"A=3", "B=2"}
	if len(got) != len(want) {
		t.Fatalf("LastEnvWins = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("LastEnvWins = %#v, want %#v", got, want)
		}
	}
}

func TestSetEnvRejectsBadInput(t *testing.T) {
	s := &Session{ID: "setenv-reject", User: "t"}
	secret := "super-secret-value"
	cases := []struct {
		key, val string
	}{
		{"", secret},
		{"A=B", secret},
		{"A\x00B", secret},
		{"OK", "has\x00nul"},
		{strings.Repeat("k", maxEnvKeyLen+1), secret},
		{"OK", strings.Repeat("v", maxEnvValueLen+1)},
	}
	for _, tc := range cases {
		err := s.SetEnv(tc.key, tc.val)
		if err == nil {
			t.Fatalf("SetEnv(%q) succeeded", tc.key)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q includes the value", err)
		}
	}
	if _, ok := s.OverlayGet("OK"); ok {
		t.Fatal("rejected assignment was stored")
	}
}

func TestSetEnvFullOverlayAllowsUpdate(t *testing.T) {
	s := &Session{ID: "setenv-full", User: "t"}
	for i := 0; i < maxEnvOverlayEntries; i++ {
		if err := s.SetEnv("K"+itoa(i), "v"); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	if err := s.SetEnv("overflow", "x"); err == nil {
		t.Fatal("overlay past the cap was accepted")
	}
	if err := s.SetEnv("K0", "updated"); err != nil {
		t.Fatalf("update at cap: %v", err)
	}
	got, ok := s.OverlayGet("K0")
	if !ok || got != "updated" {
		t.Fatalf("K0 = %q, %v", got, ok)
	}
}

func TestRegisterSessionCapFull(t *testing.T) {
	filler := "adssh-cap-filler"
	if err := RegisterSession(&Session{ID: filler, User: "cap"}); err != nil {
		t.Fatalf("register filler: %v", err)
	}
	t.Cleanup(func() { UnregisterSession(filler) })
	prev, prevRefuse := setSessionCapForTest(uint64(len(ListSessions())), false)
	t.Cleanup(func() { setSessionCapForTest(prev, prevRefuse) })

	fresh := "adssh-cap-filler-new"
	if err := RegisterSession(&Session{ID: fresh, User: "x"}); err == nil {
		UnregisterSession(fresh)
		t.Fatal("registration past the cap succeeded")
	}
	if err := RegisterSession(&Session{ID: filler, User: "cap"}); err != nil {
		t.Fatalf("replacing the filler: %v", err)
	}
}

func TestConfigureHostFromEnvGarbageCap(t *testing.T) {
	sessionsMu.RLock()
	prevCap, prevRefuse := sessionCap, sessionCapRefuse
	sessionsMu.RUnlock()
	prevLimits := sessionLimits()
	t.Cleanup(func() {
		setSessionCapForTest(prevCap, prevRefuse)
		setSessionLimitsForTest(prevLimits)
	})
	t.Setenv("ADSSH_MAX_SESSIONS", "-5")
	t.Setenv("ADSSH_SESSION_NOFILE", "9")
	err := ConfigureHostFromEnv()
	if err == nil {
		t.Fatal("garbage cap was accepted")
	}
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	if !sessionCapRefuse {
		t.Fatal("garbage cap did not refuse new sessions")
	}
	if sessionCap != prevCap || limitNOFILE != prevLimits.nofile {
		t.Fatalf("cap/limit changed: cap %d nofile %d", sessionCap, limitNOFILE)
	}
}

func TestConfigureHostFromEnvGarbageLimit(t *testing.T) {
	sessionsMu.RLock()
	prevCap, prevRefuse := sessionCap, sessionCapRefuse
	sessionsMu.RUnlock()
	prevLimits := sessionLimits()
	t.Cleanup(func() {
		setSessionCapForTest(prevCap, prevRefuse)
		setSessionLimitsForTest(prevLimits)
	})
	t.Setenv("ADSSH_MAX_SESSIONS", "3")
	t.Setenv("ADSSH_SESSION_NOFILE", "-5")
	setSessionCapForTest(7, false)
	err := ConfigureHostFromEnv()
	if err == nil {
		t.Fatal("garbage limit was accepted")
	}
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	if sessionCapRefuse || sessionCap != 7 || limitNOFILE != prevLimits.nofile {
		t.Fatalf("state cap=%d refuse=%v nofile=%d", sessionCap, sessionCapRefuse, limitNOFILE)
	}
}

func TestConfigureHostFromEnvUnlimited(t *testing.T) {
	sessionsMu.RLock()
	prevCap, prevRefuse := sessionCap, sessionCapRefuse
	sessionsMu.RUnlock()
	prevLimits := sessionLimits()
	t.Cleanup(func() {
		setSessionCapForTest(prevCap, prevRefuse)
		setSessionLimitsForTest(prevLimits)
	})
	t.Setenv("ADSSH_MAX_SESSIONS", "0")
	t.Setenv("ADSSH_SESSION_NOFILE", "")
	t.Setenv("ADSSH_SESSION_NPROC", "")
	t.Setenv("ADSSH_SESSION_AS", "")
	t.Setenv("ADSSH_SESSION_FSIZE", "")
	t.Setenv("ADSSH_SESSION_CPU_SECONDS", "")
	if err := ConfigureHostFromEnv(); err != nil {
		t.Fatal(err)
	}
	if err := SessionCapReady(); err != nil {
		t.Fatal(err)
	}
	sessionsMu.RLock()
	got := sessionCap
	sessionsMu.RUnlock()
	if got != 0 {
		t.Fatalf("cap = %d, want 0", got)
	}
	id := "adssh-unlimited-probe"
	if err := RegisterSession(&Session{ID: id, User: "u"}); err != nil {
		t.Fatal(err)
	}
	UnregisterSession(id)
}

func TestConfigureHostFromEnvCPUDefault(t *testing.T) {
	if defaultSessionCPU != 14400 {
		t.Fatalf("defaultSessionCPU = %d, want 14400", defaultSessionCPU)
	}
	sessionsMu.RLock()
	prevCap, prevRefuse := sessionCap, sessionCapRefuse
	sessionsMu.RUnlock()
	prevLimits := sessionLimits()
	t.Cleanup(func() {
		setSessionCapForTest(prevCap, prevRefuse)
		setSessionLimitsForTest(prevLimits)
	})
	t.Setenv("ADSSH_MAX_SESSIONS", "")
	t.Setenv("ADSSH_SESSION_NOFILE", "")
	t.Setenv("ADSSH_SESSION_NPROC", "")
	t.Setenv("ADSSH_SESSION_AS", "")
	t.Setenv("ADSSH_SESSION_FSIZE", "")
	t.Setenv("ADSSH_SESSION_CPU_SECONDS", "")
	if err := ConfigureHostFromEnv(); err != nil {
		t.Fatal(err)
	}
	if got := sessionLimits().cpu; got != 14400 {
		t.Fatalf("empty cpu = %d, want 14400", got)
	}
	t.Setenv("ADSSH_SESSION_CPU_SECONDS", "0")
	if err := ConfigureHostFromEnv(); err != nil {
		t.Fatal(err)
	}
	if got := sessionLimits().cpu; got != 0 {
		t.Fatalf("zero cpu = %d, want unset", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
