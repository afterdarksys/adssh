package config

import (
	"strings"
	"testing"
)

func TestSAHEnabledFailClosed(t *testing.T) {
	t.Setenv("ADSSH_SAH", "")
	if LoadFromEnv().SAHEnabled {
		t.Fatal("unset ADSSH_SAH enabled the switch")
	}
	for _, v := range []string{"on", "ON", "yes please", "trueish", "2"} {
		t.Setenv("ADSSH_SAH", v)
		if LoadFromEnv().SAHEnabled {
			t.Fatalf("%q enabled the switch", v)
		}
	}
	for _, v := range []string{"1", "true", "TRUE", " yes "} {
		t.Setenv("ADSSH_SAH", v)
		if !LoadFromEnv().SAHEnabled {
			t.Fatalf("%q did not enable the switch", v)
		}
	}
}

func TestGuardSwitchStoredRaw(t *testing.T) {
	t.Setenv("ADSSH_GUARD", "off")
	t.Setenv("ADSSH_GUARD_CONFIG", "")
	t.Setenv("ADSSH_GUARD_STATE", "")
	cfg := LoadFromEnv()
	if cfg.GuardSwitch != "off" {
		t.Fatalf("switch %q", cfg.GuardSwitch)
	}
	if !strings.HasSuffix(cfg.GuardConfigPath, "guard.yaml") {
		t.Fatalf("config %s", cfg.GuardConfigPath)
	}
	if !strings.HasSuffix(cfg.GuardStatePath, "guard-state.json") {
		t.Fatalf("state %s", cfg.GuardStatePath)
	}
}
