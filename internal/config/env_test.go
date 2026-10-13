package config

import "testing"

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
