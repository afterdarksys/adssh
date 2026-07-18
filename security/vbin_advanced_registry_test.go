package security

import "testing"

func TestAdvancedVBinsAreRegisteredAndDiscoverable(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"pick", "nav", "from", "where", "select", "to",
		"why", "runbook", "par", "evidence", "lease",
	} {
		vbin, ok := eng.Lookup(name)
		if !ok {
			t.Errorf("advanced VBIN %q is not registered", name)
			continue
		}
		if vbin.Description() == "" || vbin.Usage() == "" {
			t.Errorf("advanced VBIN %q lacks discovery metadata", name)
		}
	}
}
