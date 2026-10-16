package sys

import (
	"encoding/hex"
	"testing"
)

func TestGenerateSessionIDIs128Bits(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		id := GenerateSessionID()
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != 16 {
			t.Fatalf("id %q is not 128-bit hex", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestRegisterSessionRejectsDuplicateID(t *testing.T) {
	id := "dup-register-" + GenerateSessionID()
	first := &Session{ID: id, User: "alice"}
	if err := RegisterSession(first); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { UnregisterSession(id) })
	if err := RegisterSession(&Session{ID: id, User: "mallory"}); err == nil {
		t.Fatal("a second session registered under an existing id")
	}
	if got := GetSession(id); got != first || got.User != "alice" {
		t.Fatalf("registered session was replaced: %+v", got)
	}
	if err := RegisterSession(first); err == nil {
		t.Fatal("re-registering the same session succeeded")
	}
}
