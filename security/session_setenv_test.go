package security

import (
	"context"
	"os"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"

	"go.starlark.net/starlark"
)

func TestExecHandlerSetWritesSessionOverlay(t *testing.T) {
	const key = "ADSSH_EXEC_SET_PROBE"
	prev, had := os.LookupEnv(key)
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})

	id := "sess-set-probe"
	session := &sys.Session{ID: id, User: "t"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })

	eng, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh.authz\ndefault allow = true\n")})
	if err != nil {
		t.Fatal(err)
	}
	globals := starlark.StringDict{"SESSION_ID": starlark.String(id)}
	nextCalled := false
	h := eng.execHandler(false, globals, nil)(func(ctx context.Context, args []string) error {
		nextCalled = true
		return nil
	})
	if err := h(context.Background(), []string{"set", key + "=session-value"}); err != nil {
		t.Fatal(err)
	}
	if nextCalled {
		t.Fatal("set assignment called next")
	}
	if os.Getenv(key) != prev && (had || os.Getenv(key) != "") {
		t.Fatalf("process env changed to %q", os.Getenv(key))
	}
	got, ok := session.LookupEnv(key)
	if !ok || got != "session-value" {
		t.Fatalf("overlay = %q ok=%v", got, ok)
	}
	if g, ok := globals[key].(starlark.String); !ok || string(g) != "session-value" {
		t.Fatalf("global = %#v", globals[key])
	}

	missing := starlark.StringDict{"SESSION_ID": starlark.String("sess-set-missing")}
	t.Setenv(key, "sentinel")
	mh := eng.execHandler(false, missing, nil)(func(ctx context.Context, args []string) error {
		t.Fatal("missing session called next")
		return nil
	})
	if err := mh(context.Background(), []string{"set", key + "=nope"}); err == nil {
		t.Fatal("missing session was accepted")
	}
	if os.Getenv(key) != "sentinel" {
		t.Fatalf("process env = %q", os.Getenv(key))
	}
	if _, ok := missing[key]; ok {
		t.Fatal("missing session wrote the Starlark global")
	}

	if err := h(context.Background(), []string{"set", "ONLYONE"}); err == nil {
		t.Fatal("set usage was accepted")
	}
}
