package starlarkext

import (
	"os"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"

	"go.starlark.net/starlark"
)

func TestSysSetenvWritesSessionOverlay(t *testing.T) {
	const key = "ADSSH_EXEC_SET_PROBE"
	const value = "session-value"
	prev, had := os.LookupEnv(key)
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
	_ = os.Unsetenv(key)

	id := "sess-starlark-env-9f3a"
	if err := sys.RegisterSession(&sys.Session{ID: id, User: "t"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })

	globals := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: globals, SessionID: id})
	if _, err := callSys(t, globals, "setenv", starlark.String(key), starlark.String(value)); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	if got := os.Getenv(key); got != "" {
		t.Fatalf("process env %s = %q, want empty", key, got)
	}
	s := sys.GetSession(id)
	if s == nil {
		t.Fatal("session disappeared")
	}
	got, ok := s.LookupEnv(key)
	if !ok || got != value {
		t.Fatalf("overlay %s = %q, %v", key, got, ok)
	}
	read, err := callSys(t, globals, "getenv", starlark.String(key))
	if err != nil {
		t.Fatalf("getenv: %v", err)
	}
	if read != starlark.String(value) {
		t.Fatalf("getenv = %v, want %q", read, value)
	}

	missingID := "sess-starlark-missing"
	secret := "must-not-leak"
	t.Setenv(key, "sentinel")
	missing := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: missing, SessionID: missingID})
	_, err = callSys(t, missing, "setenv", starlark.String(key), starlark.String(secret))
	if err == nil {
		t.Fatal("unregistered session setenv succeeded")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("setenv error = %v, want not registered", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error %q includes the value", err)
	}
	if os.Getenv(key) != "sentinel" {
		t.Fatalf("process env changed to %q", os.Getenv(key))
	}
	_, err = callSys(t, missing, "getenv", starlark.String(key))
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("getenv error = %v, want not registered", err)
	}
}

func callSys(t *testing.T, globals starlark.StringDict, name string, args ...starlark.Value) (starlark.Value, error) {
	t.Helper()
	sysVal, ok := globals["sys"].(*starlark.Dict)
	if !ok {
		t.Fatalf("sys is %T", globals["sys"])
	}
	b, found, err := sysVal.Get(starlark.String(name))
	if err != nil || !found {
		t.Fatalf("sys.%s: found=%v err=%v", name, found, err)
	}
	fn, ok := b.(starlark.Callable)
	if !ok {
		t.Fatalf("sys.%s is %T", name, b)
	}
	return starlark.Call(&starlark.Thread{Name: "env-session"}, fn, starlark.Tuple(args), nil)
}
