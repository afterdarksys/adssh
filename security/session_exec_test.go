package security

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"

	"mvdan.cc/sh/v3/expand"
)

type scriptedEnv struct {
	get   map[string]expand.Variable
	order []string
	vars  map[string]expand.Variable
}

func (e scriptedEnv) Get(name string) expand.Variable {
	if e.get != nil {
		return e.get[name]
	}
	return expand.Variable{}
}

func (e scriptedEnv) Each(fn func(name string, vr expand.Variable) bool) {
	for _, name := range e.order {
		if !fn(name, e.vars[name]) {
			return
		}
	}
}

type layeredEnv struct {
	parent expand.Environ
	extra  []struct {
		name string
		vr   expand.Variable
	}
}

func (e layeredEnv) Get(name string) expand.Variable { return e.parent.Get(name) }

func (e layeredEnv) Each(fn func(name string, vr expand.Variable) bool) {
	stopped := false
	e.parent.Each(func(name string, vr expand.Variable) bool {
		if !fn(name, vr) {
			stopped = true
			return false
		}
		return true
	})
	if stopped {
		return
	}
	for _, item := range e.extra {
		if !fn(item.name, item.vr) {
			return
		}
	}
}

func envValue(list []string, name string) (string, int) {
	n := 0
	val := ""
	prefix := name + "="
	for _, kv := range list {
		if strings.HasPrefix(kv, prefix) {
			n++
			val = strings.TrimPrefix(kv, prefix)
		}
	}
	return val, n
}

func TestChildEnvironLastWinsAndUnset(t *testing.T) {
	key := "ADSSH_CHILD_LAST"
	t.Setenv(key, "from-process")

	got := ChildEnviron(scriptedEnv{
		order: []string{key, key},
		vars: map[string]expand.Variable{
			key: {Set: true, Exported: true, Kind: expand.String, Str: "second"},
		},
	})
	if val, n := envValue(got, key); n != 1 || val != "second" {
		t.Fatalf("repeated export %q x%d, want one %q", val, n, "second")
	}
	// The scripted Each emits the same variable twice; the second walk still
	// appends, and LastEnvWins keeps one value. Build an env that appends
	// two different exports by using layered order entries with a custom Each.
	seq := &seqEnv{items: []seqItem{
		{key, expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: "first"}},
		{key, expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: "second"}},
	}}
	got = ChildEnviron(seq)
	val, n := envValue(got, key)
	if n != 1 || val != "second" {
		t.Fatalf("last-wins %q x%d, list has %d entries", val, n, len(got))
	}

	dropped := ChildEnviron(&seqEnv{items: []seqItem{
		{key, expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: "shell"}},
		{key, expand.Variable{}},
	}})
	if _, n := envValue(dropped, key); n != 0 {
		t.Fatalf("export then unset kept %q", dropped)
	}

	stays := ChildEnviron(&seqEnv{items: []seqItem{
		{key, expand.Variable{}},
		{key, expand.Variable{Set: true, Exported: false, Kind: expand.String, Str: "local"}},
	}})
	if _, n := envValue(stays, key); n != 0 {
		t.Fatalf("unset then non-exported set kept %q", stays)
	}
}

type seqItem struct {
	name string
	vr   expand.Variable
}

type seqEnv struct {
	items []seqItem
}

func (e *seqEnv) Get(name string) expand.Variable { return expand.Variable{} }

func (e *seqEnv) Each(fn func(name string, vr expand.Variable) bool) {
	for _, item := range e.items {
		if !fn(item.name, item.vr) {
			return
		}
	}
}

func TestChildEnvironOverlayAndShell(t *testing.T) {
	id := "sess-child-overlay-9f3a"
	key := "ADSSH_CHILD_OVERLAY"
	session := &sys.Session{ID: id, User: "t"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	if err := session.SetEnv(key, "overlay"); err != nil {
		t.Fatal(err)
	}
	t.Setenv(key, "from-process")

	base := NewSessionEnviron(id)
	got := ChildEnviron(base)
	val, n := envValue(got, key)
	if n != 1 || val != "overlay" {
		t.Fatalf("overlay vs process = %q x%d", val, n)
	}
	if _, n := envValue(got, "SESSION_ID"); n != 0 || containsEnv(got, "SESSION_ID="+id) {
		t.Fatalf("child env contains SESSION_ID=%s", id)
	}

	layered := layeredEnv{
		parent: base,
		extra: []struct {
			name string
			vr   expand.Variable
		}{{key, expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: "from-shell"}}},
	}
	got = ChildEnviron(layered)
	val, n = envValue(got, key)
	if n != 1 || val != "from-shell" {
		t.Fatalf("shell vs overlay = %q x%d", val, n)
	}
}

func TestNewSessionEnviron(t *testing.T) {
	id := "sess-new-env-9f3a"
	session := &sys.Session{ID: id, User: "t"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	if err := session.SetEnv("ADSSH_VAULT_PROBE", "vault://abc"); err != nil {
		t.Fatal(err)
	}
	env := NewSessionEnviron(id)
	sid := env.Get("SESSION_ID")
	if !sid.IsSet() || sid.Exported || sid.Kind != expand.String || sid.Str != id {
		t.Fatalf("SESSION_ID = %+v", sid)
	}
	vault := env.Get("ADSSH_VAULT_PROBE")
	if !vault.Exported || vault.Str != "RESOLVED_SECRET_abc" {
		t.Fatalf("vault get = %+v", vault)
	}
	raw := ""
	env.Each(func(name string, vr expand.Variable) bool {
		if name == "SESSION_ID" && vr.Str == id {
			t.Fatalf("Each emitted SESSION_ID=%s", id)
		}
		if name == "ADSSH_VAULT_PROBE" {
			raw = vr.Str
		}
		return true
	})
	if raw != "vault://abc" {
		t.Fatalf("Each vault = %q", raw)
	}
}

func containsEnv(list []string, want string) bool {
	for _, kv := range list {
		if kv == want {
			return true
		}
	}
	return false
}
