package security

import (
	"context"
	"strings"
	"testing"
)

type testVBin struct {
	name string
}

func (v testVBin) Name() string        { return v.name }
func (v testVBin) Description() string { return "test vbin" }
func (v testVBin) Usage() string       { return v.name }
func (v testVBin) Run(context.Context, []string) error {
	return nil
}

func TestRegisterRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", " ", "bad name", "bad/name", "bad\tname"} {
		t.Run(name, func(t *testing.T) {
			assertRegisterPanic(t, testVBin{name: name}, "virtual binary")
		})
	}
}

func TestRegisterRejectsDuplicateNames(t *testing.T) {
	assertRegisterPanic(t, testVBin{name: "jq"}, "duplicate virtual binary")
}

func assertRegisterPanic(t *testing.T, vb VirtualBinary, want string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected Register(%q) to panic", vb.Name())
		}
		if !strings.Contains(r.(string), want) {
			t.Fatalf("panic %q does not contain %q", r, want)
		}
	}()
	Register(vb)
}
