//go:build !ee

package security

import (
	"context"
	"errors"
	"testing"
)

// In the core build `admin` explains itself; it must never fall through to a
// PATH executable named admin.
func TestCoreAdminIsAnEnterpriseStub(t *testing.T) {
	vb, ok := Lookup("admin")
	if !ok {
		t.Fatal("core build has no admin entry; `admin` would run a PATH binary")
	}
	if err := vb.Run(context.Background(), []string{"admin", "serve"}); !errors.Is(err, errAdminEnterpriseOnly) {
		t.Fatalf("admin serve in core: %v", err)
	}
}
