//go:build !ee

package security

import (
	"context"
	"errors"
)

// adminCoreBinary keeps the name "admin" in the core build so `admin serve`
// fails with an explanation instead of falling through to whatever "admin"
// executable is on PATH. The admin API is part of the enterprise layer
// (vbin_admin_ee.go, ee/LICENSE).
type adminCoreBinary struct{}

func (adminCoreBinary) Name() string        { return "admin" }
func (adminCoreBinary) Description() string { return "Local admin API (enterprise build only)" }
func (adminCoreBinary) Usage() string {
	return "admin: available in the enterprise build (go build -tags ee)"
}

var errAdminEnterpriseOnly = errors.New("admin: the admin API is part of the adssh enterprise layer; this is the core build (see docs/LICENSING.md)")

func (adminCoreBinary) Run(context.Context, []string) error { return errAdminEnterpriseOnly }

func init() { Register(adminCoreBinary{}) }
