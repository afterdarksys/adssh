package security

import (
	"context"
	"errors"

	"github.com/afterdarksys/adssh/internal/sysmgmt"
)

// package — cross-platform package manager

type packageBinary struct{}

func (packageBinary) Name() string { return "package" }
func (packageBinary) Description() string {
	return "Package manager — install, remove, update, or list packages"
}
func (packageBinary) Usage() string { return "package <install|remove|update|list> [name]" }

func (packageBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if mutationBlocked(ctx) {
		return errors.New("package: refused")
	}
	return sysmgmt.RunPackage(ctx, args)
}

func init() { Register(packageBinary{}) }
