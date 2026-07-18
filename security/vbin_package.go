package security

import (
	"context"
	"github.com/afterdarksys/adssh/sysmgmt"
)

// package — cross-platform package manager

type packageBinary struct{}

func (packageBinary) Name() string { return "package" }
func (packageBinary) Description() string {
	return "Package manager — install, remove, update, or list packages"
}
func (packageBinary) Usage() string { return "package <install|remove|update|list> [name]" }

func (packageBinary) Run(ctx context.Context, args []string) error {
	return sysmgmt.RunPackage(ctx, args)
}

func init() { Register(packageBinary{}) }
