package security

import (
	"context"
	"github.com/afterdarksys/adssh/sysmgmt"
)

// proc — /proc filesystem reader/writer (Linux only)

type procBinary struct{}

func (procBinary) Name() string { return "proc" }
func (procBinary) Description() string {
	return "Proc filesystem — read or write /proc entries (Linux only)"
}
func (procBinary) Usage() string { return "proc <get|set> <path> [value]" }

func (procBinary) Run(ctx context.Context, args []string) error {
	return sysmgmt.RunProc(ctx, args)
}

func init() { Register(procBinary{}) }
