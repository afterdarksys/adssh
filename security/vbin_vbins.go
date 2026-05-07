package security

import (
	"context"
	"fmt"

	"mvdan.cc/sh/v3/interp"
)

// vbins — virtual binary discovery

type vbinsBinary struct{}

func (vbinsBinary) Name() string        { return "vbins" }
func (vbinsBinary) Description() string { return "List all available virtual binaries" }
func (vbinsBinary) Usage() string       { return "vbins" }

func (vbinsBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintln(hc.Stdout, "Virtual Binaries:")
	for _, vb := range ListVBins() {
		fmt.Fprintf(hc.Stdout, "  %-14s  %s\n", vb.Name(), vb.Description())
	}
	fmt.Fprintln(hc.Stdout, "\nRun '<binary> --help' for usage details.")
	return nil
}

func init() { Register(vbinsBinary{}) }
