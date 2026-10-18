//go:build !ee

package security

import (
	"context"
	"fmt"
)

// enterpriseOnlyBinary keeps the name of an enterprise virtual binary in the
// core build, so the command fails with an explanation instead of falling
// through to whatever executable of that name is on PATH.
//
// Threats: without the stub, "4eyes approve <token>" or "lease ..." in a core
// build would exec a PATH binary of the same name with the caller's
// arguments, possibly secrets, after policy allowed the adssh command.
type enterpriseOnlyBinary struct {
	name        string
	description string
}

func (b enterpriseOnlyBinary) Name() string { return b.name }
func (b enterpriseOnlyBinary) Description() string {
	return b.description + " (enterprise build only)"
}
func (b enterpriseOnlyBinary) Usage() string {
	return b.name + ": available in the enterprise build (go build -tags ee)"
}
func (b enterpriseOnlyBinary) Run(context.Context, []string) error {
	return fmt.Errorf("%s: part of the adssh enterprise layer; this is the core build (see docs/LICENSING.md)", b.name)
}

// enterpriseOnlyBinaries are the virtual binaries that only the enterprise
// build implements.
var enterpriseOnlyBinaries = []enterpriseOnlyBinary{
	{"4eyes", "Four-eyes dual approval"},
	{"cm", "Change-management tickets"},
	{"evidence", "Evidence bundle export"},
	{"elevate", "Just-in-time and break-glass elevation"},
	{"grant", "Temporary role grants"},
	{"lease", "Secret leases"},
	{"identity", "OIDC import, device login and SSH CA"},
	{"gateway", "Governed TCP gateways"},
	{"grid", "sah-grid membership"},
	{"flight", "Grid flights"},
	{"agent", "Grid agents"},
	{"worktree", "Grid worktrees"},
	{"repo", "Grid repositories"},
}

func init() {
	for _, b := range enterpriseOnlyBinaries {
		Register(b)
	}
}
