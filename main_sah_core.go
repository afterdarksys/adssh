//go:build !ee

package main

import (
	"fmt"
	"os"

	"github.com/afterdarksys/adssh/security"
)

const sahEnterpriseOnly = "adssh: sah/1 is part of the adssh enterprise build; this is the core build (see docs/LICENSING.md)"

// sahDisabled refuses sah/1 in the core build. It reads no frame.
func sahDisabled() int {
	fmt.Fprintln(os.Stderr, sahEnterpriseOnly)
	return 2
}

// runSAH refuses sah/1 in the core build. It reads no frame and runs nothing.
func runSAH(*security.Engine, string) int { return sahDisabled() }
