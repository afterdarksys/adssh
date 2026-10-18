//go:build ee

package main

// The grid virtual binaries (internal/grid) are part of the enterprise layer
// (ee/LICENSE); they self-register from init.
import _ "github.com/afterdarksys/adssh/internal/grid"
