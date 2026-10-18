//go:build !ee

package security

import (
	"errors"
	"time"
)

var errMirrorShareEnterpriseOnly = errors.New("mirror: share and unshare are part of the adssh enterprise build; this is the core build (see docs/LICENSING.md)")

func (e *Engine) shareMirror(string, string, time.Duration, bool) error {
	return errMirrorShareEnterpriseOnly
}

func (e *Engine) unshareMirror(string, string) (int, error) {
	return 0, errMirrorShareEnterpriseOnly
}
