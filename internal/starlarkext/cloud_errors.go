package starlarkext

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/api/googleapi"
)

// Threats: SDK and HTTP errors can carry more than the operator needs. A
// *url.Error prints the full request URL, which for a Teams webhook is the
// secret itself; a *googleapi.Error carries the raw response body and headers.
// cloudError keeps the operation name, the HTTP status, and the server's short
// message, drops request URLs, bodies, and headers, strips control characters,
// and caps the length. It does not hide what the provider's own message says
// (a resource name the caller passed in can come back in it).

// cloudCallTimeout bounds every cloud API call made by the cloud-gap builtins.
const cloudCallTimeout = 30 * time.Second

const cloudErrorMax = 300

func cloudError(op string, err error) error {
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		msg := gerr.Message
		if msg == "" {
			msg = http.StatusText(gerr.Code)
		}
		return fmt.Errorf("%s: HTTP %d: %s", op, gerr.Code, cleanErrorText(msg))
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Errorf("%s: request failed: %s", op, cleanErrorText(uerr.Err.Error()))
	}
	return fmt.Errorf("%s: %s", op, cleanErrorText(err.Error()))
}

// cleanErrorText removes control characters and caps the length.
func cleanErrorText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > cloudErrorMax {
		s = s[:cloudErrorMax] + "..."
	}
	return s
}

// validResourceSegment reports whether s can be placed in one segment of a
// cloud resource path (projects/<s>/...). It refuses separators, query and
// fragment characters, escapes, whitespace, and dot segments so a caller
// cannot point the request at a different resource than the one the policy
// gate saw.
func validResourceSegment(s string) bool {
	if s == "" || len(s) > 255 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("/?#%\\", r) {
			return false
		}
	}
	return true
}
