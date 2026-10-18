package security

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

// Login names and client versions are attacker-controlled and pass through
// RedactSensitiveText on the way into the chain. The encoding must leave
// redaction nothing to match, so no later field can be swallowed.
func TestSSHAuditValuesSurviveRedaction(t *testing.T) {
	for _, attacker := range []string{`x token="`, `SSH-2.0-x token="`, `a password='`, `secret=1 user=root`} {
		event := "SSH_LOGIN_FAIL addr=192.0.2.1:22 user=" + sys.EncodeAuditValue(attacker) + " attempts=3 keys=SHA256:k"
		got := RedactSensitiveText(event)
		if got != event {
			t.Errorf("redaction changed an encoded record:\n in  %q\n out %q", event, got)
		}
		if !strings.HasSuffix(got, " attempts=3 keys=SHA256:k") {
			t.Errorf("later fields lost: %q", got)
		}
	}
}
