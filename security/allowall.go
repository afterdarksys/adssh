package security

import "errors"

// RefuseAllowAll rejects a policy that allows every command, including the
// case where no policy is loaded. The daily path sets ADSSH_REFUSE_ALLOW_ALL.
// The switch stays off unless the caller asks, so a break-glass child whose
// policy is default allow = true still starts.
//
// Threats: one fixed canary, not a sample of real commands. A nil engine,
// or AuthorizeCommand allowing adssh-allowall-canary, returns the allow-all
// error and the caller must not start the session. A deny or an audit
// failure returns nil. It does not rewrite the policy file.
func (e *Engine) RefuseAllowAll() error {
	if e == nil {
		return errors.New("adssh: policy allows every command (allow-all)")
	}
	if err := e.AuthorizeCommand([]string{"adssh-allowall-canary"}, ""); err != nil {
		return nil
	}
	return errors.New("adssh: policy allows every command (allow-all)")
}
