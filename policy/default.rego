# Default adssh policy — allow all commands.
# File permissions should be 0644 owned by the user (see T-01-01).
# Copy this file to ~/.adssh/policy.rego or set ADSSH_POLICY to customize.
#
# The engine reads these fields from data.adssh.authz:
#   allow                 bool, required. Only allow == true permits. A missing
#                         or non-bool allow denies.
#   deny_reason           string, optional. Shown to the operator and audited.
#   required_role         string, optional. `??` suggests `elevate request <role>`.
#   rule                  string, optional. Names the rule that decided.
#   required_entitlement  string, optional. The entitlement that would allow it.
# A rule or required_entitlement that is not a string denies the command.
# policy/examples/explained.rego sets all of them.
package adssh.authz

default allow = true
default deny_reason = ""
