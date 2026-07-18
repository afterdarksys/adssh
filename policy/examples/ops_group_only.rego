# Example: Only members of the "ops" group may execute commands.
# All other users are denied.
# Copy to ~/.adssh/policy.rego to activate.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "only members of the ops group may run commands"

allow {
    some group in input.groups
    group == "ops"
}

deny_reason = "" {
    some group in input.groups
    group == "ops"
}
