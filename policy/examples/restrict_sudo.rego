# Example: Deny sudo for all users.
# Copy to ~/.adssh/policy.rego to activate.
package adssh.authz

default allow = true
default deny_reason = ""

allow = false {
    input.command == "sudo"
}

deny_reason = "sudo is not allowed by policy" {
    input.command == "sudo"
}
