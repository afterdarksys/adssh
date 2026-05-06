# Default adssh policy — allow all commands.
# File permissions should be 0644 owned by the user (see T-01-01).
# Copy this file to ~/.adssh/policy.rego or set ADSSH_POLICY to customize.
package adssh.authz

default allow = true
default deny_reason = ""
