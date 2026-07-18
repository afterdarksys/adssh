# Migration Guide: YAML Entitlements -> Rego Policy
#
# This file shows how to express YAML entitlement patterns as Rego rules.
# The YAML entitlements system used per-user and per-group allow/deny lists.
# In Rego, you have full programmatic control over authorization logic.
#
# YAML structure was:
#   users:
#     alice:
#       allow: [git, docker]
#       deny: [rm, shutdown]
#   groups:
#     devops:
#       allow: [kubectl, terraform]
#
# Equivalent Rego policy:

package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "command not in allowlist"

# Per-user allowlists
user_allow := {
    "alice": {"git", "docker"},
    "bob": {"git", "ls", "cat"},
}

# Per-user denylists (takes precedence over allow)
user_deny := {
    "alice": {"rm", "shutdown"},
}

# Per-group allowlists
group_allow := {
    "devops": {"kubectl", "terraform", "docker"},
    "ops": {"systemctl", "journalctl"},
}

# Allow if user has explicit permission
allow {
    commands := user_allow[input.user]
    input.command in commands
    not is_denied
}

# Allow if any of the user's groups grant permission
allow {
    some group in input.groups
    commands := group_allow[group]
    input.command in commands
    not is_denied
}

# Deny takes precedence
is_denied {
    commands := user_deny[input.user]
    input.command in commands
}

deny_reason = msg {
    is_denied
    msg := sprintf("command '%s' is explicitly denied for user '%s'", [input.command, input.user])
}
