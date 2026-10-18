# Capability-group policy bundle.
#
# Gates the enhanced-Starlark surface by CAPABILITY GROUP instead of by
# individual builtin name. adssh classifies every governed Starlark builtin into
# capability groups (cloud, fileops, proc, net, tcp, databases, regex, strings,
# security, secrets, ...) and passes them as input.capabilities. Shell-layer
# commands (external binaries, mvdan builtins) carry no capabilities and are
# gated by name as usual.
#
# This bundle: allow shell commands and low-risk capability groups, deny the
# high-blast-radius groups unless a human-approved elevation claim is present,
# and always deny anything tagged "unclassified" (fail-closed hook for a builtin
# nobody has classified yet).
package adssh.authz

import future.keywords.in
import future.keywords.every

default allow = false
default deny_reason = "capability policy denied this operation"

# Groups any session may use freely.
allowed_capabilities := {"strings", "regex", "data", "crypto", "template", "stdio"}

# Groups that require a human-approved elevation claim.
elevated_capabilities := {"cloud", "proc", "fileops", "net", "tcp", "databases", "secrets", "security", "containers", "k8s", "vcs", "notify"}

# Shell-layer commands (no capabilities) — gated by name elsewhere; allow here.
allow {
    count(input.capabilities) == 0
    not startswith(input.command, "starlark.")
}

# A governed builtin whose every capability is in the always-allowed set.
allow {
    count(input.capabilities) > 0
    every cap in input.capabilities {
        cap in allowed_capabilities
    }
}

# Elevated groups are permitted only with a non-empty human-approved elevation,
# and only when every capability the builtin touches is recognised (allowed or
# elevated) — an unclassified tag still denies.
allow {
    some cap in input.capabilities
    cap in elevated_capabilities
    input.elevation.role == "capability-approved"
    input.elevation.reason != ""
    every c in input.capabilities {
        c in (allowed_capabilities | elevated_capabilities)
    }
}

# Fail closed: an unclassified starlark builtin is never allowed.
deny_reason = "unclassified capability — refusing a builtin no policy has classified" {
    "unclassified" in input.capabilities
}

deny_reason = sprintf("capability group requires 'capability-approved' elevation: %v", [input.capabilities]) {
    some cap in input.capabilities
    cap in elevated_capabilities
    not input.elevation.role == "capability-approved"
}
