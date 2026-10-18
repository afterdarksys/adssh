# Regulated ops policy: deny by default, allow routine read-only tools, and
# require explicit break-glass elevation for destructive production actions.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "regulated ops policy denied this command"

read_only := {"ls", "cat", "pwd", "env", "jq", "yq", "http", "why", "??", "audit", "evidence", "mirror"}
ops_groups := {"ops", "sre", "security"}

allow {
    input.command in read_only
    some group in input.groups
    group in ops_groups
}

allow {
    input.command == "elevate"
    some group in input.groups
    group in ops_groups
}

allow {
    input.command in {"kubectl", "terraform", "aws", "gateway", "lease"}
    input.elevation.role == "prod-admin"
    input.elevation.reason != ""
}

deny_reason = "prod-admin break-glass elevation is required" {
    input.command in {"kubectl", "terraform", "aws", "gateway", "lease"}
    not input.elevation.role == "prod-admin"
}
