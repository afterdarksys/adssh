# Role-separated policy for operators using the governed admin API.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "admin API policy denied this operation"

read_only_admin := {"sessions", "gateways", "approvals", "explain"}

allow {
    input.command == "admin"
    input.args[0] in read_only_admin
    has_group("ops-readonly")
}

allow {
    input.command == "admin"
    input.args[0] == "evidence"
    has_group("security-auditor")
}

allow {
    input.command == "admin"
    input.args[0] == "serve"
    has_group("platform-admin")
}

deny_reason = "platform-admin role is required to start admin serve" {
    input.command == "admin"
    input.args[0] == "serve"
    not has_group("platform-admin")
}

has_group(group) {
    input.groups[_] == group
}
