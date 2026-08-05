# Gateway-only policy: operators may use adssh as a controlled SSH/TCP gateway
# only for approved targets, with break-glass required for production.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "gateway target is not allowed"

allowed_dev_hosts := {"dev.internal", "staging.internal"}
prod_hosts := {"bastion.internal", "prod-db.internal"}

allow {
    input.command in {"why", "??", "mirror", "audit", "evidence", "elevate", "gateway"}
}

allow {
    input.command == "gateway"
    input.gateway.target_host in allowed_dev_hosts
    input.gateway.target_port == "22"
}

allow {
    input.command == "gateway"
    input.gateway.target_host in prod_hosts
    input.gateway.target_port == "22"
    input.elevation.role == "prod-admin"
    input.elevation.reason != ""
}

deny_reason = msg {
    input.command == "gateway"
    msg := sprintf("gateway to %s:%s requires an approved target or prod-admin elevation", [input.gateway.target_host, input.gateway.target_port])
}
