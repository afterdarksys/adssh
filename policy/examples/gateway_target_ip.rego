# Example: SSH direct-tcpip and `gateway` forwarding by name, by resolved
# address, or both. Copy to ~/.adssh/policy.rego to activate.
#
# For an SSH direct-tcpip channel and for `gateway start`, adssh resolves the
# requested name once and makes one decision with both fields:
#   input.gateway.target_host  the name the client asked for ("db.internal")
#   input.gateway.target_ip    the address it resolved to ("10.20.0.7")
#   input.gateway.target_port  the port, as a string ("5432")
# adssh then dials target_ip, so a DNS answer that changes after the
# decision is never used. When the target is already an address,
# target_host and target_ip are the same address. target_ip is "" only for
# a caller that does not resolve.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "gateway target is not allowed"

# Names operators may reach, and the port for each.
allowed_targets := {
    "db.internal": "5432",
    "bastion.internal": "22",
}

# Addresses no name may resolve to: instance metadata, loopback, and a
# subnet that must stay unreachable from the gateway.
blocked_address(ip) {
    ip in {"169.254.169.254", "fd00:ec2::254"}
}

blocked_address(ip) {
    net.cidr_contains("127.0.0.0/8", ip)
}

blocked_address(ip) {
    net.cidr_contains("10.99.0.0/16", ip)
}

# Allow by name. A policy that stops here (no target_ip rule) keeps working
# unchanged: the name check alone decides.
name_allowed {
    allowed_targets[input.gateway.target_host] == input.gateway.target_port
}

# Constrain the address as well: the resolved address must not be blocked.
address_ok {
    input.gateway.target_ip == ""
}

address_ok {
    input.gateway.target_ip != ""
    not blocked_address(input.gateway.target_ip)
}

allow {
    input.command == "gateway"
    name_allowed
    address_ok
}

# Or allow by address alone, e.g. a database subnet, whatever name was used.
allow {
    input.command == "gateway"
    input.gateway.target_ip != ""
    net.cidr_contains("10.20.0.0/24", input.gateway.target_ip)
    input.gateway.target_port == "5432"
}

deny_reason = msg {
    input.command == "gateway"
    input.gateway.target_ip != ""
    blocked_address(input.gateway.target_ip)
    msg := sprintf("gateway target %s resolved to a blocked address %s", [input.gateway.target_host, input.gateway.target_ip])
}
