# Bound a secret lease before the secret is fetched.
# Fields match security.LeaseClaim: source_type, source_name, destination,
# ttl_seconds, command, delivery. source_type is the prefix of --from
# (env, file, vault, aws-sm, azure-kv, gcp-sm). delivery is env, stdin, or fd.
# destination is the --as name for env, the literal stdin, or fd:3.
# The lease binary itself caps TTL at 24h; this policy tightens that to
# 5 minutes, vault only, and destination TOKEN.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "lease is missing or outside bounds"

allow {
    input.command == "lease"
    input.lease.source_type == "vault"
    input.lease.ttl_seconds > 0
    input.lease.ttl_seconds <= 300
    input.lease.destination == "TOKEN"
    input.lease.command[0] == "deploy"
}

deny_reason = "lease ttl exceeds 300 seconds" {
    input.lease.ttl_seconds > 300
}

deny_reason = "lease source must be vault" {
    object.get(input, "lease", {}) != {}
    input.lease.source_type != "vault"
}
