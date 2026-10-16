# Example only. A decision that names its rule and what would unblock it.
#
# The engine reads five fields from data.adssh.authz:
#   allow                 bool, required. Only allow == true permits.
#   deny_reason           string, optional. Shown to the operator and audited.
#   required_role         string, optional. `??` suggests `elevate request <role>`.
#   rule                  string, optional. Names the rule that decided.
#   required_entitlement  string, optional. The entitlement that would allow it.
# A rule or required_entitlement that is not a string denies the command.
# `why`, `??`, `whoami --caps` and the [POLICY] audit line show all of them.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = ""
default rule = "default_deny"
default required_role = ""
default required_entitlement = ""

read_only := {"ls", "cat", "uptime", "whoami", "why", "??"}

kubectl_write {
    input.command == "kubectl"
    input.args[0] in {"apply", "delete", "scale", "rollout"}
}

allow {
    input.command in read_only
}

allow {
    kubectl_write
    "k8s-ops" in input.groups
}

rule = "read_only" {
    input.command in read_only
}

rule = "k8s_write" {
    kubectl_write
}

deny_reason = "kubectl writes need the k8s-ops role" {
    kubectl_write
    not "k8s-ops" in input.groups
}

required_role = "k8s-ops" {
    kubectl_write
    not "k8s-ops" in input.groups
}

required_entitlement = "k8s-write" {
    kubectl_write
    not "k8s-ops" in input.groups
}
