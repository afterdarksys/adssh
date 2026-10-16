# Example only. Gates `mirror share`, which grants another user time-boxed
# access to this session. The gate sees command "mirror" and the argv in
# input.args, e.g. ["share", "--with", "bob", "--for", "10m", "--console"].
# The engine itself caps a grant at 24h; this policy caps it at 30m and lets
# only oncall-lead grant console (input) access.
package adssh.authz

import future.keywords.in

default allow = false
default rule = "default_deny"
default deny_reason = ""
default required_role = ""

# Everything that is not mirror is out of scope for this example.
allow {
    input.command != "mirror"
}

rule = "not_mirror" {
    input.command != "mirror"
}

allow {
    input.command == "mirror"
    input.args[0] in {"list", "view", "console", "unshare"}
}

rule = "mirror_read" {
    input.command == "mirror"
    input.args[0] in {"list", "view", "console", "unshare"}
}

share {
    input.command == "mirror"
    input.args[0] == "share"
}

share_for_ns := time.parse_duration_ns(input.args[i + 1]) {
    share
    some i
    input.args[i] == "--for"
}

share_console {
    share
    "--console" in input.args
}

share_short {
    share_for_ns <= time.parse_duration_ns("30m")
}

console_ok {
    not share_console
}

console_ok {
    "oncall-lead" in input.groups
}

allow {
    share_short
    console_ok
}

rule = "mirror_share" {
    share
}

deny_reason = "mirror share is limited to 30m" {
    share
    not share_short
}

deny_reason = "console sharing needs the oncall-lead role" {
    share_short
    not console_ok
}

required_role = "oncall-lead" {
    share_short
    not console_ok
}
