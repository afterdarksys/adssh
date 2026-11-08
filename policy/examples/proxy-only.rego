# Use with the enterprise build, ADSSH_PROXY_CONFIG, --restricted, and a
# configured audit chain. The administrator-owned config is an additional
# mandatory gate on all destinations. No ordinary shell/network commands.
package adssh.authz

default allow = false
default deny_reason = "only approved proxy destinations are available"

allow {
    input.command == "proxy"
}

# Native ssh -L/-W/-J and the proxy's structured destination decision.
allow {
    input.command == "gateway"
    input.gateway.action == "direct-tcpip"
}

allow {
    input.command == "gateway"
    input.gateway.action == "proxy"
}
