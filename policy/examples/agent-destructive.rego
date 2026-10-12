# Focused example of the destructive-agent rule already in
# policy/bundles/ai-agent.rego. This file is an example, not a new control.
# input.agent is set for MCP calls: id, kind, risk, dry_run.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "agent action denied"

allow {
    input.agent.kind == "mcp"
    input.agent.risk != "destructive"
}

allow {
    input.agent.kind == "mcp"
    input.agent.risk == "destructive"
    input.agent.dry_run
}

deny_reason = "destructive agent actions require dry_run=true" {
    input.agent.kind == "mcp"
    input.agent.risk == "destructive"
    not input.agent.dry_run
}
