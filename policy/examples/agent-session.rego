# Example only. Tool arguments named agent_id or session_id are command
# arguments. They do not replace input.agent.id or input.agent.session_id.
# Those two fields are bound once when the MCP process starts.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "agent session denied"

allow {
    input.agent.kind == "mcp"
    input.agent.id == "bound-agent"
    input.agent.session_id == "sess-1"
    input.agent.session_id != ""
}
