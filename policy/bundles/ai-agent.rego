# AI-agent policy: agents can inspect and explain, but destructive operations
# require human-visible elevation claims.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "AI agent policy denied this operation"

safe_commands := {"ls", "cat", "pwd", "jq", "yq", "http", "why", "??", "audit", "evidence"}
mcp_tools := {"eval_starlark", "run_shell", "list_sessions", "cloud_query", "audit_log"}

allow {
    input.command in safe_commands
}

allow {
    input.command in mcp_tools
    not destructive_arg
}

allow {
    input.elevation.role == "human-approved-agent"
    input.elevation.reason != ""
}

destructive_arg {
    some arg in input.args
    lower(arg) in {"delete", "destroy", "terminate", "rm", "--force", "-f"}
}

deny_reason = "human-approved-agent elevation is required for destructive agent actions" {
    destructive_arg
}
