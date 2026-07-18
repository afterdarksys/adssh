# A small, portable runbook demonstrating typed parameters and argv-only steps.
#
# Try:
#   ADSSH_RUNBOOK_DIR=examples/runbooks runbook show diagnose
#   ADSSH_RUNBOOK_DIR=examples/runbooks runbook run diagnose --param path=.
#   ADSSH_RUNBOOK_DIR=examples/runbooks runbook run diagnose --param path=. --dry-run

description = "Collect basic host and filesystem diagnostics"

params = {
    "path": {
        "type": "string",
        "required": False,
        "default": ".",
        "description": "Filesystem path to inspect",
    },
}

steps = [
    {
        "name": "kernel",
        "command": ["uname", "-a"],
    },
    {
        "name": "directory",
        "command": ["ls", "-la", "${path}"],
    },
    {
        "name": "filesystem",
        "command": ["df", "-h", "${path}"],
    },
]
