# For a per-user adssh-userland daemon. OS permissions still bound file access.
# Customize this policy before use; this example permits all arguments to the
# five bundled inspection commands. It is not path confinement.
package adssh.authz

default allow := false
allow if {
    input.command in {"cat", "find", "grep", "head", "ls"}
}
