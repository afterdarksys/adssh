# Certificate principals land on the session and are evaluated as input.groups.
# BuildPolicyContext copies session.Principals into input.groups. There is no
# separate input.principals field in the decision document.
# SSH user certificates put ValidPrincipals on the session at login.
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "certificate principal is not in the break-glass set"

breakglass_principals := {"breakglass", "ops"}

allow {
    some group in input.groups
    group in breakglass_principals
}

deny_reason = "" {
    some group in input.groups
    group in breakglass_principals
}
