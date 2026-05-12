#compdef adssh
# Zsh completion for adssh
# Install: copy to /usr/local/share/zsh/site-functions/_adssh
#          (the filename must start with an underscore)

_adssh() {
    local -a opts

    _arguments -s -S \
        '(- 1 *)'{-h,--help}'[show help and exit]' \
        '--init[create starter config in ~/.adssh/ and exit]' \
        {-l,--login}'[run as a login shell (load profile)]' \
        {-r,--restricted}'[enable restricted (sandboxed) mode]' \
        '-c[evaluate expression and exit]:expression: ' \
        '--serve[start SSH server on address]:address (e.g. \:2222): ' \
        '--entitlements[load RBAC entitlements YAML]:entitlements file:_files' \
        '--policy[load OPA/Rego policy file]:policy file:_files' \
        '1:script file:_files -g "*.star"'
}

compdef _adssh adssh
