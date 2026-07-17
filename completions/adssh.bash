# Bash completion for adssh
# Install: copy to /etc/bash_completion.d/adssh
#          or source this file from ~/.bashrc

_adssh() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        # Fallback if bash-completion library is not available
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local flags="-h --help -l --login -r --restricted -c --serve --entitlements --policy --init --doctor"

    case "${prev}" in
        --policy|--entitlements)
            # Complete with file paths
            _filedir
            return
            ;;
        --serve)
            # Expects a port/address like :2222 — no useful completion
            return
            ;;
        -c)
            # Expects a shell/Starlark expression — no useful completion
            return
            ;;
    esac

    case "${cur}" in
        -*)
            COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
            return
            ;;
        *)
            # Complete with .star script files or fall back to all files
            COMPREPLY=( $(compgen -f -X '!*.star' -- "${cur}") \
                        $(compgen -f -- "${cur}") )
            # Remove duplicates and let readline sort them
            local seen=()
            local unique=()
            for item in "${COMPREPLY[@]}"; do
                local found=0
                for s in "${seen[@]}"; do [ "$s" = "$item" ] && found=1 && break; done
                if [ $found -eq 0 ]; then
                    seen+=("$item")
                    unique+=("$item")
                fi
            done
            COMPREPLY=("${unique[@]}")
            return
            ;;
    esac
}

complete -F _adssh adssh
