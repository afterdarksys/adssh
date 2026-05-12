#!/bin/sh
# install.sh — Install adssh to /usr/local/bin and set up supporting files
# POSIX-compliant shell script (no bashisms)
set -e

BINARY_NAME="adssh"
INSTALL_DIR="/usr/local/bin"
INSTALL_PATH="${INSTALL_DIR}/${BINARY_NAME}"
SHELLS_FILE="/etc/shells"
DOWNLOAD_URL="https://github.com/example/adssh/releases/latest/download/adssh-$(uname -s)-$(uname -m)"

# ── Helpers ──────────────────────────────────────────────────────────────────

info()  { printf '\033[1;32m==> \033[0m%s\n' "$*"; }
warn()  { printf '\033[1;33mWARN: \033[0m%s\n' "$*" >&2; }
die()   { printf '\033[1;31mERROR: \033[0m%s\n' "$*" >&2; exit 1; }

# ── Root check ───────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    warn "Not running as root. Installing to ${INSTALL_DIR} may fail."
    warn "Re-run with: sudo sh install.sh"
fi

# ── Locate or download binary ─────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -x "${SCRIPT_DIR}/adssh" ]; then
    info "Using locally built binary: ${SCRIPT_DIR}/adssh"
    BINARY_SRC="${SCRIPT_DIR}/adssh"
else
    info "Local binary not found. Downloading from ${DOWNLOAD_URL} ..."
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TMP_DIR}"' EXIT

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/adssh" || die "Download failed."
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${DOWNLOAD_URL}" -O "${TMP_DIR}/adssh" || die "Download failed."
    else
        die "Neither curl nor wget found. Please install one, or build adssh locally."
    fi

    chmod +x "${TMP_DIR}/adssh"
    BINARY_SRC="${TMP_DIR}/adssh"
fi

# ── Install binary ────────────────────────────────────────────────────────────

info "Installing ${BINARY_NAME} to ${INSTALL_PATH} ..."
mkdir -p "${INSTALL_DIR}"
cp "${BINARY_SRC}" "${INSTALL_PATH}"
chmod 755 "${INSTALL_PATH}"

# ── Register in /etc/shells ───────────────────────────────────────────────────

if [ -w "${SHELLS_FILE}" ] || [ "$(id -u)" -eq 0 ]; then
    if grep -qxF "${INSTALL_PATH}" "${SHELLS_FILE}" 2>/dev/null; then
        info "${INSTALL_PATH} already in ${SHELLS_FILE}"
    else
        info "Adding ${INSTALL_PATH} to ${SHELLS_FILE} ..."
        printf '%s\n' "${INSTALL_PATH}" >> "${SHELLS_FILE}"
    fi
else
    warn "Cannot write to ${SHELLS_FILE}. Run the following manually as root:"
    warn "  echo '${INSTALL_PATH}' >> ${SHELLS_FILE}"
fi

# ── XDG config directories ────────────────────────────────────────────────────

info "Creating XDG-compliant config directories ..."
mkdir -p "${HOME}/.config/adssh" \
         "${HOME}/.local/share/adssh" \
         "${HOME}/.cache/adssh"

# ── Bash completion ───────────────────────────────────────────────────────────

BASH_COMPLETION_DIR="/etc/bash_completion.d"
BASH_COMPLETION_SRC="${SCRIPT_DIR}/completions/adssh.bash"

if [ -f "${BASH_COMPLETION_SRC}" ]; then
    if [ -d "${BASH_COMPLETION_DIR}" ] && { [ -w "${BASH_COMPLETION_DIR}" ] || [ "$(id -u)" -eq 0 ]; }; then
        info "Installing bash completion to ${BASH_COMPLETION_DIR}/adssh ..."
        cp "${BASH_COMPLETION_SRC}" "${BASH_COMPLETION_DIR}/adssh"
    else
        warn "Cannot write to ${BASH_COMPLETION_DIR}. Copy manually:"
        warn "  sudo cp '${BASH_COMPLETION_SRC}' ${BASH_COMPLETION_DIR}/adssh"
    fi
else
    warn "Bash completion source not found: ${BASH_COMPLETION_SRC}"
fi

# ── Zsh completion ────────────────────────────────────────────────────────────

ZSH_COMPLETION_DIR="/usr/local/share/zsh/site-functions"
ZSH_COMPLETION_SRC="${SCRIPT_DIR}/completions/adssh.zsh"

if [ -f "${ZSH_COMPLETION_SRC}" ]; then
    if { [ -d "${ZSH_COMPLETION_DIR}" ] || mkdir -p "${ZSH_COMPLETION_DIR}" 2>/dev/null; } && \
       { [ -w "${ZSH_COMPLETION_DIR}" ] || [ "$(id -u)" -eq 0 ]; }; then
        info "Installing zsh completion to ${ZSH_COMPLETION_DIR}/_adssh ..."
        cp "${ZSH_COMPLETION_SRC}" "${ZSH_COMPLETION_DIR}/_adssh"
    else
        warn "Cannot write to ${ZSH_COMPLETION_DIR}. Copy manually:"
        warn "  sudo mkdir -p '${ZSH_COMPLETION_DIR}'"
        warn "  sudo cp '${ZSH_COMPLETION_SRC}' ${ZSH_COMPLETION_DIR}/_adssh"
    fi
else
    warn "Zsh completion source not found: ${ZSH_COMPLETION_SRC}"
fi

# ── Man page ──────────────────────────────────────────────────────────────────

MAN_DIR="/usr/local/share/man/man1"
MAN_SRC="${SCRIPT_DIR}/man/adssh.1"

if [ -f "${MAN_SRC}" ]; then
    if { [ -d "${MAN_DIR}" ] || mkdir -p "${MAN_DIR}" 2>/dev/null; } && \
       { [ -w "${MAN_DIR}" ] || [ "$(id -u)" -eq 0 ]; }; then
        info "Installing man page to ${MAN_DIR}/adssh.1 ..."
        cp "${MAN_SRC}" "${MAN_DIR}/adssh.1"
    else
        warn "Cannot write to ${MAN_DIR}. Copy manually:"
        warn "  sudo mkdir -p '${MAN_DIR}'"
        warn "  sudo cp '${MAN_SRC}' ${MAN_DIR}/adssh.1"
    fi
else
    warn "Man page source not found: ${MAN_SRC}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

info "adssh installed successfully!"
printf '\n'
printf '  Binary   : %s\n' "${INSTALL_PATH}"
printf '  Config   : %s/.config/adssh/\n' "${HOME}"
printf '\n'
printf 'Run: exec adssh\n'
printf '\n'
