#!/usr/bin/env bash
# One-line Mantis installer.
#
#   curl -fsSL https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.sh | bash
#
# - Builds (or downloads, if available) the `mantis-daemon` and
#   `mantis` binaries.
# - Installs them under ~/.local/bin (or $PREFIX/bin).
# - Detects which AI CLI(s) you have installed (claude, codex, opencode)
#   and installs Mantis as a plugin for each, exposing slash
#   commands like /mantis-scan, /mantis-status, /mantis-claim.

set -euo pipefail

PREFIX="${MANTIS_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
PLUGIN_SOURCE_REPO="${MANTIS_REPO:-https://github.com/deonmenezes/mantishack}"
MANTIS_REF="${MANTIS_REF:-main}"
BUILD_DIR="${MANTIS_BUILD_DIR:-$HOME/.cache/mantis-build}"

log() { printf '\033[36m[mantis]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[mantis] warn:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[mantis] error:\033[0m %s\n' "$*" >&2; exit 1; }

uname_s=$(uname -s)
uname_m=$(uname -m)
log "host: $uname_s/$uname_m"

# 1. Toolchain check ----------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
    die "cargo not found. Install Rust from https://rustup.rs and rerun."
fi
if ! command -v git >/dev/null 2>&1; then
    die "git not found. Install git and rerun."
fi

mkdir -p "$BIN_DIR" "$BUILD_DIR"

# 2. Source checkout ----------------------------------------------------------
if [ -d "$BUILD_DIR/.git" ]; then
    log "updating existing checkout at $BUILD_DIR"
    git -C "$BUILD_DIR" fetch --depth=1 origin "$MANTIS_REF"
    git -C "$BUILD_DIR" checkout -f FETCH_HEAD
else
    log "cloning $PLUGIN_SOURCE_REPO@$MANTIS_REF -> $BUILD_DIR"
    rm -rf "$BUILD_DIR"
    git clone --depth=1 --branch "$MANTIS_REF" "$PLUGIN_SOURCE_REPO" "$BUILD_DIR"
fi

# 3. Build binaries -----------------------------------------------------------
log "building mantis-daemon + mantis (release)"
(cd "$BUILD_DIR" && cargo build --release --bin mantis-daemon --bin mantis)
install -m 0755 "$BUILD_DIR/target/release/mantis-daemon" "$BIN_DIR/mantis-daemon"
install -m 0755 "$BUILD_DIR/target/release/mantis" "$BIN_DIR/mantis"
log "installed: $BIN_DIR/mantis-daemon"
log "installed: $BIN_DIR/mantis"

# 4. AI-CLI plugin installation ----------------------------------------------
PLUGIN_SOURCE="$BUILD_DIR/plugin"
INSTALLED_FOR=()

install_for_claude() {
    if ! command -v claude >/dev/null 2>&1 && [ ! -d "$HOME/.claude" ]; then
        return 1
    fi
    local target="$HOME/.claude/plugins/mantis"
    rm -rf "$target"
    mkdir -p "$(dirname "$target")"
    cp -R "$PLUGIN_SOURCE/claude-code" "$target"
    log "installed plugin for claude-code at $target"
    INSTALLED_FOR+=("claude-code")
}

install_for_codex() {
    if ! command -v codex >/dev/null 2>&1 && [ ! -d "$HOME/.codex" ]; then
        return 1
    fi
    local target="$HOME/.codex/plugins/mantis"
    rm -rf "$target"
    mkdir -p "$(dirname "$target")"
    cp -R "$PLUGIN_SOURCE/codex" "$target"
    log "installed plugin for codex at $target"
    INSTALLED_FOR+=("codex")
}

install_for_opencode() {
    if ! command -v opencode >/dev/null 2>&1 && [ ! -d "$HOME/.config/opencode" ]; then
        return 1
    fi
    local target="$HOME/.config/opencode/plugins/mantis"
    rm -rf "$target"
    mkdir -p "$(dirname "$target")"
    cp -R "$PLUGIN_SOURCE/opencode" "$target"
    log "installed plugin for opencode at $target"
    INSTALLED_FOR+=("opencode")
}

install_for_claude || true
install_for_codex || true
install_for_opencode || true

# 5. PATH hint ---------------------------------------------------------------
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        warn "add $BIN_DIR to your PATH:"
        warn "    echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zshrc  # or ~/.bashrc"
        ;;
esac

# 6. Summary ------------------------------------------------------------------
log "done."
if [ "${#INSTALLED_FOR[@]}" -gt 0 ]; then
    log "AI CLIs configured: ${INSTALLED_FOR[*]}"
    log "try:    mantis daemon   # start the daemon"
    log "or in your AI CLI:    /mantis-scan <target>"
else
    warn "no claude/codex/opencode CLI detected — the binaries are installed but no plugin was wired."
    warn "install the CLI you want and rerun this script."
fi
