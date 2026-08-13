#!/usr/bin/env bash
# Remove env2hell from every assistant found, and from PATH.
#
#   ./uninstall.sh              remove everything this installer added
#   ./uninstall.sh --dry-run    print what would happen, change nothing
#   ./uninstall.sh --ide claude remove from one assistant only
#   ./uninstall.sh --keep-bin   unwire the assistants, leave the two commands
#
# The backups made at install time are left in place: they are the only copy of
# whatever the configuration held before, and deleting them here would defeat
# the point of making them.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${ENV2HELL_BIN_DIR:-$HOME/.local/bin}"

DRY_RUN=0
KEEP_BIN=0
ONLY_IDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)  DRY_RUN=1 ;;
        --keep-bin) KEEP_BIN=1 ;;
        --ide)      ONLY_IDE="${2:-}"; shift ;;
        -h|--help)  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -t 1 ]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_OFF=$'\033[0m'
else
    C_OK=''; C_WARN=''; C_OFF=''
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s%s%s\n' "$C_OK"   "$*" "$C_OFF"; }
warn() { printf '%s%s%s\n' "$C_WARN" "$*" "$C_OFF"; }
tilde() { printf '%s' "${1/#$HOME/\~}"; }

remove_file() {
    local path="$1"
    [ -e "$path" ] || return 0
    if [ "$DRY_RUN" -eq 1 ]; then
        say "    would remove $(tilde "$path")"
    else
        rm -f "$path"
        say "    - $(tilde "$path")"
    fi
}

detect_ides() {
    if [ -n "$ONLY_IDE" ]; then
        printf '%s\n' "$ONLY_IDE"
        return
    fi
    [ -d "$HOME/.claude" ]          && printf 'claude\n'
    [ -d "$HOME/.config/opencode" ] && printf 'opencode\n'
    [ -d "$HOME/.codex" ]           && printf 'codex\n'
    return 0
}

rule_target() {
    case "$1" in
        claude)   printf '%s' "$HOME/.claude/rules/secrets-hygiene.md" ;;
        opencode) printf '%s' "$HOME/.config/opencode/instructions/secrets-hygiene.md" ;;
        codex)    printf '%s' "$HOME/.codex/memories/secrets-hygiene.md" ;;
        *)        printf '' ;;
    esac
}

PY="python3"
command -v "$PY" >/dev/null 2>&1 || PY="python"

while IFS= read -r ide; do
    [ -n "$ide" ] || continue
    say "── $ide ──"
    if [ "$DRY_RUN" -eq 1 ]; then
        "$PY" "$SRC/lib/patch_config.py" "$ide" --remove --dry-run || true
    else
        "$PY" "$SRC/lib/patch_config.py" "$ide" --remove || true
    fi
    [ "$ide" = "opencode" ] && remove_file "$HOME/.config/opencode/plugins/secrets-guard.ts"
    remove_file "$(rule_target "$ide")"
done < <(detect_ides)

if [ "$KEEP_BIN" -eq 0 ]; then
    say "── commands ──"
    remove_file "$BIN_DIR/secrets-guard"
    remove_file "$BIN_DIR/safe-env"
fi

say ""
if [ "$DRY_RUN" -eq 1 ]; then
    warn "dry run — nothing was removed"
else
    ok "removed. Restart your assistant for it to stop calling the guard."
    warn "Backups (.bak.*) were left in place."
fi
