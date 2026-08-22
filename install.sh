#!/usr/bin/env bash
# Install env2hell — Linux / macOS.
#
# Three commands go on PATH:
#   secrets-guard   the policy; assistants call it before every shell command
#   secrets-redact  masks a secret that a command printed, after the fact
#   safe-env        prints the environment with secret values masked
#
# Then each assistant found is wired to call the guard, and the house rule that
# tells the model to reach for `safe-env` is installed alongside it. The
# redactor is wired for Claude Code only — see lib/patch_config.py for why.
#
#   ./install.sh                  install into every assistant found
#   ./install.sh --dry-run        print what would happen, change nothing
#   ./install.sh --ide claude     install into one assistant only
#   ./install.sh --bin-dir D      put the commands in D instead of ~/.local/bin
#   ./install.sh --no-rule        skip the documentation rule, wire the guard only
#
# Idempotent: re-running rewrites only what differs. A configuration file about
# to change is copied to <file>.bak.<timestamp> first. Nothing outside $HOME is
# touched.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${ENV2HELL_BIN_DIR:-$HOME/.local/bin}"
STAMP="$(date +%Y%m%d-%H%M%S)"

DRY_RUN=0
WITH_RULE=1
ONLY_IDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)  DRY_RUN=1 ;;
        --no-rule)  WITH_RULE=0 ;;
        --ide)      ONLY_IDE="${2:-}"; shift ;;
        --bin-dir)  BIN_DIR="${2:-}"; shift ;;
        -h|--help)  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -t 1 ]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_BAD=$'\033[31m'; C_OFF=$'\033[0m'
else
    C_OK=''; C_WARN=''; C_BAD=''; C_OFF=''
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s%s%s\n' "$C_OK"   "$*" "$C_OFF"; }
warn() { printf '%s%s%s\n' "$C_WARN" "$*" "$C_OFF"; }
bad()  { printf '%s%s%s\n' "$C_BAD"  "$*" "$C_OFF"; }
tilde() { printf '%s' "${1/#$HOME/\~}"; }

# Copy with a timestamped backup, skipping the copy when the content already
# matches so that a re-run leaves no pile of identical .bak files.
install_file() {
    local src="$1" dst="$2" mode="${3:-644}"
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        say "    = $(tilde "$dst")"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        say "    would write $(tilde "$dst")"
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    if [ -f "$dst" ]; then
        cp -p "$dst" "$dst.bak.$STAMP"
        say "    ~ $(tilde "$dst")  (backup .bak.$STAMP)"
    else
        say "    + $(tilde "$dst")"
    fi
    cp "$src" "$dst"
    chmod "$mode" "$dst"
}

# Only assistants that are already installed are written to. Creating a
# configuration tree for an assistant the user does not have would just litter
# their home directory.
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

# Each assistant reads its always-on instructions from a different directory.
rule_target() {
    case "$1" in
        claude)   printf '%s' "$HOME/.claude/rules/secrets-hygiene.md" ;;
        opencode) printf '%s' "$HOME/.config/opencode/instructions/secrets-hygiene.md" ;;
        codex)    printf '%s' "$HOME/.codex/memories/secrets-hygiene.md" ;;
        *)        printf '' ;;
    esac
}

find_python() {
    local py
    for py in python3 python; do
        if command -v "$py" >/dev/null 2>&1 &&
           "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' \
                 >/dev/null 2>&1; then
            printf '%s' "$py"
            return 0
        fi
    done
    return 1
}

# ── prerequisites ───────────────────────────────────────────────────────────
if ! PY="$(find_python)"; then
    bad "Python 3.8 or newer is required (the configuration files are JSON)."
    say "  python3: $(python3 --version 2>&1 || echo 'not found')"
    exit 1
fi
ok "python: $PY — $("$PY" --version 2>&1)"

if ! command -v jq >/dev/null 2>&1; then
    warn "jq not found — not required, but useful for inspecting the result."
fi

# ── the commands ────────────────────────────────────────────────────────
say "── commands ──"
install_file "$SRC/bin/secrets-guard"  "$BIN_DIR/secrets-guard"  755
install_file "$SRC/bin/secrets-redact" "$BIN_DIR/secrets-redact" 755
install_file "$SRC/bin/safe-env"       "$BIN_DIR/safe-env"       755

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "    $(tilde "$BIN_DIR") is not on PATH. Add it:"
       say  "        echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

# ── assistants ──────────────────────────────────────────────────────────────
found=0
while IFS= read -r ide; do
    [ -n "$ide" ] || continue
    found=1
    say "── $ide ──"

    # The opencode plugins are files next to the configuration, not on PATH.
    if [ "$ide" = "opencode" ]; then
        install_file "$SRC/plugins/opencode/secrets-guard.ts" \
                     "$HOME/.config/opencode/plugins/secrets-guard.ts"
        install_file "$SRC/plugins/opencode/secrets-redact.ts" \
                     "$HOME/.config/opencode/plugins/secrets-redact.ts"
    fi

    # --with-rule matters for opencode only: it reads an instruction file just
    # when the file is listed in its configuration.
    rule_flag=""
    [ "$WITH_RULE" -eq 1 ] && rule_flag="--with-rule"
    if [ "$DRY_RUN" -eq 1 ]; then
        "$PY" "$SRC/lib/patch_config.py" "$ide" --guard "$BIN_DIR/secrets-guard" \
              --redact "$BIN_DIR/secrets-redact" \
              ${rule_flag:+"$rule_flag"} --dry-run || true
    else
        "$PY" "$SRC/lib/patch_config.py" "$ide" --guard "$BIN_DIR/secrets-guard" \
              --redact "$BIN_DIR/secrets-redact" \
              ${rule_flag:+"$rule_flag"} || true
    fi

    if [ "$WITH_RULE" -eq 1 ]; then
        target="$(rule_target "$ide")"
        [ -n "$target" ] && install_file "$SRC/rules/secrets-hygiene.md" "$target"
    fi
done < <(detect_ides)

if [ "$found" -eq 0 ]; then
    bad "  No assistant found."
    warn "    Looked for ~/.claude, ~/.config/opencode, ~/.codex"
    warn "    Pass --ide <claude|opencode|codex> to install anyway."
    exit 1
fi

# ── verify ──────────────────────────────────────────────────────────────────
say "── verify ──"
if [ "$DRY_RUN" -eq 1 ]; then
    warn "  dry run — nothing was installed"
    exit 0
fi

guard="$BIN_DIR/secrets-guard"
probe() {
    printf '%s' "{\"tool_input\":{\"command\":$1}}" | "$guard" >/dev/null 2>&1
    printf '%s' "$?"
}

blocked="$(probe '"env"')"
allowed="$(probe '"echo hi"')"

if [ "$blocked" = "2" ] && [ "$allowed" = "0" ]; then
    ok "  ok — the guard blocks a bare env and allows an ordinary command"

    # The redactor has the opposite failure mode: it is silent when it works and
    # silent when it is broken, so the probe checks both directions — a labelled
    # password must be masked, a bare checksum of the same length must not.
    redact="$BIN_DIR/secrets-redact"
    if [ -x "$redact" ] && command -v jq >/dev/null 2>&1; then
        hexval='deadbeefdeadbeefdeadbeefdeadbeef'
        masked="$(printf '{"tool_response":{"stdout":"--pass %s"}}' "$hexval" |
                  "$redact" 2>/dev/null | grep -c 'REDACTED' || true)"
        kept="$(printf '{"tool_response":{"stdout":"md5 %s"}}' "$hexval" |
                "$redact" 2>/dev/null | wc -c)"
        if [ "$masked" -ge 1 ] && [ "$kept" -eq 0 ]; then
            ok "  ok — the redactor masks a labelled password, leaves a checksum alone"
        else
            warn "  the redactor did not behave as expected (masked=$masked kept=$kept)"
            warn "    run tests/test_redact.sh for the detail"
        fi
    elif [ -x "$redact" ]; then
        warn "  secrets-redact installed, but jq is missing — it will do nothing"
    fi

    say ""
    say "  Restart your assistant: hooks and plugins are read at start-up."
    say "  Then, in a shell it runs: safe-env        (values masked)"
    say "                            echo \"\$VAR\"     (one variable)"
else
    bad "  Installed, but the guard did not behave as expected."
    say "    bare env  → exit $blocked (expected 2)"
    say "    echo hi   → exit $allowed (expected 0)"
    exit 1
fi
