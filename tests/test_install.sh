#!/usr/bin/env bash
# tests/test_install.sh — the installer must be idempotent.
#
#   bash tests/test_install.sh
#
# This class of bug is invisible on the run that introduces it and obvious on
# the second, which nobody makes by hand. Measured 2026-09-14: a change to how
# patch_config.py told its own PostToolUse entry from a new one keyed on a flag
# that Codex's entry also carries, so there the entry became invisible to its
# own patcher and every run appended another copy. Codex ended with three
# identical hooks, found by reading the file for an unrelated reason.
#
# Nothing here touches the real configuration: HOME is a temporary directory,
# and patch_config.py derives every path from it.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH="$SRC/lib/patch_config.py"

[ -e "$PATCH" ] || { echo "patch_config.py not found: $PATCH" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "these tests need python3" >&2; exit 2; }

pass=0
fail=0
ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "$tmp"' EXIT

GUARD=/opt/env2hell/secrets-guard
REDACT=/opt/env2hell/secrets-redact

fresh () {                      # fresh <ide>
    rm -rf "${tmp:?}/home"    # :? so an empty $tmp can never mean /home
    mkdir -p "$tmp/home/.claude" "$tmp/home/.codex"
    printf '{}\n' > "$tmp/home/.claude/settings.json"
    printf '{}\n' > "$tmp/home/.codex/hooks.json"
}

run () {                        # run <ide> [extra args…]
    HOME="$tmp/home" python3 "$PATCH" "$1" \
        --guard "$GUARD" --redact "$REDACT" "${@:2}" >/dev/null 2>&1
}

cfg () {                        # cfg <ide> — the file that ide writes
    case "$1" in
        claude) printf '%s' "$tmp/home/.claude/settings.json" ;;
        codex)  printf '%s' "$tmp/home/.codex/hooks.json" ;;
    esac
}

# Every hook entry mentioning this tool, across every event, as one sorted list.
# Comparing the whole shape rather than a count catches an entry that was
# duplicated *and* one that was silently rewritten.
shape () {                      # shape <ide>
    python3 - "$(cfg "$1")" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("<unreadable>"); raise SystemExit
out = []
for event, blocks in sorted(d.get("hooks", {}).items()):
    for b in blocks:
        for h in b.get("hooks", []):
            c = str(h.get("command", ""))
            if "secrets-" in c:
                out.append(f"{event}\t{b.get('matcher')}\t{c}")
print("\n".join(sorted(out)))
PY
}

for ide in claude codex; do
    fresh
    run "$ide"
    first="$(shape "$ide")"

    if [ -n "$first" ]; then
        ok "$ide: the first run wires something"
    else
        no "$ide: the first run wires something" "nothing was written"
        continue
    fi

    run "$ide"
    second="$(shape "$ide")"
    if [ "$first" = "$second" ]; then
        ok "$ide: a second run changes nothing"
    else
        no "$ide: a second run changes nothing" \
           "the wiring moved:
$(diff <(printf '%s\n' "$first") <(printf '%s\n' "$second") | sed 's/^/        /')"
    fi

    run "$ide"
    third="$(shape "$ide")"
    if [ "$first" = "$third" ]; then
        ok "$ide: a third run changes nothing"
    else
        no "$ide: a third run changes nothing" "it kept growing after the second"
    fi

    # Counting entries as well as comparing them: a duplicate that happens to
    # sort next to its original is still a duplicate.
    n_uniq="$(printf '%s\n' "$first" | sort -u | grep -c .)"
    n_all="$(printf '%s\n' "$third" | grep -c .)"
    if [ "$n_all" -eq "$n_uniq" ]; then
        ok "$ide: no duplicate hook entries after three runs"
    else
        no "$ide: no duplicate hook entries after three runs" \
           "$n_all entries, $n_uniq distinct"
    fi
done

# ── what each assistant is supposed to end up with ──────────────────────────
# Claude Code takes three: the guard before the command, the redactor on the
# results it can rewrite, and a warn-only entry on the ones it cannot. Codex
# takes two, both --warn-only on the shell tool, because its hook contract has
# no field that replaces output.
fresh
run claude
claude_shape="$(shape claude)"

for want in \
    "PreToolUse.*secrets-guard" \
    "PostToolUse.*Bash|Read|Grep.*secrets-redact$" \
    "PostToolUse.*Edit|Write|mcp__.*--warn-only" \
    "PostToolUseFailure.*--warn-only"; do
    if grep -qE "$want" <<< "$claude_shape"; then
        ok "claude: wired ${want%%.*} — $(printf '%s' "$want" | cut -d. -f2- | head -c 30)"
    else
        no "claude: wired $want" "not found in:
$(printf '%s\n' "$claude_shape" | sed 's/^/        /')"
    fi
done

# ── removal has to be complete, and reversible ──────────────────────────────
run claude --remove
left="$(shape claude)"
if [ -z "$left" ]; then
    ok "claude: --remove takes every entry back out"
else
    no "claude: --remove takes every entry back out" "left behind:
$(printf '%s\n' "$left" | sed 's/^/        /')"
fi

run claude
if [ "$(shape claude)" = "$claude_shape" ]; then
    ok "claude: re-adding after --remove lands in the same place"
else
    no "claude: re-adding after --remove lands in the same place" "the wiring differs"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
