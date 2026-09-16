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

# ── somebody else's hooks, which happen to mention these names ──────────────
# Ownership used to be a substring of the command, so a wrapper or an audit
# script named after this tool was treated as one of its own entries: silently
# repointed on install, deleted on --remove. The program being run is what says
# whose entry it is.

seed_third_party () {           # seed_third_party — a config with foreign hooks
    fresh
    cat > "$tmp/home/.claude/settings.json" <<'JSON'
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash",
       "hooks": [{"type": "command", "command": "/home/me/bin/wrap-secrets-guard --audit"}]}
    ],
    "PostToolUse": [
      {"matcher": "Write",
       "hooks": [{"type": "command", "command": "/home/me/bin/secrets-redact-audit"}]}
    ]
  }
}
JSON
}

foreign_commands () {           # foreign_commands — theirs, still in the file
    python3 - "$tmp/home/.claude/settings.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
out = [h.get("command", "")
       for blocks in d.get("hooks", {}).values()
       for b in blocks for h in b.get("hooks", [])
       if "/home/me/bin/" in h.get("command", "")]
print("\n".join(sorted(out)))
PY
}

seed_third_party
run claude
kept="$(foreign_commands)"
want="/home/me/bin/secrets-redact-audit
/home/me/bin/wrap-secrets-guard --audit"
if [ "$kept" = "$want" ]; then
    ok "claude: install leaves a third-party hook and its arguments alone"
else
    no "claude: install leaves a third-party hook and its arguments alone" \
       "what survived:
$(printf '%s\n' "$kept" | sed 's/^/        /')"
fi

# Ours landed beside theirs rather than instead of it.
if [ -n "$(shape claude)" ]; then
    ok "claude: our own entries are added next to the third-party ones"
else
    no "claude: our own entries are added next to the third-party ones" "nothing was wired"
fi

run claude --remove
kept="$(foreign_commands)"
if [ "$kept" = "$want" ]; then
    ok "claude: --remove takes ours out and leaves theirs"
else
    no "claude: --remove takes ours out and leaves theirs" \
       "what survived:
$(printf '%s\n' "$kept" | sed 's/^/        /')"
fi
# `shape` lists every entry mentioning "secrets-", which now includes theirs —
# so the assertion is about what is left once theirs is set aside.
ours_left="$(shape claude | grep -v '/home/me/bin/' || true)"
if [ -z "$ours_left" ]; then
    ok "claude: --remove still takes every entry of ours out"
else
    no "claude: --remove still takes every entry of ours out" "left: $ours_left"
fi

# ── the file on disk, not the wiring inside it ──────────────────────────────
# Every case below is a way to patch a configuration correctly and damage it
# anyway: the hook entries land, and something else about the file is wrong —
# its mode, its identity as a symlink, or a second copy left beside it.

mode_of () {                    # mode_of <path> — portable stat -c '%a'
    python3 - "$1" <<'PY'
import os, sys
print(format(os.stat(sys.argv[1]).st_mode & 0o777, "o"))
PY
}

# A driver that dies exactly where a SIGKILL hurts: after the temp file is
# written, before it is renamed over the configuration.
cat > "$tmp/kill_at_replace.py" <<'PY'
import os, sys
sys.path.insert(0, os.environ["PATCH_LIB"])
import patch_config
patch_config.os.replace = lambda *a, **k: os._exit(9)
sys.argv = ["patch_config.py"] + sys.argv[1:]
sys.exit(patch_config.main())
PY

# The same, stalled instead of killed: it holds its temp file open while a
# second patcher runs the whole cycle underneath it.
cat > "$tmp/slow_replace.py" <<'PY'
import os, sys, time
sys.path.insert(0, os.environ["PATCH_LIB"])
import patch_config
_real = os.replace
def _slow(src, dst):
    time.sleep(2)
    return _real(src, dst)
patch_config.os.replace = _slow
sys.argv = ["patch_config.py"] + sys.argv[1:]
sys.exit(patch_config.main())
PY

leftover_tmp () {               # leftover_tmp <dir> — yes/no, no subprocess
    set -- "$1"/*.env2hell.tmp
    [ -e "$1" ] && printf 'yes' || printf 'no'
}

# ── valid JSON that is not an object ────────────────────────────────────────
fresh
printf '[]\n' > "$tmp/home/.claude/settings.json"
out="$(HOME="$tmp/home" python3 "$PATCH" claude --guard "$GUARD" --redact "$REDACT" 2>&1)"
rc=$?
case "$out" in
    *Traceback*) traceback=yes ;;
    *)           traceback=no  ;;
esac
if [ "$rc" -eq 1 ] && [ "$traceback" = no ]; then
    ok "claude: a config holding a list is refused with a sentence"
else
    no "claude: a config holding a list is refused with a sentence" \
       "exit $rc, traceback=$traceback:
$(printf '%s\n' "$out" | sed 's/^/        /')"
fi

# ── the mode of the file survives the patch ─────────────────────────────────
# ~/.claude/settings.json carries an `env` block, which is where an API key
# goes. A patch that publishes it to the rest of the machine is a leak caused
# by the tool that exists to prevent one.
fresh
chmod 600 "$tmp/home/.claude/settings.json"
run claude
got="$(mode_of "$tmp/home/.claude/settings.json")"
if [ "$got" = 600 ]; then
    ok "claude: a 600 config is still 600 after a patch"
else
    no "claude: a 600 config is still 600 after a patch" "mode is now $got"
fi

# ── a config that is a symlink into a dotfiles repository ───────────────────
fresh
mkdir -p "$tmp/home/dotfiles"
printf '{"model": "opus"}\n' > "$tmp/home/dotfiles/settings.json"
ln -sf "$tmp/home/dotfiles/settings.json" "$tmp/home/.claude/settings.json"
run claude
target_wired="$(python3 - "$tmp/home/dotfiles/settings.json" <<'PY'
import json, sys
print("yes" if json.load(open(sys.argv[1])).get("hooks") else "no")
PY
)"
if [ -L "$tmp/home/.claude/settings.json" ] && [ "$target_wired" = yes ]; then
    ok "claude: a symlinked config stays a link and the target is wired"
else
    no "claude: a symlinked config stays a link and the target is wired" \
       "link=$([ -L "$tmp/home/.claude/settings.json" ] && echo yes || echo no), target wired=$target_wired"
fi

# ── killed between the write and the rename ─────────────────────────────────
# The atomic write means the configuration itself survives; what used to
# survive with it was a world-readable copy of the whole file. A SIGKILL runs
# no cleanup handler, so the copy is kept private instead, and the next run
# sweeps it.
fresh
chmod 600 "$tmp/home/.claude/settings.json"
before="$(cat "$tmp/home/.claude/settings.json")"
PATCH_LIB="$(dirname "$PATCH")" HOME="$tmp/home" \
    python3 "$tmp/kill_at_replace.py" claude --guard "$GUARD" --redact "$REDACT" \
    >/dev/null 2>&1
after="$(cat "$tmp/home/.claude/settings.json")"

if [ "$before" = "$after" ]; then
    ok "claude: a run killed mid-write leaves the config untouched"
else
    no "claude: a run killed mid-write leaves the config untouched" "the file changed"
fi

worst=600
for leftover in "$tmp"/home/.claude/*.env2hell.tmp; do
    [ -e "$leftover" ] || continue
    worst="$(mode_of "$leftover")"
done
if [ "$worst" = 600 ]; then
    ok "claude: the copy a killed run leaves behind is not world-readable"
else
    no "claude: the copy a killed run leaves behind is not world-readable" \
       "mode is $worst"
fi

# Back-dated on purpose: the sweep leaves a temp file that is seconds old,
# because that one belongs to a patcher running right now. What it clears is
# the litter of a crash that happened earlier.
touch -d '2 hours ago' "$tmp"/home/.claude/*.env2hell.tmp 2>/dev/null \
    || touch -t 200001010000 "$tmp"/home/.claude/*.env2hell.tmp
run claude
if [ "$(leftover_tmp "$tmp/home/.claude")" = no ]; then
    ok "claude: the next run sweeps a stale temp file the killed one left"
else
    no "claude: the next run sweeps a stale temp file the killed one left" \
       "still there: $(echo "$tmp"/home/.claude/*.env2hell.tmp)"
fi

# ── two patchers on one configuration ───────────────────────────────────────
# They used to share one temp filename, so whichever renamed first left the
# other with nothing to rename and a traceback to show for it.
fresh
PATCH_LIB="$(dirname "$PATCH")" HOME="$tmp/home" \
    python3 "$tmp/slow_replace.py" claude --guard "$GUARD" --redact "$REDACT" \
    >"$tmp/slow.out" 2>&1 &
slow_pid=$!
sleep 1
HOME="$tmp/home" python3 "$PATCH" claude \
    --guard /other/place/secrets-guard --redact /other/place/secrets-redact \
    >"$tmp/fast.out" 2>&1
fast_rc=$?
wait "$slow_pid"
slow_rc=$?

if [ "$slow_rc" -eq 0 ] && [ "$fast_rc" -eq 0 ]; then
    ok "claude: two patchers at once both finish cleanly"
else
    no "claude: two patchers at once both finish cleanly" \
       "slow exited $slow_rc, fast exited $fast_rc:
$(cat "$tmp/slow.out" "$tmp/fast.out" | sed 's/^/        /')"
fi

# Last writer wins — the file carries one installation's paths, not a mixture,
# and it is still valid JSON with the wiring in place.
still_wired="$(python3 - "$tmp/home/.claude/settings.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:
    print(f"unreadable: {exc}"); raise SystemExit
pre = d.get("hooks", {}).get("PreToolUse", [])
cmds = {h.get("command") for e in pre for h in e.get("hooks", [])}
print("one" if len(cmds) == 1 else f"{len(cmds)}: {sorted(cmds)}")
PY
)"
if [ "$still_wired" = one ]; then
    ok "claude: the config a race leaves behind is readable and wired once"
else
    no "claude: the config a race leaves behind is readable and wired once" \
       "$still_wired"
fi

# ── the number that decides whether the redactor finishes ───────────────────
# A killed PostToolUse hook replaces nothing, so the tool result reaches the
# model as it was. At the masking pass's measured ~90 KB/s, 10 s covered under
# a megabyte: every larger result went through unmasked and unannounced. The
# assertion is a floor, not the value — raising it is fine, lowering it is the
# defect coming back.
fresh
run claude
written="$(python3 - "$(cfg claude)" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
out = [h.get("timeout")
       for event in ("PostToolUse", "PostToolUseFailure")
       for b in d.get("hooks", {}).get(event, [])
       for h in b.get("hooks", [])
       if "secrets-redact" in str(h.get("command", ""))]
print(min(out) if out else "none")
PY
)"
if [ "$written" != none ] && [ "$written" -ge 60 ]; then
    ok "claude: the redactor is given at least 60 s (got $written)"
else
    no "claude: the redactor is given at least 60 s" "smallest timeout written: $written"
fi

# The same number lives twice; nothing but this line keeps the copies equal.
py_timeout="$(sed -n 's/^REDACT_TIMEOUT = \([0-9]*\).*/\1/p' "$PATCH")"
# shellcheck disable=SC2016  # $RedactTimeout is PowerShell's variable, matched
                            # as text — expanding it here would search for ""
ps_timeout="$(sed -n 's/^\$RedactTimeout = \([0-9]*\).*/\1/p' "$SRC/install.ps1")"
if [ -n "$py_timeout" ] && [ "$py_timeout" = "$ps_timeout" ]; then
    ok "install.ps1 gives the redactor the same $py_timeout s as lib/patch_config.py"
else
    no "install.ps1 gives the redactor the same timeout as lib/patch_config.py" \
       "python=$py_timeout powershell=$ps_timeout"
fi

# ── the same question, asked of the PowerShell port ─────────────────────────
# install.ps1 carries its own copy of every decision here, and until now
# nothing in tests/ ran a line of it. This covers the one that damaged a
# user's configuration; the rest of the port is still untested.
if command -v pwsh >/dev/null 2>&1; then
    if out="$(pwsh -NoProfile -File "$SRC/tests/test_ownership.ps1" 2>&1)"; then
        ok "install.ps1: ownership is the program, not a substring ($(printf '%s' "$out" | tail -1))"
    else
        no "install.ps1: ownership is the program, not a substring" "$out"
    fi
else
    printf '  skip  install.ps1 ownership — pwsh not installed\n'
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
