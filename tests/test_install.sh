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

# ── what the patch does to the rest of the file ─────────────────────────────
# Two decisions taken on 2026-09-16, both about a reader who keeps their
# dotfiles in git: the backups stop piling up, and the indent is the file's own
# rather than this program's.

fresh
printf '{}\n' > "$tmp/home/.claude/settings.json"
for stamp in 20260901-120000 20260902-120000 20260903-120000 20260904-120000; do
    cp "$tmp/home/.claude/settings.json" "$tmp/home/.claude/settings.json.bak.$stamp"
done
run claude
kept="$(find "$tmp/home/.claude" -maxdepth 1 -name 'settings.json.bak.*' | wc -l)"
newest_gone="$(find "$tmp/home/.claude" -maxdepth 1 -name 'settings.json.bak.20260904-120000' | wc -l)"
oldest_gone="$(find "$tmp/home/.claude" -maxdepth 1 -name 'settings.json.bak.20260901-120000' | wc -l)"
if [ "$kept" -eq 3 ] && [ "$newest_gone" -eq 1 ] && [ "$oldest_gone" -eq 0 ]; then
    ok "claude: three backups are kept and the oldest go"
else
    no "claude: three backups are kept and the oldest go" \
       "$kept left; newest present=$newest_gone oldest present=$oldest_gone"
fi

# The indent is read from the file, not imposed on it. A configuration written
# with four spaces used to come back with two, which is 68 changed lines on a
# file where four lines actually changed.
indent_of () {                  # indent_of <file> — the leading run of line 2
    python3 - "$1" <<'PY'
import sys
for line in open(sys.argv[1]):
    body = line.lstrip(" \t")
    if body and body != line:
        print(len(line) - len(body)); break
else:
    print("none")
PY
}

fresh
printf '{\n    "model": "opus",\n    "env": {\n        "FOO": "bar"\n    }\n}\n' \
    > "$tmp/home/.claude/settings.json"
before_indent="$(indent_of "$tmp/home/.claude/settings.json")"
run claude
after_indent="$(indent_of "$tmp/home/.claude/settings.json")"
if [ "$before_indent" = 4 ] && [ "$after_indent" = 4 ]; then
    ok "claude: a four-space configuration stays four-space"
else
    no "claude: a four-space configuration stays four-space" \
       "was $before_indent, now $after_indent"
fi

fresh
printf '{\n  "model": "opus"\n}\n' > "$tmp/home/.claude/settings.json"
run claude
if [ "$(indent_of "$tmp/home/.claude/settings.json")" = 2 ]; then
    ok "claude: a two-space configuration stays two-space"
else
    no "claude: a two-space configuration stays two-space" \
       "now $(indent_of "$tmp/home/.claude/settings.json")"
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

# ── opencode, which nothing here used to touch ──────────────────────────────
# patch_opencode writes 394 permission rules into a live configuration and had
# no test at all. It also has a second filename to deal with: Opencode reads
# opencode.jsonc too, and a file earns that extension by carrying comments.

oc_dir="$tmp/home/.config/opencode"
oc_run () {                     # oc_run — prints nothing, returns the exit code
    HOME="$tmp/home" python3 "$PATCH" opencode --with-rule >/dev/null 2>&1
}
oc_fresh () {                   # oc_fresh <filename> <content>
    rm -rf "${tmp:?}/home/.config"
    mkdir -p "$oc_dir"
    printf '%s' "$2" > "$oc_dir/$1"
}

oc_fresh opencode.json '{}
'
oc_run; first_rc=$?
rules="$(python3 - "$oc_dir/opencode.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(len(d.get("permission", {}).get("bash", {})), d.get("plugin", []) and "plugin" or "no-plugin")
PY
)"
oc_run; oc_run; second="$(python3 - "$oc_dir/opencode.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(len(d.get("permission", {}).get("bash", {})), len(d.get("plugin", [])), len(d.get("instructions", [])))
PY
)"
if [ "$first_rc" -eq 0 ] && [ "$rules" = "394 plugin" ] && [ "$second" = "394 1 1" ]; then
    ok "opencode: three runs write the rules once ($rules)"
else
    no "opencode: three runs write the rules once" "first=$rules after three=$second rc=$first_rc"
fi

# A .jsonc with comments: readable, but not rewritable — the dump would drop
# every comment, and a mangled configuration is worse than an unwired one.
oc_fresh opencode.jsonc '{
  // the model this machine uses
  "model": "anthropic/claude-opus-5"
}
'
before="$(cat "$oc_dir/opencode.jsonc")"
out="$(HOME="$tmp/home" python3 "$PATCH" opencode --with-rule 2>&1)"
rc=$?
after="$(cat "$oc_dir/opencode.jsonc")"
case "$out" in
    *"carries comments"*) said=yes ;;
    *)                    said=no  ;;
esac
if [ "$rc" -eq 1 ] && [ "$said" = yes ] && [ "$before" = "$after" ]; then
    ok "opencode: a commented .jsonc is refused loudly and left untouched"
else
    no "opencode: a commented .jsonc is refused loudly and left untouched" \
       "exit $rc, said=$said, changed=$([ "$before" = "$after" ] && echo no || echo yes):
$(printf '%s\n' "$out" | sed 's/^/        /')"
fi

# The same extension without comments is ordinary JSON, and gets wired.
oc_fresh opencode.jsonc '{"model": "anthropic/claude-opus-5"}
'
oc_run; rc=$?
wired="$(python3 - "$oc_dir/opencode.jsonc" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(len(d.get("permission", {}).get("bash", {})))
PY
)"
if [ "$rc" -eq 0 ] && [ "$wired" = 394 ]; then
    ok "opencode: a .jsonc with no comments in it is wired normally"
else
    no "opencode: a .jsonc with no comments in it is wired normally" "exit $rc, rules $wired"
fi

# No configuration at all is not a failure — exit 3, so the installer can tell
# "this assistant is not here" from "this assistant was left unprotected".
rm -rf "${tmp:?}/home/.config"
HOME="$tmp/home" python3 "$PATCH" opencode --with-rule >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 3 ]; then
    ok "opencode: a missing configuration exits 3, not 1"
else
    no "opencode: a missing configuration exits 3, not 1" "exit $rc"
fi

# ── an installation that predates the current numbers ───────────────────────
# Re-running the installer repointed the command and widened the matcher of an
# entry it found, and never touched its timeout. Measured 2026-09-16 on this
# machine: every redactor entry still said 10 while the installer had been
# writing 60 for hours — the very window the number was raised to close.
fresh
cat > "$tmp/home/.claude/settings.json" <<'JSON'
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash",
       "hooks": [{"type": "command", "command": "/opt/env2hell/secrets-guard",
                  "timeout": 2, "statusMessage": "secrets-guard..."}]}
    ],
    "PostToolUse": [
      {"matcher": "Bash",
       "hooks": [{"type": "command", "command": "/opt/env2hell/secrets-redact",
                  "timeout": 10, "statusMessage": "secrets-redact..."}]},
      {"matcher": "Edit|Write|mcp__.*",
       "hooks": [{"type": "command", "command": "/opt/env2hell/secrets-redact --warn-only",
                  "timeout": 10, "statusMessage": "secrets-redact..."}]}
    ],
    "PostToolUseFailure": [
      {"matcher": "Bash|Read|Grep",
       "hooks": [{"type": "command", "command": "/opt/env2hell/secrets-redact --warn-only",
                  "timeout": 10, "statusMessage": "secrets-redact..."}]}
    ]
  }
}
JSON
run claude
timeouts="$(python3 - "$(cfg claude)" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
out = []
for event, blocks in sorted(d.get("hooks", {}).items()):
    for b in blocks:
        for h in b.get("hooks", []):
            c = str(h.get("command", ""))
            if "secrets-guard" in c:
                out.append(f"guard={h.get('timeout')}")
            elif "secrets-redact" in c:
                out.append(f"redact={h.get('timeout')}")
print(" ".join(sorted(set(out))))
PY
)"
if [ "$timeouts" = "guard=5 redact=60" ]; then
    ok "claude: an old installation is brought up to the current timeouts ($timeouts)"
else
    no "claude: an old installation is brought up to the current timeouts" "got [$timeouts]"
fi

# And the matcher that was narrow when it was written.
if grep -qE 'PostToolUseFailure.*Edit.Write.mcp__' <<< "$(shape claude)"; then
    ok "claude: the old failure matcher is widened by the same run"
else
    no "claude: the old failure matcher is widened by the same run" "$(shape claude)"
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

# ── the two installers write the same policy, and nothing enforced it ───────
# Every matcher and the timeout exist twice, in two languages. A comment saying
# "keep these in step" is what failed: the Python side grew the Edit/Write/MCP
# notice entry on 2026-09-14 and the port went without it until 2026-09-16, so
# a Windows user editing a .env got no warning at all. This compares the
# literals themselves, in the order below.
py_values="$(python3 - "$PATCH" <<'PY'
import runpy, sys
mod = runpy.run_path(sys.argv[1])
for value in (mod["REDACT_MATCHER"]["claude"], mod["NOTICE_MATCHER"],
              mod["FAILURE_MATCHER"], mod["REDACT_TIMEOUT"]):
    print(value)
PY
)"

# shellcheck disable=SC2016  # the $-names below are PowerShell's, matched as
                            # text in install.ps1 — expanding them here would
                            # search for the empty string
ps_value () {                   # ps_value <name> — the literal from install.ps1
    sed -n "s/^\\\$$1 *= *'\\(.*\\)'.*/\\1/p;s/^\\\$$1 *= *\\([0-9][0-9]*\\).*/\\1/p" \
        "$SRC/install.ps1" | head -1
}

i=0
while IFS='|' read -r label ps_name; do
    [ -n "$label" ] || continue
    i=$((i + 1))
    want="$(printf '%s\n' "$py_values" | sed -n "${i}p")"
    got="$(ps_value "$ps_name")"
    if [ -n "$want" ] && [ "$want" = "$got" ]; then
        ok "install.ps1 and lib/patch_config.py agree on $label ($want)"
    else
        no "install.ps1 and lib/patch_config.py agree on $label" \
           "python=[$want] powershell=[$got]"
    fi
done <<'PAIRS'
the redactor matcher|RedactMatcher
the notice matcher|NoticeMatcher
the failure matcher|FailureMatcher
the redactor timeout|RedactTimeout
PAIRS

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

# ── the round trip: install.sh, then uninstall.sh ───────────────────────────
# Both scripts were only ever driven a piece at a time — the patcher directly,
# with --remove. Nothing had run the pair as a user runs it, which is the only
# way to find what one leaves for the other.
sh_home="$tmp/shhome"
mkdir -p "$sh_home/.claude" "$sh_home/.codex" "$sh_home/.config/opencode"
for f in "$sh_home/.claude/settings.json" "$sh_home/.codex/hooks.json" \
         "$sh_home/.config/opencode/opencode.json"; do
    printf '{"model": "kept-by-the-user"}\n' > "$f"
done

if HOME="$sh_home" ENV2HELL_BIN_DIR="$sh_home/bin" \
       bash "$SRC/install.sh" >"$tmp/sh-install.out" 2>&1; then
    ok "install.sh: a run over a fresh home finishes"
else
    no "install.sh: a run over a fresh home finishes" \
       "$(tail -5 "$tmp/sh-install.out" | sed 's/^/        /')"
fi

sh_state () {                   # sh_state — hooks, rules, plugin, commands
    python3 - "$sh_home" <<'PY'
import json, pathlib, sys
h = pathlib.Path(sys.argv[1])
claude = json.load(open(h / ".claude/settings.json"))
hooks = [c for blocks in claude.get("hooks", {}).values()
         for b in blocks for hk in b.get("hooks", [])
         for c in [str(hk.get("command", ""))] if "secrets-" in c]
oc = json.load(open(h / ".config/opencode/opencode.json"))
bins = sorted(p.name for p in (h / "bin").iterdir()) if (h / "bin").is_dir() else []
print(f"hooks={len(hooks)} rules={len(oc.get('permission', {}).get('bash', {}))} "
      f"plugins={len(oc.get('plugin', []))} bins={len(bins)} "
      f"model={claude.get('model')}")
PY
}

installed="$(sh_state)"
# Four hook commands on Claude Code: the guard before the command, the redactor
# on results it can rewrite, the notice on the ones it cannot, and the failure
# warning.
if [ "$installed" = "hooks=4 rules=394 plugins=1 bins=3 model=kept-by-the-user" ]; then
    ok "install.sh: the whole thing lands ($installed)"
else
    no "install.sh: the whole thing lands" "got [$installed]"
fi

if HOME="$sh_home" ENV2HELL_BIN_DIR="$sh_home/bin" \
       bash "$SRC/uninstall.sh" >"$tmp/sh-uninstall.out" 2>&1; then
    ok "uninstall.sh: a run over an installed home finishes"
else
    no "uninstall.sh: a run over an installed home finishes" \
       "$(tail -5 "$tmp/sh-uninstall.out" | sed 's/^/        /')"
fi

removed="$(sh_state)"
if [ "$removed" = "hooks=0 rules=0 plugins=0 bins=0 model=kept-by-the-user" ]; then
    ok "uninstall.sh: everything of ours goes, the user's key stays"
else
    no "uninstall.sh: everything of ours goes, the user's key stays" "got [$removed]"
fi

# The backups are the only copy of what the configuration held before, so the
# uninstaller says out loud that it leaves them — and it has to be true.
baks="$(find "$sh_home/.claude" -maxdepth 1 -name 'settings.json.bak.*' | wc -l)"
if [ "$baks" -ge 1 ]; then
    ok "uninstall.sh: the backups are left in place ($baks)"
else
    no "uninstall.sh: the backups are left in place" "none left"
fi

# A second uninstall is something people do when they are not sure the first
# worked.
if HOME="$sh_home" ENV2HELL_BIN_DIR="$sh_home/bin" \
       bash "$SRC/uninstall.sh" >"$tmp/sh-uninstall2.out" 2>&1; then
    ok "uninstall.sh: running it again is harmless"
else
    no "uninstall.sh: running it again is harmless" \
       "$(tail -5 "$tmp/sh-uninstall2.out" | sed 's/^/        /')"
fi

# ── install.ps1, run rather than read ───────────────────────────────────────
# Until 2026-09-16 nothing had ever executed this file: the parity checks above
# read its literals, and tests/test_ownership.ps1 lifts one function out of it.
# The first end-to-end run died on the first assistant it touched, with
# "The property 'Name' cannot be found on this object" — `$o.PSObject.Properties
# .Name` throws under Set-StrictMode when the object has no properties, and a
# settings.json holding `{}` is exactly that object.
#
# USERPROFILE and LOCALAPPDATA are what the installer reads for its paths, so
# pointing them at a temporary directory keeps this as far from the real
# configuration as the rest of this file.
if command -v pwsh >/dev/null 2>&1; then
    ps_home="$tmp/pshome"
    mkdir -p "$ps_home/.claude" "$ps_home/.codex" "$ps_home/.config/opencode"
    for f in "$ps_home/.claude/settings.json" "$ps_home/.codex/hooks.json" \
             "$ps_home/.config/opencode/opencode.json"; do
        printf '{}\n' > "$f"
    done

    ps_install () {             # ps_install — one run, output discarded
        USERPROFILE="$ps_home" LOCALAPPDATA="$ps_home/AppData" \
            pwsh -NoProfile -File "$SRC/install.ps1" -BinDir "$ps_home/bin" \
            >"$tmp/ps-install.out" 2>&1
    }

    ps_shape () {               # ps_shape — the wiring, as one sorted list
        python3 - "$ps_home/.claude/settings.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
out = []
for event, blocks in sorted(d.get("hooks", {}).items()):
    for b in blocks:
        for h in b.get("hooks", []):
            out.append(f"{event}\t{b.get('matcher')}\ttimeout={h.get('timeout')}")
print("\n".join(sorted(out)))
PY
    }

    if ps_install; then
        ok "install.ps1: a run over an empty configuration finishes"
    else
        no "install.ps1: a run over an empty configuration finishes" \
           "$(tail -5 "$tmp/ps-install.out" | sed 's/^/        /')"
    fi

    ps_first="$(ps_shape)"
    ps_install; ps_install
    if [ "$ps_first" = "$(ps_shape)" ]; then
        ok "install.ps1: three runs leave the same wiring"
    else
        no "install.ps1: three runs leave the same wiring" "the wiring moved:
$(diff <(printf '%s\n' "$ps_first") <(ps_shape) | sed 's/^/        /')"
    fi

    # One line per entry the port is supposed to write, named the way a reader
    # would name it rather than by the regex that finds it.
    while IFS='|' read -r label want; do
        [ -n "$label" ] || continue
        if grep -qE "$want" <<< "$ps_first"; then
            ok "install.ps1: wired $label"
        else
            no "install.ps1: wired $label" "not found in:
$(printf '%s\n' "$ps_first" | sed 's/^/        /')"
        fi
    done <<'ENTRIES'
the guard, before the command|PreToolUse.*Bash.*timeout=5
the redactor, on results it can rewrite|PostToolUse.*Bash.Read.Grep.*timeout=
the notice, on the ones it cannot|PostToolUse.*Edit.Write.mcp__.*timeout=
the failure warning|PostToolUseFailure.*Edit.Write.mcp__.*timeout=
ENTRIES

    oc_written="$(python3 - "$ps_home/.config/opencode/opencode.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(len(d.get("permission", {}).get("bash", {})), len(d.get("plugin", [])))
PY
)"
    if [ "$oc_written" = "394 1" ]; then
        ok "install.ps1: opencode gets the same 394 rules and the plugin"
    else
        no "install.ps1: opencode gets the same 394 rules and the plugin" "got [$oc_written]"
    fi
else
    printf '  skip  install.ps1 end to end — pwsh not installed\n'
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
