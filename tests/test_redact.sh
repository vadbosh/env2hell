#!/usr/bin/env bash
# Behaviour tests for secrets-redact: the PostToolUse half of the pair.
#
#   ./tests/test_redact.sh               test the copy in ../bin
#   ./tests/test_redact.sh --tool PATH   test an installed copy
#
# Two properties carry the whole design and are easy to lose in a later edit:
#
#   it masks a labelled secret       `--pass <32 hex>` is a password
#   it leaves bare hex alone         an md5sum and a git SHA are not
#
# Length cannot tell those apart — an md5 is 32 characters and so was the croc
# relay password this hook was written for. Only the label can. A change that
# starts masking bare hex will pass every other test here and quietly redact
# every checksum in the session, so both directions are asserted.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$SRC/bin/secrets-redact"

while [ $# -gt 0 ]; do
    case "$1" in
        --tool) TOOL="${2:-}"; shift ;;
        -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -e "$TOOL" ] || { echo "secrets-redact not found: $TOOL" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "these tests need jq" >&2; exit 2; }

pass=0
fail=0
ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

# A hex run of exactly md5 length: a password in one test, a checksum in the
# next. Same string, opposite verdicts — that is the point.
HEX='deadbeefdeadbeefdeadbeefdeadbeef'
SHA='feedfacefeedfacefeedfacefeedfacefeedface'
GHP='ghp_0123456789abcdefghijklmnopqrstuvwxyzAB'

# hook_out <stdout-json-string> — run the hook, print the replacement stdout.
# Prints nothing when the hook declines to replace anything.
hook_out () {
    printf '{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"%s","stderr":"","interrupted":false,"isImage":false}}' "$1" |
        bash "$TOOL" | jq -j 'try (.hookSpecificOutput.updatedToolOutput.stdout // empty)'
}

# ── what must be masked ─────────────────────────────────────────────────────
got="$(hook_out "croc --relay h:9009 --pass $HEX code-word")"
if printf '%s' "$got" | grep -q "$HEX"; then
    no "masks a labelled password" "the raw value reached the output"
else
    ok "masks a labelled password"
fi

if printf '%s' "$got" | grep -q -- '--pass <REDACTED:32>'; then
    ok "keeps the label so the model can see what was removed"
else
    no "keeps the label" "expected '--pass <REDACTED:32>', got: $got"
fi

for form in "password=$HEX" "TOKEN: $HEX" "--token $HEX" "api_key=$HEX"; do
    if printf '%s' "$(hook_out "$form")" | grep -q "$HEX"; then
        no "masks $form" "the raw value reached the output"
    else
        ok "masks ${form%%[=: ]*} regardless of separator"
    fi
done

# Cloud keys with no provider prefix. Tier 1 could never take them by shape:
# 20 uppercase characters or 40 of base62 also describe a git SHA and half the
# identifiers in ordinary output. The variable name is the only signal, so it
# has to be in the label list.
for form in "HW_ACCESS_KEY=$HEX" "HW_SECRET_KEY: $HEX" "OS_SECRET_KEY=$HEX" \
    "HUAWEICLOUD_SECRET_KEY=$HEX"; do
    if printf '%s' "$(hook_out "$form")" | grep -q "$HEX"; then
        no "masks $form" "the raw value reached the output"
    else
        ok "masks ${form%%[=: ]*} — named as a cloud key, not shaped like one"
    fi
done

# The counterpart: a bare SHA must still come through, or every `git rev-parse`
# in the session turns into <REDACTED:40>.
if [ "$(hook_out "$SHA")" = "" ] || [ "$(hook_out "$SHA")" = "$SHA" ]; then
    ok "leaves a bare git SHA alone"
else
    no "leaves a bare git SHA alone" "got: $(hook_out "$SHA")"
fi

if printf '%s' "$(hook_out "export GH=$GHP")" | grep -q 'ghp_0123456789'; then
    no "masks a provider token with no label" "the raw value reached the output"
else
    ok "masks a provider token with no label"
fi

# ── what must NOT be masked ─────────────────────────────────────────────────
plain="md5sum: $HEX  big.bin"
if [ "$(hook_out "$plain")" = "" ]; then
    ok "leaves a bare md5 alone (no replacement issued)"
else
    no "leaves a bare md5 alone" "the hook rewrote: $(hook_out "$plain")"
fi

if [ "$(hook_out "commit $SHA fix: thing")" = "" ]; then
    ok "leaves a bare git SHA alone"
else
    no "leaves a bare git SHA alone" "the hook rewrote a commit line"
fi

if [ "$(hook_out "just some ordinary output")" = "" ]; then
    ok "stays silent when there is nothing to mask"
else
    no "stays silent when there is nothing to mask" "it produced a replacement"
fi

# ── it must not reformat what it passes through ─────────────────────────────
with_nl="$(hook_out "--pass $HEX\n" | od -An -c | tr -s ' ' | tail -c 4)"
if [ "$with_nl" = '\n
' ] || printf '%s' "$with_nl" | grep -q 'n'; then
    ok "keeps a trailing newline that was there"
else
    no "keeps a trailing newline that was there" "tail was [$with_nl]"
fi

without="$(hook_out "--pass $HEX")"
if [ "$(printf '%s' "$without" | tail -c1 | wc -l)" -eq 0 ]; then
    ok "adds no trailing newline that was not there"
else
    no "adds no trailing newline that was not there" "awk's print leaked through"
fi

multi="$(hook_out "first\n\n--pass $HEX")"
if [ "$multi" = "$(printf 'first\n\n--pass <REDACTED:32>')" ]; then
    ok "preserves interior blank lines"
else
    no "preserves interior blank lines" "got: $(printf '%s' "$multi" | od -An -c | head -2)"
fi

# ── the replacement must stay a valid tool result ───────────────────────────
full="$(printf '{"tool_response":{"stdout":"--pass %s","stderr":"","interrupted":true,"isImage":false}}' "$HEX" | bash "$TOOL")"
if printf '%s' "$full" | jq -e '.hookSpecificOutput.updatedToolOutput.interrupted == true' >/dev/null 2>&1; then
    ok "carries unrelated fields of tool_response through untouched"
else
    no "carries unrelated fields through" "interrupted was dropped or changed"
fi

if printf '%s' "$full" | jq -e '.hookSpecificOutput.hookEventName == "PostToolUse"' >/dev/null 2>&1; then
    ok "names the hook event as the schema requires"
else
    no "names the hook event" "hookEventName missing or wrong"
fi

# A tool result with no shell streams is not this hook's business.
if [ "$(printf '{"tool_response":{"filePath":"/etc/hosts"}}' | bash "$TOOL")" = "" ]; then
    ok "declines a tool result that carries no stdout/stderr"
else
    no "declines a tool result with no streams" "it invented a replacement"
fi

# ── every shape a tool result arrives in ────────────────────────────────────
# Claude Code sends {"stdout":…,"stderr":…} for a command that succeeded, and a
# bare string when it exited non-zero. Until 2026-09-14 the hook read the two
# stream fields and nothing else, so a `git remote -v` that failed carried its
# GitLab token straight into the transcript: both fields were empty, the hook
# declined, and the leak was invisible because the hook had fired correctly all
# session on every command that worked. A failing command is precisely when a
# credential surfaces — a URL with a password in it, an auth error quoting the
# token — so the shape that was not covered was the shape that mattered most.
GLPAT='glpat-0123456789abcdefghijklmnopqrstuvwx'

# `\\n` and not `\n`: printf would turn the latter into a real newline inside
# the JSON string, which is invalid JSON, and the hook would fail open — the
# test would then pass for the wrong reason on a hook that never looked at it.
bare="$(printf '{"tool_response":"Exit code 1\\nhttps://oauth2:%s@example/x.git\\n"}' "$GLPAT" | bash "$TOOL")"
if printf '%s' "$bare" | jq -r '.hookSpecificOutput.updatedToolOutput' 2>/dev/null | grep -q "$GLPAT"; then
    no "masks a bare-string tool_response" "the raw token reached the output"
elif printf '%s' "$bare" | jq -re '.hookSpecificOutput.updatedToolOutput' 2>/dev/null | grep -q '<REDACTED:'; then
    ok "masks a bare-string tool_response — the shape a failed command takes"
else
    no "masks a bare-string tool_response" "no replacement was produced at all"
fi

if printf '%s' "$bare" | jq -e '(.hookSpecificOutput.updatedToolOutput | type) == "string"' >/dev/null 2>&1; then
    ok "rebuilds a string result as a string, not as an object"
else
    no "rebuilds a string result as a string" "the schema of the result was changed"
fi

blob="$(printf '{"tool_response":{"is_error":true,"content":"https://oauth2:%s@example/x.git"}}' "$GLPAT" | bash "$TOOL")"
if printf '%s' "$blob" | jq -r '.hookSpecificOutput.updatedToolOutput.content' 2>/dev/null | grep -q "$GLPAT"; then
    no "masks a {content:…} tool_response" "the raw token reached the output"
elif printf '%s' "$blob" | jq -re '.hookSpecificOutput.updatedToolOutput.content' 2>/dev/null | grep -q '<REDACTED:'; then
    ok "masks a {content:…} tool_response"
else
    no "masks a {content:…} tool_response" "no replacement was produced at all"
fi

if printf '%s' "$blob" | jq -e '.hookSpecificOutput.updatedToolOutput.is_error == true' >/dev/null 2>&1; then
    ok "carries unrelated fields through on the content shape too"
else
    no "carries unrelated fields through on the content shape" "is_error was dropped"
fi

if [ "$(printf '{"tool_response":"nothing secret here\\n"}' | bash "$TOOL")" = "" ]; then
    ok "leaves a clean bare-string result alone"
else
    no "leaves a clean bare-string result alone" "it rewrote output with no secret in it"
fi

read_shape="$(printf '{"tool_response":{"type":"text","file":{"filePath":"/tmp/x.env","totalLines":1,"content":"GITLAB=%s\\n"}}}' "$GLPAT" | bash "$TOOL")"
if printf '%s' "$read_shape" | jq -r '.hookSpecificOutput.updatedToolOutput.file.content' 2>/dev/null | grep -q "$GLPAT"; then
    no "masks the Read tool's {file:{content}} result" "the raw token reached the output"
elif printf '%s' "$read_shape" | jq -re '.hookSpecificOutput.updatedToolOutput.file.content' 2>/dev/null | grep -q '<REDACTED:'; then
    ok "masks the Read tool's {file:{content}} result"
else
    no "masks the Read tool's {file:{content}} result" "no replacement was produced at all"
fi

if printf '%s' "$read_shape" | jq -e '.hookSpecificOutput.updatedToolOutput.file.filePath == "/tmp/x.env"' >/dev/null 2>&1; then
    ok "keeps the Read result's siblings — filePath, totalLines"
else
    no "keeps the Read result's siblings" "the file object was rebuilt from scratch"
fi

# ── size: the argument limit this hook used to fail open at ─────────────────
# `jq --arg out "$big"` dies at MAX_ARG_STRLEN — 128 KB on Linux, a single
# argument's limit and not ARG_MAX as a whole. The `|| exit 0` after it turned
# that into a silent pass-through. Measured 2026-09-14: 96 KB was masked, 128 KB
# was not, and nothing reported the difference. 128 KB of command output is
# ordinary — one `terraform show`, one verbose log, one long `kubectl get -o
# yaml`. The rebuild uses --rawfile now, which has no such ceiling.
big="$(head -c 200000 /dev/zero | tr '\0' 'y')"
bigout="$(printf '{"tool_response":{"stdout":"%s TOKEN=%s","stderr":""}}' "$big" "$GHP" |
          bash "$TOOL" | jq -r '.hookSpecificOutput.updatedToolOutput.stdout // empty' 2>/dev/null)"
if [ -z "$bigout" ]; then
    no "masks a 200 KB stdout" "the hook produced no replacement — it failed open on size"
elif printf '%s' "$bigout" | grep -q "$GHP"; then
    no "masks a 200 KB stdout" "the raw value reached the output"
else
    ok "masks a 200 KB stdout — past the 128 KB argument limit"
fi

warned="$(printf '{"tool_response":"https://oauth2:%s@example/x.git"}' "$GLPAT" | bash "$TOOL" --warn-only)"
if printf '%s' "$warned" | grep -q "$GLPAT"; then
    no "--warn-only never repeats the value" "the token is in the warning"
elif printf '%s' "$warned" | jq -re '.hookSpecificOutput.additionalContext' 2>/dev/null | grep -q 'credential-shaped'; then
    ok "--warn-only reports a bare-string result"
else
    no "--warn-only reports a bare-string result" "no warning was produced"
fi

# ── failing open ────────────────────────────────────────────────────────────
# /bin/bash by absolute path: `PATH=/nonexistent bash` would fail to find bash
# itself and report 127, which looks exactly like the failure being tested for.
# Nothing external runs before the jq check, so an empty PATH is enough.
nojq="$(PATH=/nonexistent /bin/bash "$TOOL" <<<'{"tool_response":{"stdout":"--pass '"$HEX"'"}}' 2>/dev/null; printf 'rc=%s' "$?")"
if [ "$nojq" = "rc=0" ]; then
    ok "fails open when jq is unavailable"
else
    no "fails open when jq is unavailable" "got [$nojq], expected a silent rc=0"
fi

if [ "$(printf '' | bash "$TOOL"; printf 'rc=%s' "$?")" = "rc=0" ]; then
    ok "fails open on empty input"
else
    no "fails open on empty input" "it did not exit 0 silently"
fi

# ── --filter: the plain-text mode the Opencode plugin uses ──────────────────
# The plugin skips the assignment when nothing changed, so the exit status is
# part of the contract, not a detail: 0 masked, 1 untouched.
filtered="$(printf 'croc --pass %s x\n' "$HEX" | bash "$TOOL" --filter; printf 'rc=%s' "$?")"
if [ "$filtered" = "$(printf 'croc --pass <REDACTED:32> x\nrc=0')" ]; then
    ok "--filter masks and reports exit 0"
else
    no "--filter masks and reports exit 0" "got: $filtered"
fi

untouched="$(printf 'md5 %s\n' "$HEX" | bash "$TOOL" --filter; printf 'rc=%s' "$?")"
if [ "$untouched" = "$(printf 'md5 %s\nrc=1' "$HEX")" ]; then
    ok "--filter passes a checksum through and reports exit 1"
else
    no "--filter passes a checksum through and reports exit 1" "got: $untouched"
fi

# --filter is the mode that must work on a machine without jq: the plugin runs
# it directly, with no JSON on either side.
nojq_filter="$(printf 'x --pass %s\n' "$HEX" |
               PATH="/usr/bin:/bin" /bin/bash "$TOOL" --filter 2>/dev/null)"
if printf '%s' "$nojq_filter" | grep -q 'REDACTED'; then
    ok "--filter needs no jq"
else
    no "--filter needs no jq" "got: $nojq_filter"
fi

# ── --warn-only: what an assistant that cannot replace output gets ──────────
# Codex names the shell result `output`, Claude Code splits it into stdout and
# stderr; the warning path reads all three, so the Codex shape is the one worth
# asserting — it is the shape the other modes never see.
warn="$(printf '{"tool_response":{"output":"croc --pass %s code"}}' "$HEX" | bash "$TOOL" --warn-only)"

if printf '%s' "$warn" | jq -e '.hookSpecificOutput.additionalContext' >/dev/null 2>&1; then
    ok "--warn-only reports through additionalContext"
else
    no "--warn-only reports through additionalContext" "got: $warn"
fi

# The whole point is a warning that does not repeat what it is warning about.
if printf '%s' "$warn" | grep -q "$HEX"; then
    no "--warn-only never repeats the value" "the secret is in the warning itself"
else
    ok "--warn-only never repeats the value"
fi

if printf '%s' "$warn" | jq -e '.hookSpecificOutput.updatedToolOutput' >/dev/null 2>&1; then
    no "--warn-only claims no power it lacks" "it emitted updatedToolOutput, which Codex ignores"
else
    ok "--warn-only claims no power it lacks"
fi

quiet="$(printf '{"tool_response":{"output":"md5 %s"}}' "$HEX" | bash "$TOOL" --warn-only)"
if [ "$quiet" = "" ]; then
    ok "--warn-only stays silent on a bare checksum"
else
    no "--warn-only stays silent on a bare checksum" "it warned about: $quiet"
fi

# ── the Opencode plugin must call this CLI, not reimplement it ──────────────
PLUGIN="$SRC/plugins/opencode/secrets-redact.ts"
if [ -f "$PLUGIN" ]; then
    # The binary name is resolved into a variable, because a plugin shell may
    # not carry ~/.local/bin on PATH — so match the `--filter` call itself
    # rather than the literal command name. What this asserts is unchanged:
    # the plugin delegates instead of carrying its own copy of the policy.
    if grep -qE '(secrets-redact|\$\{redact\}) --filter' "$PLUGIN"; then
        ok "the Opencode plugin delegates to the CLI with --filter"
    else
        no "the Opencode plugin delegates to the CLI" \
           "no '--filter' call in $PLUGIN — a second copy of the policy?"
    fi
    if grep -q 'tool.execute.after' "$PLUGIN"; then
        ok "the Opencode plugin hooks tool.execute.after"
    else
        no "the Opencode plugin hooks tool.execute.after" "wrong hook, or renamed"
    fi
else
    no "the Opencode plugin exists" "missing: $PLUGIN"
fi

# ── tier 1 must not drift away from safe-env ────────────────────────────────
# The provider patterns are duplicated rather than shared: both files are
# installed standalone onto PATH, and a shared include would be a third file
# to install and a new way for the pair to half-exist. Duplication is fine as
# long as something notices when the copies part.
if diff <(grep -E '^  RE = ' "$SRC/bin/safe-env") \
        <(grep -E '^  RE = ' "$TOOL") >/dev/null 2>&1; then
    ok "tier-1 patterns match bin/safe-env character for character"
else
    no "tier-1 patterns match bin/safe-env" \
       "the provider list has drifted; run: diff <(grep '^  RE = ' bin/safe-env) <(grep '^  RE = ' bin/secrets-redact)"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
