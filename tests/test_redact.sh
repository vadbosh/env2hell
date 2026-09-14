#!/usr/bin/env bash
# Behaviour tests for secrets-redact: the PostToolUse half of the pair.
#
#   ./tests/test_redact.sh               test the copy in ../bin
#   ./tests/test_redact.sh --pwsh        test the PowerShell port instead
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
RUNNER="bash"
PORT="posix"

while [ $# -gt 0 ]; do
    case "$1" in
        --pwsh) TOOL="$SRC/bin/secrets-redact.ps1"
                RUNNER="pwsh -NoProfile -File"; PORT="pwsh" ;;
        --tool) TOOL="${2:-}"; shift ;;
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -e "$TOOL" ] || { echo "secrets-redact not found: $TOOL" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "these tests need jq" >&2; exit 2; }

# $RUNNER is a command plus its flags and has to split into words.
# shellcheck disable=SC2086
run_tool () { $RUNNER "$TOOL" "$@"; }

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
        run_tool | jq -j 'try (.hookSpecificOutput.updatedToolOutput.stdout // empty)'
}

# ── what must be masked ─────────────────────────────────────────────────────
got="$(hook_out "croc --relay h:9009 --pass $HEX code-word")"
if grep -q "$HEX" <<< "$got"; then
    no "masks a labelled password" "the raw value reached the output"
else
    ok "masks a labelled password"
fi

if grep -q -- '--pass <REDACTED:32>' <<< "$got"; then
    ok "keeps the label so the model can see what was removed"
else
    no "keeps the label" "expected '--pass <REDACTED:32>', got: $got"
fi

# A silent hook is not a masked value. hook_out prints nothing when the hook
# declines to replace anything, so "the raw value is not in this empty string"
# scored as a pass — and two real defects sat behind that green for months:
#
#   TOKEN: 6310…      never masked at all. awk matches case-sensitively and the
#                     label list is lower case, so only `token:` was caught —
#                     while uppercase is how a token appears in an env dump, a
#                     config echo, or a CI log.
#   password=6310…    masked together with its label, as <REDACTED:41>. VALUE
#                     admits `=`, so the old "value is the longest suffix"
#                     reading swallowed `password=` too.
#
# Assert all three things: a replacement was issued, the value is gone, and the
# label survived it. Any one of them alone can pass on a broken hook.
check_labelled () {                     # <line> <label that must survive>
    local line="$1" label="$2" out
    out="$(hook_out "$line")"
    if [ -z "$out" ]; then
        no "masks $label" "the hook issued no replacement at all"
    elif grep -q "$HEX" <<< "$out"; then
        no "masks $label" "the raw value reached the output"
    elif ! grep -qF -- "$label" <<< "$out"; then   # `--` or `--token` is a flag
        no "masks $label" "the label was masked along with the value: $out"
    else
        ok "masks $label, keeping the label readable"
    fi
}

check_labelled "password=$HEX"  'password='
check_labelled "TOKEN: $HEX"    'TOKEN:'
check_labelled "Token: $HEX"    'Token:'
check_labelled "TOKEN=$HEX"     'TOKEN='
check_labelled "--token $HEX"   '--token'
check_labelled "--PASS $HEX"    '--PASS'
check_labelled "api_key=$HEX"   'api_key='

# Cloud keys with no provider prefix. Tier 1 could never take them by shape:
# 20 uppercase characters or 40 of base62 also describe a git SHA and half the
# identifiers in ordinary output. The variable name is the only signal, so it
# has to be in the label list — and these names are written in upper case
# everywhere they appear, which is what made the case bug expensive.
check_labelled "HW_ACCESS_KEY=$HEX"          'HW_ACCESS_KEY='
check_labelled "HW_SECRET_KEY: $HEX"         'HW_SECRET_KEY:'
check_labelled "OS_SECRET_KEY=$HEX"          'OS_SECRET_KEY='
check_labelled "HUAWEICLOUD_SECRET_KEY=$HEX" 'HUAWEICLOUD_SECRET_KEY='

# The counterpart: a bare SHA must still come through, or every `git rev-parse`
# in the session turns into <REDACTED:40>.
if [ "$(hook_out "$SHA")" = "" ] || [ "$(hook_out "$SHA")" = "$SHA" ]; then
    ok "leaves a bare git SHA alone"
else
    no "leaves a bare git SHA alone" "got: $(hook_out "$SHA")"
fi

if grep -q 'ghp_0123456789' <<< "$(hook_out "export GH=$GHP")"; then
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
' ] || grep 'n' <<< "$with_nl" >/dev/null; then
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
full="$(printf '{"tool_response":{"stdout":"--pass %s","stderr":"","interrupted":true,"isImage":false}}' "$HEX" | run_tool)"
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
if [ "$(printf '{"tool_response":{"filePath":"/etc/hosts"}}' | run_tool)" = "" ]; then
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
bare="$(printf '{"tool_response":"Exit code 1\\nhttps://oauth2:%s@example/x.git\\n"}' "$GLPAT" | run_tool)"
if printf '%s' "$bare" | jq -r '.hookSpecificOutput.updatedToolOutput' 2>/dev/null | grep "$GLPAT" >/dev/null; then
    no "masks a bare-string tool_response" "the raw token reached the output"
elif printf '%s' "$bare" | jq -re '.hookSpecificOutput.updatedToolOutput' 2>/dev/null | grep '<REDACTED:' >/dev/null; then
    ok "masks a bare-string tool_response"
else
    no "masks a bare-string tool_response" "no replacement was produced at all"
fi

if printf '%s' "$bare" | jq -e '(.hookSpecificOutput.updatedToolOutput | type) == "string"' >/dev/null 2>&1; then
    ok "rebuilds a string result as a string, not as an object"
else
    no "rebuilds a string result as a string" "the schema of the result was changed"
fi

blob="$(printf '{"tool_response":{"is_error":true,"content":"https://oauth2:%s@example/x.git"}}' "$GLPAT" | run_tool)"
if printf '%s' "$blob" | jq -r '.hookSpecificOutput.updatedToolOutput.content' 2>/dev/null | grep "$GLPAT" >/dev/null; then
    no "masks a {content:…} tool_response" "the raw token reached the output"
elif printf '%s' "$blob" | jq -re '.hookSpecificOutput.updatedToolOutput.content' 2>/dev/null | grep '<REDACTED:' >/dev/null; then
    ok "masks a {content:…} tool_response"
else
    no "masks a {content:…} tool_response" "no replacement was produced at all"
fi

if printf '%s' "$blob" | jq -e '.hookSpecificOutput.updatedToolOutput.is_error == true' >/dev/null 2>&1; then
    ok "carries unrelated fields through on the content shape too"
else
    no "carries unrelated fields through on the content shape" "is_error was dropped"
fi

if [ "$(printf '{"tool_response":"nothing secret here\\n"}' | run_tool)" = "" ]; then
    ok "leaves a clean bare-string result alone"
else
    no "leaves a clean bare-string result alone" "it rewrote output with no secret in it"
fi

read_shape="$(printf '{"tool_response":{"type":"text","file":{"filePath":"/tmp/x.env","totalLines":1,"content":"GITLAB=%s\\n"}}}' "$GLPAT" | run_tool)"
if printf '%s' "$read_shape" | jq -r '.hookSpecificOutput.updatedToolOutput.file.content' 2>/dev/null | grep "$GLPAT" >/dev/null; then
    no "masks the Read tool's {file:{content}} result" "the raw token reached the output"
elif printf '%s' "$read_shape" | jq -re '.hookSpecificOutput.updatedToolOutput.file.content' 2>/dev/null | grep '<REDACTED:' >/dev/null; then
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
          run_tool | jq -r '.hookSpecificOutput.updatedToolOutput.stdout // empty' 2>/dev/null)"
if [ -z "$bigout" ]; then
    no "masks a 200 KB stdout" "the hook produced no replacement — it failed open on size"
elif grep -q "$GHP" <<< "$bigout"; then
    no "masks a 200 KB stdout" "the raw value reached the output"
else
    ok "masks a 200 KB stdout — past the 128 KB argument limit"
fi

warned="$(printf '{"tool_response":"https://oauth2:%s@example/x.git"}' "$GLPAT" | run_tool --warn-only)"
if grep -q "$GLPAT" <<< "$warned"; then
    no "--warn-only never repeats the value" "the token is in the warning"
elif printf '%s' "$warned" | jq -re '.hookSpecificOutput.additionalContext' 2>/dev/null | grep 'credential-shaped' >/dev/null; then
    ok "--warn-only reports a bare-string result"
else
    no "--warn-only reports a bare-string result" "no warning was produced"
fi

# ── failing open ────────────────────────────────────────────────────────────
# /bin/bash by absolute path: `PATH=/nonexistent bash` would fail to find bash
# itself and report 127, which looks exactly like the failure being tested for.
# Nothing external runs before the jq check, so an empty PATH is enough.
# POSIX only: the PowerShell port parses JSON with ConvertFrom-Json and masks
# with .NET regex, so it has neither dependency to lose.
if [ "$PORT" = posix ]; then
    nojq="$(PATH=/nonexistent /bin/bash "$TOOL" <<<'{"tool_response":{"stdout":"--pass '"$HEX"'"}}' 2>/dev/null; printf 'rc=%s' "$?")"
    if [ "$nojq" = "rc=0" ]; then
        ok "fails open when jq is unavailable"
    else
        no "fails open when jq is unavailable" "got [$nojq], expected a silent rc=0"
    fi
fi

if [ "$(printf '' | run_tool; printf 'rc=%s' "$?")" = "rc=0" ]; then
    ok "fails open on empty input"
else
    no "fails open on empty input" "it did not exit 0 silently"
fi

# ── --filter: the plain-text mode the Opencode plugin uses ──────────────────
# The plugin skips the assignment when nothing changed, so the exit status is
# part of the contract, not a detail: 0 masked, 1 untouched.
filtered="$(printf 'croc --pass %s x\n' "$HEX" | run_tool --filter; printf 'rc=%s' "$?")"
if [ "$filtered" = "$(printf 'croc --pass <REDACTED:32> x\nrc=0')" ]; then
    ok "--filter masks and reports exit 0"
else
    no "--filter masks and reports exit 0" "got: $filtered"
fi

untouched="$(printf 'md5 %s\n' "$HEX" | run_tool --filter; printf 'rc=%s' "$?")"
if [ "$untouched" = "$(printf 'md5 %s\nrc=1' "$HEX")" ]; then
    ok "--filter passes a checksum through and reports exit 1"
else
    no "--filter passes a checksum through and reports exit 1" "got: $untouched"
fi

# --filter is the mode that must work on a machine without jq: the plugin runs
# it directly, with no JSON on either side.
if [ "$PORT" = posix ]; then
    nojq_filter="$(printf 'x --pass %s\n' "$HEX" |
                   PATH="/usr/bin:/bin" /bin/bash "$TOOL" --filter 2>/dev/null)"
    if grep -q 'REDACTED' <<< "$nojq_filter"; then
        ok "--filter needs no jq"
    else
        no "--filter needs no jq" "got: $nojq_filter"
    fi
fi

# ── PostToolUseFailure: the one path where masking is impossible ────────────
# A command that exits non-zero does not fire PostToolUse in Claude Code. It
# fires PostToolUseFailure, whose output is a top-level `error` string — first
# line `Exit code N`, then stdout and stderr interleaved — and whose only
# documented return field is `additionalContext`. There is no slot for a
# replacement, so the value is in the transcript before any hook sees it.
#
# That is the path the GitLab token took on 2026-09-14. All the warning can do
# is make the leak loud enough to be rotated, and the two things it must get
# right are asserted here: it has to notice, and it has to name the event back
# as it arrived — a hook that answers "PostToolUse" to a failure event is
# answering a question nobody asked, and the reply is dropped.
# `\\n`, not `\n`: printf would turn the latter into a real newline inside the
# JSON string, the payload would be invalid JSON, and the hook would fail open —
# the test would then pass for the wrong reason, on a hook that never looked.
fail_payload="$(printf '{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","error":"Exit code 1\\nurl https://oauth2:%s@gitlab.example/x.git\\n"}' "$GLPAT")"
failwarn="$(printf '%s' "$fail_payload" | run_tool --warn-only)"

if printf '%s' "$failwarn" | jq -e '.hookSpecificOutput.additionalContext' >/dev/null 2>&1; then
    ok "--warn-only notices a credential in a PostToolUseFailure error string"
else
    no "--warn-only notices a credential in a failure error string" "got: $failwarn"
fi

if printf '%s' "$failwarn" | jq -e '.hookSpecificOutput.hookEventName == "PostToolUseFailure"' >/dev/null 2>&1; then
    ok "names the failure event back as it arrived"
else
    no "names the failure event back as it arrived" \
       "got: $(printf '%s' "$failwarn" | jq -r '.hookSpecificOutput.hookEventName // "<none>"')"
fi

if grep -q "$GLPAT" <<< "$failwarn"; then
    no "the failure warning never repeats the value" "the token is in the warning"
else
    ok "the failure warning never repeats the value"
fi

if [ -z "$(printf '{"hook_event_name":"PostToolUseFailure","error":"Exit code 1\\nfile not found\\n"}' | run_tool --warn-only)" ]; then
    ok "stays silent on a failure with no credential in it"
else
    no "stays silent on a failure with no credential in it" "it warned about nothing"
fi

# ── --warn-only: what an assistant that cannot replace output gets ──────────
# Codex names the shell result `output`, Claude Code splits it into stdout and
# stderr; the warning path reads all three, so the Codex shape is the one worth
# asserting — it is the shape the other modes never see.
warn="$(printf '{"tool_response":{"output":"croc --pass %s code"}}' "$HEX" | run_tool --warn-only)"

if printf '%s' "$warn" | jq -e '.hookSpecificOutput.additionalContext' >/dev/null 2>&1; then
    ok "--warn-only reports through additionalContext"
else
    no "--warn-only reports through additionalContext" "got: $warn"
fi

# The whole point is a warning that does not repeat what it is warning about.
if grep -q "$HEX" <<< "$warn"; then
    no "--warn-only never repeats the value" "the secret is in the warning itself"
else
    ok "--warn-only never repeats the value"
fi

if printf '%s' "$warn" | jq -e '.hookSpecificOutput.updatedToolOutput' >/dev/null 2>&1; then
    no "--warn-only claims no power it lacks" "it emitted updatedToolOutput, which Codex ignores"
else
    ok "--warn-only claims no power it lacks"
fi

quiet="$(printf '{"tool_response":{"output":"md5 %s"}}' "$HEX" | run_tool --warn-only)"
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
# The PowerShell pair carries the same list in its own syntax, so the
# comparison is between the two .ps1 files there, not across languages.
if [ "$PORT" = pwsh ]; then
    peer="$SRC/bin/safe-env.ps1"
    strip () { sed -n "/^\\\$patterns = @(/,/^)/p" "$1" | sed 's/[[:space:]]*#.*//; s/^[[:space:]]*//; /^$/d'; }
else
    peer="$SRC/bin/safe-env"
    strip () { grep -E '^  RE = ' "$1"; }
fi
if diff <(strip "$peer") <(strip "$TOOL") >/dev/null 2>&1; then
    ok "tier-1 patterns match ${peer##*/} character for character"
else
    no "tier-1 patterns match bin/safe-env" \
       "the provider list has drifted; run: diff <(grep '^  RE = ' bin/safe-env) <(grep '^  RE = ' bin/secrets-redact)"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
