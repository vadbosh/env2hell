#!/usr/bin/env bash
# tests/test_parity.sh — the two redactors must answer the same thing.
#
#   bash tests/test_parity.sh
#
# bin/secrets-redact and bin/secrets-redact.ps1 implement the same decisions in
# two languages. tests/test_redact.sh runs the same cases against each, which
# catches a missing behaviour only when somebody wrote a case for it. This runs
# real text through both and diffs the answers, which catches the rest.
#
# Three defects found by doing exactly this by hand on 2026-09-16, before it
# was a test: the port never split its input into lines, the POSIX --filter
# added a byte the input did not have, and the POSIX warning counted lines
# instead of values. In each case one port was right and the other was wrong,
# and no single-port test could have said which.
#
# Nothing here writes outside its own temporary directory.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POSIX="$SRC/bin/secrets-redact"
PORT="$SRC/bin/secrets-redact.ps1"

[ -e "$POSIX" ] || { echo "not found: $POSIX" >&2; exit 2; }
[ -e "$PORT" ]  || { echo "not found: $PORT"  >&2; exit 2; }
if ! command -v pwsh >/dev/null 2>&1; then
    echo "pwsh is not installed — nothing to compare against" >&2
    exit 0
fi

pass=0
fail=0
ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "${tmp:?}"' EXIT

posix_filter () { "$POSIX" --filter; }
port_filter  () { pwsh -NoProfile -File "$PORT" --filter; }

# ── the corpora ─────────────────────────────────────────────────────────────
# Real machine output, because invented "ordinary text" comes out as prose and
# prose contains none of the shapes that collide with these patterns: no
# kebab-case names, no hashes, no paths, no version strings.
ls -la "$SRC" "$SRC/bin" "$SRC/tests" > "$tmp/c-ls" 2>&1
cat "$SRC/README.md" "$SRC/bin/secrets-guard" > "$tmp/c-source" 2>/dev/null
git -C "$SRC" log --oneline -40 > "$tmp/c-git" 2>/dev/null || : > "$tmp/c-git"

# And the shapes a secret actually takes, including the ones that were missed.
HEX='deadbeefdeadbeefdeadbeefdeadbeef'
{
    printf 'croc --relay h:9009 --pass %s code-word\n' "$HEX"
    printf 'md5sum: %s  big.bin\n' "$HEX"
    printf 'TOKEN: %s\n' "$HEX"
    printf 'HW_SECRET_KEY=%s\n' "$HEX"
    printf 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\n'
    printf 'password = "S3cr3t!Passw0rd#2026"\n'
    printf "PGPASSWORD='S3cr3t!Passw0rd#2026'\n"
    printf '{"password": "hunter2-hunter2-hunter2"}\n'
    printf 'output_tokens: usage.outputTokens,\n'
    printf '  --anthropic-api-key ANTHROPIC_API_KEY\n'
    printf 'settings.json.bak.20260915-224647\n'
    printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\n'
    printf 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt\n'
    printf -- '-----END OPENSSH PRIVATE KEY-----\n'
    printf 'ordinary line after the key\n'
} > "$tmp/c-shapes"

for corpus in ls source git shapes; do
    file="$tmp/c-$corpus"
    [ -s "$file" ] || continue
    posix_filter < "$file" > "$tmp/a-$corpus" 2>/dev/null
    port_filter  < "$file" > "$tmp/b-$corpus" 2>/dev/null
    if cmp -s "$tmp/a-$corpus" "$tmp/b-$corpus"; then
        ok "$corpus: both ports answer the same ($(wc -l < "$file") lines)"
    else
        no "$corpus: both ports answer the same" "
$(diff "$tmp/a-$corpus" "$tmp/b-$corpus" | head -12 | sed 's/^/        /')"
    fi
done

# ── the bytes at the edges ──────────────────────────────────────────────────
# Whether the result ends in a newline is a property of the input, and a mode
# that adds one is reformatting rather than redacting.
edge () {                               # edge <label> <printf-format>
    # shellcheck disable=SC2059  # the argument IS the format: these cases are
                                 # about which bytes are there at all
    printf "$2" > "$tmp/e-in"
    posix_filter < "$tmp/e-in" > "$tmp/e-a" 2>/dev/null
    port_filter  < "$tmp/e-in" > "$tmp/e-b" 2>/dev/null
    if cmp -s "$tmp/e-a" "$tmp/e-b"; then
        ok "edge: $1"
    else
        no "edge: $1" "posix $(wc -c < "$tmp/e-a") bytes, pwsh $(wc -c < "$tmp/e-b") bytes"
    fi
}

edge "no trailing newline"    "x --pass $HEX"
edge "a trailing newline"     "x --pass $HEX\n"
edge "CRLF"                   "x --pass $HEX\r\n"
edge "an empty line in the middle" "a\n\nx --pass $HEX\n"
edge "nothing to mask"        'plain text, no secret\n'
edge "utf-8 around a secret"  "ключ --pass $HEX конец\n"

# ── the hook replies ────────────────────────────────────────────────────────
# Compared by key set and by "was anything masked", not by text: the two emit
# their JSON keys in different order, and that is not a difference.
reply () {                              # reply <posix|pwsh> <payload file>
    if [ "$1" = posix ]; then "$POSIX" < "$2" 2>/dev/null
    else pwsh -NoProfile -File "$PORT" < "$2" 2>/dev/null; fi |
    jq -S -r 'try (.hookSpecificOutput
                   | "keys=\(keys|join(",")) event=\(.hookEventName // "none") "
                   + "masked=\((.updatedToolOutput|tostring)|test("REDACTED"))") // "no reply"'
}

for shape in streams file content string; do
    python3 - "$tmp/h.json" "$shape" <<'PY'
import json, sys
secret = "x --pass deadbeefdeadbeefdeadbeefdeadbeef"
resp = {"streams": {"stdout": secret, "stderr": ""},
        "file":    {"file": {"content": secret}},
        "content": {"content": secret},
        "string":  secret}[sys.argv[2]]
json.dump({"hook_event_name": "PostToolUse", "tool_name": "Bash",
           "tool_response": resp}, open(sys.argv[1], "w"))
PY
    a="$(reply posix "$tmp/h.json")"
    b="$(reply pwsh  "$tmp/h.json")"
    if [ "$a" = "$b" ]; then
        ok "hook reply: $shape"
    else
        no "hook reply: $shape" "posix [$a] pwsh [$b]"
    fi
done

# ── the warning ─────────────────────────────────────────────────────────────
# It is read by a human deciding whether to rotate a key, so the count matters
# as much as the fact.
GHP='ghp_0123456789abcdefghijklmnopqrstuvwxyzAB'
printf '{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"%s %s\\n%s"}}' \
    "$GHP" "$GHP" "$GHP" > "$tmp/w.json"
count () {                              # count <posix|pwsh>
    if [ "$1" = posix ]; then "$POSIX" --warn-only < "$tmp/w.json" 2>/dev/null
    else pwsh -NoProfile -File "$PORT" --warn-only < "$tmp/w.json" 2>/dev/null; fi |
    jq -r 'try (.hookSpecificOutput.additionalContext
                | capture("contains (?<n>[0-9]+) credential").n) // "none"'
}
a="$(count posix)"; b="$(count pwsh)"
if [ "$a" = "$b" ] && [ "$a" = 3 ]; then
    ok "the warning counts three values the same way in both"
else
    no "the warning counts the same in both" "posix=$a pwsh=$b, expected 3 in each"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
