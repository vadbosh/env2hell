#!/usr/bin/env bash
# tests/test_parity_guard.sh — the two guards must answer the same thing.
#
#   bash tests/test_parity_guard.sh
#
# bin/secrets-guard and bin/secrets-guard.ps1 implement the same decisions in
# two languages, and the port's own header says so: "policy is kept identical to
# the POSIX version on purpose". tests/test_guard.sh runs one case list against
# each, which catches a missing behaviour only when somebody wrote a case for
# it. This builds its corpus from the project's own documentation and scripts
# instead, which catches the rest.
#
# Found by doing exactly this on 2026-09-17, before it was a test: the port
# split pass A on separators and not on newlines, so a dump on the second line
# of a two-line command went through on Windows — and, in the other direction,
# the reader on one line and a secret path on another counted as one
# sub-command, which denied the rsync-with-an-identity-file case and the
# commit-message case that the suite pins as must-pass. 357 single-line
# commands diverged on nothing; every multi-line shape diverged.
#
# The verdict is taken from the EXIT STATUS and never from the text: a session
# running these has its own redactor rewriting terminal output.
#
# The port runs through tests/pwsh_batch.ps1 — one pwsh process for the whole
# corpus instead of one per case, which is six minutes against seconds. The
# first group below re-checks that the batched route agrees with a plain
# `pwsh -File` run, because a harness that lies about verdicts is the exact
# failure class this test exists to catch.
#
# Nothing here writes outside its own temporary directory.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$SRC/bin/secrets-guard"
PORT="$SRC/bin/secrets-guard.ps1"
BATCH="$SRC/tests/pwsh_batch.ps1"

for f in "$GUARD" "$PORT" "$BATCH"; do
    [ -e "$f" ] || { echo "not found: $f" >&2; exit 2; }
done
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

# payload <command-string> — one line of JSON, appended to the payload file
payload () {
    # The python program is single-quoted on purpose: its $ and quotes belong to
    # python, not to the shell.
    # shellcheck disable=SC2016
    printf '%s' "$1" | python3 -c \
        'import json,sys; print(json.dumps({"tool_input":{"command":sys.stdin.read()}}))'
}

# posix_run <payload-file> — one exit code per line, in order
posix_run () {
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        printf '%s' "$p" | "$GUARD" >/dev/null 2>&1
        echo $?
    done < "$1"
}

# port_run <payload-file> — the same, from a single pwsh process
port_run () {
    pwsh -NoProfile -File "$BATCH" "$PORT" "$1" 2>/dev/null
}

# ── the batched route has to agree with a plain one ─────────────────────────
# Cheap, and it is the assumption everything below rests on.
: > "$tmp/sanity.txt"
for c in 'ls -la' 'env' 'cat .env' 'cat README.md' 'printenv PATH'; do
    payload "$c" >> "$tmp/sanity.txt"
done
port_run "$tmp/sanity.txt" > "$tmp/sanity-batched.txt"
: > "$tmp/sanity-plain.txt"
while IFS= read -r p; do
    printf '%s' "$p" | pwsh -NoProfile -File "$PORT" >/dev/null 2>&1
    echo $? >> "$tmp/sanity-plain.txt"
done < "$tmp/sanity.txt"
if diff -q "$tmp/sanity-batched.txt" "$tmp/sanity-plain.txt" >/dev/null 2>&1; then
    ok "the batched port run agrees with pwsh -File, case for case"
else
    no "the batched port run agrees with pwsh -File" \
       "everything below is unreliable until this passes:
$(diff "$tmp/sanity-batched.txt" "$tmp/sanity-plain.txt" | sed 's/^/        /')"
fi

# ── the named cases ─────────────────────────────────────────────────────────
labels=()
: > "$tmp/named.txt"
add () {                        # add <label> <command-string>
    labels+=("$1")
    payload "$2" >> "$tmp/named.txt"
}

# A line-based corpus cannot ask these, which is how the defect above survived.
add 'dump on the second line'            $'ls -la\nenv'
add 'dump after a wrapper, second line'  $'cd /tmp\nsudo env'
add 'backslash continuation into a dump' $'echo hi && \\\nenv'
add 'read on the second line'            $'ls -la\ncat .env'
add 'a pipeline broken over two lines'   $'git log --oneline |\n  head -20'
add 'a heredoc body holding env'         $'cat > /tmp/c.txt <<CASES\nenv\nprintenv\nCASES'
add 'a heredoc body holding cat .env'    $'cat > /tmp/n.md <<EOF\nThen run cat .env to see it.\nEOF'
add 'a quote opened on one line'         $'echo "start\nstill inside" && cat .env'
add 'credential print on line two'       $'cd /tmp\necho "$HW_SECRET_KEY"'
add 'a template on line two'             $'cd /tmp\nprintf %s '\''key: ${secret_name}'\'''
# The reader on one line, the secret path on another. Denying these is the
# failure the `rsync -e "ssh -i …pem" … | head` incident bought locality for.
add 'key on one line, reader on the next' $'ssh -i ~/.ssh/id.pem host uptime\nhead -5 report.txt'
add 'rsync key, reader on the next line'  $'rsync -e "ssh -i ~/.ssh/id.pem" a b\ncat report.txt'
add 'commit message, reader next line'    $'git commit -m "docs: cat .env ends the same way"\nhead -5 CHANGELOG.md'

mapfile -t posix_rc < <(posix_run "$tmp/named.txt")
mapfile -t port_rc  < <(port_run  "$tmp/named.txt")

echo
echo "multi-line commands and locality across a newline"
for i in "${!labels[@]}"; do
    a="${posix_rc[$i]:-<none>}"
    b="${port_rc[$i]:-<none>}"
    if [ "$a" = "$b" ]; then
        ok "${labels[$i]} (exit $a)"
    else
        no "${labels[$i]}" "posix=$a pwsh=$b"
    fi
done

# ── the project's own text, as a corpus ─────────────────────────────────────
# Real command lines, because invented "ordinary text" comes out as prose and
# prose contains none of the shapes that collide with these patterns. Reported
# as one case: three hundred identical `ok` lines would bury everything above.
echo
echo "the project's own command lines"
awk '/^```/ { b = !b; next } b && $0 !~ /^[[:space:]]*$/ && $0 !~ /^[[:space:]]*#/ { print }' \
    "$SRC/README.md" "$SRC"/docs/*.md > "$tmp/corpus.txt"
grep -hv -e '^[[:space:]]*$' -e '^[[:space:]]*#' \
    "$SRC/install.sh" "$SRC/uninstall.sh" "$SRC/release.sh" "$SRC/bin/safe-env" \
    >> "$tmp/corpus.txt"
sort -u "$tmp/corpus.txt" -o "$tmp/corpus.txt"

: > "$tmp/corpus-payloads.txt"
while IFS= read -r line; do
    [ -z "$line" ] && continue
    payload "$line" >> "$tmp/corpus-payloads.txt"
done < "$tmp/corpus.txt"

posix_run "$tmp/corpus-payloads.txt" > "$tmp/corpus-posix.txt"
port_run  "$tmp/corpus-payloads.txt" > "$tmp/corpus-port.txt"

total="$(grep -c . "$tmp/corpus.txt")"
if diff -q "$tmp/corpus-posix.txt" "$tmp/corpus-port.txt" >/dev/null 2>&1; then
    ok "$total real command lines, no divergence"
else
    # paste the three together so the report names the command, not a line number
    no "$total real command lines" "the two disagree:
$(paste "$tmp/corpus-posix.txt" "$tmp/corpus-port.txt" "$tmp/corpus.txt" \
    | awk -F'\t' '$1 != $2 { printf "        posix=%s pwsh=%s  %s\n", $1, $2, $3 }')"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
