#!/usr/bin/env bash
# tests/test_scan.sh — tools/scan-transcripts.
#
# The scanner reports leaks to the person who has to rotate them, which makes
# two of its properties load-bearing rather than nice to have: it must not
# print the value it is reporting, and its exit status must be usable without
# parsing the output. Both are checked here.
#
#   bash tests/test_scan.sh              scan the copy in this checkout
#   bash tests/test_scan.sh --installed  the one on PATH
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$SRC/tools/scan-transcripts"

while [ $# -gt 0 ]; do
    case "$1" in
        --installed) TOOL="$(command -v scan-transcripts || echo /nonexistent)" ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -x "$TOOL" ] || { echo "scan-transcripts not found: $TOOL" >&2; exit 2; }

pass=0
fail=0
ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

GLPAT='glpat-0123456789abcdefghijklmnopqrstuvwx'
HEX='deadbeefdeadbeefdeadbeefdeadbeef'

tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "$tmp"' EXIT

printf 'ordinary line\nGITLAB_TOKEN=%s\nmd5sum: %s  big.bin\n' "$GLPAT" "$HEX" > "$tmp/session.jsonl"
printf 'nothing to see here\n' > "$tmp/clean.jsonl"
printf '{"token":"%s"}\n' "$GLPAT" > "$tmp/auth.json"

run () { "$TOOL" --path "$tmp" "$@" 2>&1; }

# ── it finds what is there ──────────────────────────────────────────────────
out="$(run)"
if grep -q 'session.jsonl' <<< "$out"; then
    ok "names the file holding a credential"
else
    no "names the file holding a credential" "session.jsonl is not in the report"
fi

if grep -q '<REDACTED:' <<< "$out"; then
    ok "shows the finding as a masked excerpt"
else
    no "shows the finding as a masked excerpt" "no <REDACTED:> marker in the report"
fi

# ── and never repeats it ────────────────────────────────────────────────────
# The whole point. A report that quotes the secret has leaked it a second time,
# into the transcript of whoever ran the scan.
for m in "" --quiet --files; do
    if grep -q "$GLPAT" <<< "$(run $m)"; then
        no "never prints the raw value (${m:---full})" "the token is in the output"
    else
        ok "never prints the raw value (${m:---full})"
    fi
done

# ── what must not be reported ───────────────────────────────────────────────
if grep -q 'clean.jsonl' <<< "$out"; then
    no "leaves a file with no credential out of the report" "clean.jsonl was reported"
else
    ok "leaves a file with no credential out of the report"
fi

if grep -q "$HEX" <<< "$out"; then
    no "does not treat a checksum as a credential" "the md5 was reported"
else
    ok "does not treat a checksum as a credential"
fi

# ── token stores ────────────────────────────────────────────────────────────
# auth.json holds a credential because that is its job. A standing entry in
# every report is how a report stops being read.
# The path, not the bare name: the summary line explaining the skip says
# "auth.json" too, and matching that would pass on a scanner that skips nothing.
if grep -q "$tmp/auth.json" <<< "$out"; then
    no "skips an assistant's own token store by default" "auth.json was reported"
else
    ok "skips an assistant's own token store by default"
fi

if grep -q 'token store(s) skipped' <<< "$out"; then
    ok "says that a store was skipped rather than hiding it"
else
    no "says that a store was skipped" "the skip was silent"
fi

if grep -q "$tmp/auth.json" <<< "$(run --include-stores)"; then
    ok "--include-stores scans the token stores too"
else
    no "--include-stores scans the token stores" "auth.json is still missing"
fi

# ── exit status is the interface ────────────────────────────────────────────
# So it fits a cron line or a CI step with no output parsing at all.
run >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 1 ]; then
    ok "exits 1 when there are findings"
else
    no "exits 1 when there are findings" "got $rc"
fi

mkdir -p "$tmp/empty"
printf 'all clear\n' > "$tmp/empty/x.jsonl"
"$TOOL" --path "$tmp/empty" >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 0 ]; then
    ok "exits 0 when there is nothing to report"
else
    no "exits 0 when there is nothing to report" "got $rc"
fi

# A copy with no ../bin beside it and a HOME that holds nothing: the three
# places the scanner looks all come up empty. Emptying PATH instead would test
# the shebang, not the scanner — `env` would fail to find bash and report 127.
mkdir -p "$tmp/isolated" "$tmp/nohome"
cp "$TOOL" "$tmp/isolated/scan-transcripts"
SECRETS_REDACT=/nonexistent HOME="$tmp/nohome" \
    "$tmp/isolated/scan-transcripts" --path "$tmp" >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then
    ok "exits 2 when it cannot find secrets-redact"
else
    no "exits 2 when it cannot find secrets-redact" "got $rc — a broken scan must not read as clean"
fi

# ── modes ───────────────────────────────────────────────────────────────────
if [ "$(run --files | grep -c 'session.jsonl')" -eq 1 ] &&
   [ "$(run --files | grep -c '<REDACTED:')" -eq 0 ]; then
    ok "--files prints names only"
else
    no "--files prints names only" "it printed excerpts or lost the file name"
fi

if grep -q 'line(s) with a credential' <<< "$(run --quiet)"; then
    ok "--quiet prints per-file counts"
else
    no "--quiet prints per-file counts" "no count line"
fi

# ── a mistake is not a clean result ─────────────────────────────────────────
# A path that is not there used to print "scanned 0 file(s)" and exit 0, which
# reads exactly like a machine with nothing on it.
"$TOOL" --path /nonexistent-path-for-the-test >/dev/null 2>&1
if [ $? -eq 2 ]; then
    ok "a missing --path exits 2, not 0"
else
    no "a missing --path exits 2" "a typo reads as a clean machine"
fi

empty_dir="$(mktemp -d)"
"$TOOL" --path "$empty_dir" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    ok "an existing but empty directory is still exit 0"
else
    no "an empty directory exits 0" "it reported an error"
fi

# ── a newline in a filename ─────────────────────────────────────────────────
# find without -print0 split one name into two: the file was skipped, its
# credential never reported, and the error landed among the findings.
nl_dir="$(mktemp -d)"
printf 'x --token abcdefghijklmnopqrstuvwx\n' > "$nl_dir/$(printf 'a\nb').jsonl"
if [ "$("$TOOL" --files --path "$nl_dir" 2>/dev/null | wc -l)" -ge 1 ]; then
    ok "a filename containing a newline is scanned"
else
    no "a filename containing a newline is scanned" "the file was skipped"
fi

# ── both truncations announce themselves ────────────────────────────────────
many_dir="$(mktemp -d)"
i=0; while [ $i -lt 25 ]; do
    printf 'line%d --token abcdefghijklmnopqrstu%03d\n' "$i" "$i" >> "$many_dir/many.jsonl"
    i=$((i + 1))
done
many_out="$("$TOOL" --path "$many_dir" 2>/dev/null)"
if grep -q 'and 5 more in this file' <<< "$many_out"; then
    ok "says how many excerpts it did not print"
else
    no "says how many excerpts it did not print" "the count and the list disagree in silence"
fi

# ── the patterns are not duplicated ─────────────────────────────────────────
# Detection has to go through secrets-redact, or the scanner drifts from the
# guard and reports clean on whatever the guard has learned since.
if grep -q 'REDACT" --filter' "$TOOL"; then
    ok "detects through secrets-redact --filter, not a copy of the patterns"
else
    no "detects through secrets-redact --filter" \
       "the scanner has its own detection; it will drift from bin/secrets-redact"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
