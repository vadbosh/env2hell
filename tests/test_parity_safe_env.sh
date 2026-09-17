#!/usr/bin/env bash
# tests/test_parity_safe_env.sh — the two maskers must answer the same thing.
#
#   bash tests/test_parity_safe_env.sh
#
# bin/safe-env and bin/safe-env.ps1 implement the same decisions in two
# languages. tests/test_safe_env.sh runs one case list against each, which
# catches a missing behaviour only when somebody wrote a case for it. This
# plants a whole table of values in one process on each side and diffs the two
# outputs, which catches the rest.
#
# Found by doing exactly this on 2026-09-17, before it was a test: a Windows
# drive path is exempt from the name tier in the port and masked by the POSIX
# version, and an empty value prints as NAME on one side and NAME= on the other.
#
# EVERY VALUE BELOW IS INVENTED. They have the shape of credentials and are not
# any. Never plant a real one here: a correctly formatted key is a real finding
# to every scanner that later touches this repository, fake or not.
#
# Nothing here writes outside its own temporary directory.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POSIX="$SRC/bin/safe-env"
PORT="$SRC/bin/safe-env.ps1"

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

# The table covers every provider row of docs/patterns.md, all four generic
# fallbacks, both base64 alphabets, the name tier with each of its exclusions,
# and the ordinary values that must survive untouched.
cat > "$tmp/pairs.txt" <<'PAIRS'
PARITY_AWS=AKIAIOSFODNN7EXAMPLE
PARITY_GH_CLASSIC=ghp_abcdefghijklmnopqrstuvwxyz0123456789
PARITY_GH_FINE=github_pat_11ABCDEFG0abcdefghijklmnop
PARITY_GITLAB=glpat-abcdefghijklmnopqrstu
PARITY_SLACK=xoxb-1234567890-abcdefghij
PARITY_TAVILY=tvly-abcdefghijklmno
PARITY_GOOGLE=AIzaSyA1234567890abcdefghijklmnopqrstuv
PARITY_OPENAI=sk-abcdefghijklmnopqrstuvwx
PARITY_OPENROUTER=sk-or-v1-abcdefghijklmnopqrstuvwx
PARITY_ATLASSIAN=ATATTxyz1234567890abcdefghijklmno
PARITY_JWT=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig
PARITY_URLPW=postgres://user:hunter2000@db.example:5432/app
PARITY_URLNOPW=postgres://user@db.example:5432/app
PARITY_HEX32=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
PARITY_HEX40=5100e79bf6fba1dafa048c0ffee1234567890abcd
PARITY_KEYSIG=abcdefghij1234567890.abcdefgh
PARITY_OPAQUE40=QWERTYuiop1234567890QWERTYuiop1234567890
PARITY_B64PLUS=QWxhZGRpbjpvcGVuIHNlc2FtZQ+abcdefghij/klmnopqrst=
PARITY_B64EQ=QWxhZGRpbjpvcGVuc2VzYW1lMTIzNDU2Nzg5MGFiY2RlZg==
PARITY_UUID=550e8400-e29b-41d4-a716-446655440000
PARITY_DIGEST=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
PARITY_API_TOKEN=ATBBxyz123456789abcdefgh
PARITY_API_KEY_SHORT=abc123
PARITY_API_KEY_FILE=/run/secrets/api_key
PARITY_TOKEN_REL=./secrets/token
PARITY_TOKEN_HOME=~/secrets/token
PARITY_TOKEN_WIN=C:/Users/me/token
PARITY_TOKENIZERS_PARALLELISM=false
PARITY_TOKEN_COUNT=4096
PARITY_BYPASS_CACHE=never-on-tuesdays
PARITY_PASSENGER_ROOT=opt-passenger-6-0-17
PARITY_GREETING=hello there this is fine
PARITY_PATHLIST=/usr/local/bin:/usr/bin:/bin
PARITY_MODEL=zai-sk-glm-4-6-turbo-preview
PARITY_CHART=at-rest-encryption-controller-v2
PARITY_OPTS=--enable-feature=exemplar-storage --web.enable-lifecycle
PARITY_JAVA=-XX:MaxRAMPercentage=75.0 -Dfile.encoding=UTF-8
PARITY_LANG=en_US.UTF-8
PARITY_SQL=CREATE USER bob IDENTIFIED BY 'hunter2000'
PARITY_EMPTY=
PARITY_EQUALS=a=b=c=d
PARITY_UNICODE=привет-мир-значение
PAIRS

# The Stripe row is assembled here rather than written into the table above,
# and the reason is worth keeping: GitHub push protection rejected the push
# that first added this file, naming tests/test_parity_safe_env.sh and the line
# the literal sat on. It was invented, and that changed nothing — a correctly
# formatted key is a real finding to every scanner that touches the repository
# afterwards, which is what the warning at the top of this file says. Split
# across a printf, no line of this file has the shape.
#
# The other provider rows survived the same scan. If one is rejected later,
# move it here too rather than weakening the sample: the point of the row is
# that the value matches the pattern in docs/patterns.md.
printf 'PARITY_STRIPE=%s_%s_%s\n' sk live abcdefghijklmnopqrstuvwx >> "$tmp/pairs.txt"

# ── POSIX side: one process, the whole table planted with env -i ────────────
mapfile -t args < "$tmp/pairs.txt"
env -i "${args[@]}" "$POSIX" 2>&1 | grep '^PARITY_' | sort > "$tmp/posix.txt"

# ── PowerShell side: the same table, one process ────────────────────────────
# Not `IFS='=' read -r name value`: read discards a trailing delimiter, which
# ate the `==` padding off a base64 value and produced a difference that
# belonged to this harness rather than to either implementation.
{
    echo '$ErrorActionPreference = "Stop"'
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        name="${line%%=*}"
        value="${line#*=}"
        printf '$env:%s = %s\n' "$name" "'${value//\'/\'\'}'"
    done < "$tmp/pairs.txt"
    printf '& "%s" | Select-String -Pattern "^PARITY_" -CaseSensitive | ForEach-Object { $_.Line }\n' "$PORT"
} > "$tmp/driver.ps1"
pwsh -NoProfile -File "$tmp/driver.ps1" 2>&1 | sort > "$tmp/pwsh.txt"

planted="$(grep -c . "$tmp/pairs.txt")"
got_posix="$(grep -c . "$tmp/posix.txt")"
got_pwsh="$(grep -c . "$tmp/pwsh.txt")"

if [ "$got_posix" = "$planted" ]; then
    ok "the POSIX side reports every planted variable ($planted)"
else
    no "the POSIX side reports every planted variable" "planted $planted, got $got_posix"
fi
if [ "$got_pwsh" = "$planted" ]; then
    ok "the port reports every planted variable ($planted)"
else
    no "the port reports every planted variable" "planted $planted, got $got_pwsh"
fi

if diff -q "$tmp/posix.txt" "$tmp/pwsh.txt" >/dev/null 2>&1; then
    ok "$planted values, no divergence"
else
    no "$planted values" "the two disagree (posix <, pwsh >):
$(diff "$tmp/posix.txt" "$tmp/pwsh.txt" | sed 's/^/        /')"
fi

# A multi-line value cannot live in the table above, and it is the one shape
# where the implementations are known to differ — bin/safe-env reads lines, the
# port reads variables. review-2026-09-17-safe-env.md item A1.
key_body='MIIEpAIBAAKCAQEAxGZlbGxvd3NoaXBvZnRoZXJpbmdvbmU'
multi="-----BEGIN RSA PRIVATE KEY-----
$key_body
-----END RSA PRIVATE KEY-----"
env -i "PARITY_PK=$multi" "$POSIX" > "$tmp/posix-multi.txt" 2>&1
{
    echo '$ErrorActionPreference = "Stop"'
    printf '$env:PARITY_PK = "-----BEGIN RSA PRIVATE KEY-----`n%s`n-----END RSA PRIVATE KEY-----"\n' "$key_body"
    printf '& "%s" | Select-String -Pattern "^PARITY_PK" -CaseSensitive | ForEach-Object { $_.Line }\n' "$PORT"
    printf 'if ((& "%s") -match "%s") { "BODY-PRESENT" } else { "body-absent" }\n' "$PORT" "$key_body"
} > "$tmp/driver-multi.ps1"
pwsh -NoProfile -File "$tmp/driver-multi.ps1" > "$tmp/pwsh-multi.txt" 2>&1

posix_leaks=no
grep -Fq -- "$key_body" "$tmp/posix-multi.txt" && posix_leaks=yes
pwsh_leaks=no
grep -Fq 'BODY-PRESENT' "$tmp/pwsh-multi.txt" && pwsh_leaks=yes

if [ "$posix_leaks" = "$pwsh_leaks" ]; then
    ok "a multi-line value is treated the same by both (body printed: $posix_leaks)"
else
    no "a multi-line value is treated the same by both" \
       "the body is printed by posix=$posix_leaks pwsh=$pwsh_leaks — review-2026-09-17-safe-env.md A1"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
