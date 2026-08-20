#!/usr/bin/env bash
# Behaviour tests for safe-env: it must print the environment, and it must
# redact the values that look like secrets.
#
#   ./tests/test_safe_env.sh               test the copy in ../bin
#   ./tests/test_safe_env.sh --tool PATH   test an installed copy
#
# The first case is the one this file exists for. safe-env used to call `env`
# through PATH, and the uv installer writes a file of its own named `env` into
# ~/.local/bin — a PATH-setup snippet meant to be sourced. With ~/.local/bin
# first on PATH, safe-env ran that, printed nothing and exited 0. An empty
# answer from this tool reads like "no variables set", not like a broken tool,
# so nothing surfaced it. Asserting a non-empty result is what catches it.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$SRC/bin/safe-env"

while [ $# -gt 0 ]; do
    case "$1" in
        --tool) TOOL="${2:-}"; shift ;;
        -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -e "$TOOL" ] || { echo "safe-env not found: $TOOL" >&2; exit 2; }

pass=0
fail=0

ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

# The whole environment, whatever it is, must come back.
lines="$(bash "$TOOL" 2>/dev/null | wc -l)"
if [ "$lines" -gt 0 ]; then
    ok "prints the environment ($lines lines)"
else
    no "prints the environment" "printed nothing — is \`env\` being resolved through PATH?"
fi

# A planted secret must not appear in the output; a plain value must.
planted="$(MYTEST_TOKEN='ghp_0123456789abcdefghijklmnopqrstuvwxyzAB' \
           MYTEST_PLAIN='hello-world' bash "$TOOL" 2>/dev/null)"

if printf '%s' "$planted" | grep -q 'ghp_0123456789'; then
    no "masks a github token" "the raw value reached the output"
else
    ok "masks a github token"
fi

if printf '%s' "$planted" | grep -q '^MYTEST_TOKEN=<REDACTED:'; then
    ok "reports the masked variable by name"
else
    no "reports the masked variable by name" "MYTEST_TOKEN missing or not marked REDACTED"
fi

if printf '%s' "$planted" | grep -qx 'MYTEST_PLAIN=hello-world'; then
    ok "leaves a non-secret value alone"
else
    no "leaves a non-secret value alone" "MYTEST_PLAIN was altered or dropped"
fi

# A long hex string is a secret even without a recognisable prefix.
unprefixed="$(MYTEST_HEX='0123456789abcdef0123456789abcdef0123456789' \
              bash "$TOOL" 2>/dev/null)"
if printf '%s' "$unprefixed" | grep -q '^MYTEST_HEX=<REDACTED:'; then
    ok "masks an unprefixed high-entropy value"
else
    no "masks an unprefixed high-entropy value" "the hex run reached the output"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
