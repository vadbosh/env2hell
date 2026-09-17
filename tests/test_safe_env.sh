#!/usr/bin/env bash
# Behaviour tests for safe-env: it must print the environment, and it must
# redact the values that look like secrets.
#
#   ./tests/test_safe_env.sh               test the copy in ../bin
#   ./tests/test_safe_env.sh --pwsh        test the PowerShell port instead
#   ./tests/test_safe_env.sh --tool PATH   test an installed copy
#
# The PowerShell port had no suite of its own until 2026-09-14, and that is
# exactly how `secrets-guard.ps1` drifted: it lost the command-substitution pass
# the POSIX guard had, denied a working command, and nothing ran to notice.
# Running the same cases against both is the only thing that keeps two
# implementations of one rule in step.
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
RUNNER="bash"

while [ $# -gt 0 ]; do
    case "$1" in
        --pwsh) TOOL="$SRC/bin/safe-env.ps1"; RUNNER="pwsh -NoProfile -File" ;;
        --tool) TOOL="${2:-}"; shift ;;
        -h|--help) sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -e "$TOOL" ] || { echo "safe-env not found: $TOOL" >&2; exit 2; }

# $RUNNER is a command plus its flags and has to split into words.
# shellcheck disable=SC2086
run_tool () { $RUNNER "$TOOL"; }

pass=0
fail=0

ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

# The whole environment, whatever it is, must come back.
lines="$(run_tool 2>/dev/null | wc -l)"
if [ "$lines" -gt 0 ]; then
    ok "prints the environment ($lines lines)"
else
    no "prints the environment" "printed nothing — is \`env\` being resolved through PATH?"
fi

# A planted secret must not appear in the output; a plain value must.
planted="$(MYTEST_TOKEN='ghp_0123456789abcdefghijklmnopqrstuvwxyzAB' \
           MYTEST_PLAIN='hello-world' run_tool 2>/dev/null)"

if grep -q 'ghp_0123456789' <<< "$planted"; then
    no "masks a github token" "the raw value reached the output"
else
    ok "masks a github token"
fi

if grep -q '^MYTEST_TOKEN=<REDACTED:' <<< "$planted"; then
    ok "reports the masked variable by name"
else
    no "reports the masked variable by name" "MYTEST_TOKEN missing or not marked REDACTED"
fi

# The failure message carries what was actually seen. This assertion failed
# once, on 2026-09-14, in a session whose environment is no longer reachable,
# and "altered or dropped" was not enough to tell the two apart: a masked line
# and a missing line are different bugs with different causes, and the CRED
# name list cannot match MYTEST_PLAIN at all, so neither reading was obvious.
# Report the line, or its absence, rather than the verdict alone.
if grep -qx 'MYTEST_PLAIN=hello-world' <<< "$planted"; then
    ok "leaves a non-secret value alone"
else
    seen="$(printf '%s' "$planted" | grep '^MYTEST_PLAIN=' || true)"
    no "leaves a non-secret value alone" \
       "expected the exact line MYTEST_PLAIN=hello-world; got ${seen:-<no MYTEST_PLAIN line at all>} out of $(printf '%s' "$planted" | grep -c .) lines"
fi

# A long hex string is a secret even without a recognisable prefix.
unprefixed="$(MYTEST_HEX='0123456789abcdef0123456789abcdef0123456789' \
              run_tool 2>/dev/null)"
if grep -q '^MYTEST_HEX=<REDACTED:' <<< "$unprefixed"; then
    ok "masks an unprefixed high-entropy value"
else
    no "masks an unprefixed high-entropy value" "the hex run reached the output"
fi

# Atlassian API token: ATATT prefix, base64url body, trailing checksum. The
# generic fallbacks miss it — the body carries '-', '_' and '=' — so it needs
# its own pattern.
atl="$(MYTEST_ATL='ATATT3xFfGF0YULg6ygsuaRoh0oRsRcmtUdOrLkiAeWFqtnR5wQ72GF0odDd-kw3qD0v-Bl_noPqLIZU1va5C4D6yv2zLss8Zh9RJixqpilKBitzF5vP-RFQnrKasP0RRwOVg3FIdHRsjdmKoIwOv=A5DDAXXD' \
              run_tool 2>/dev/null)"
if grep -q '^MYTEST_ATL=<REDACTED:' <<< "$atl"; then
    ok "masks an Atlassian API token"
else
    no "masks an Atlassian API token" "the ATATT token reached the output"
fi

# A classic Atlassian token is 24 characters of letters and digits — the shape
# of a build id. Only the variable's name says it is a secret.
named="$(MYTEST_JIRA_API_TOKEN='K3nT8sQ2vB7hL9wR4dY6' \
         MYTEST_TOKENIZERS_PARALLELISM='false' \
         MYTEST_TOKEN_FILE='/etc/creds/jira' \
         run_tool 2>/dev/null)"
if grep -q '^MYTEST_JIRA_API_TOKEN=<REDACTED:' <<< "$named"; then
    ok "masks a shapeless value whose name says credential"
else
    no "masks a shapeless value whose name says credential" \
       "the 24-character token reached the output"
fi
if grep -qx 'MYTEST_TOKENIZERS_PARALLELISM=false' <<< "$named"; then
    ok "leaves a flag alone, whatever its name contains"
else
    no "leaves a flag alone, whatever its name contains" "false was masked"
fi
if grep -qx 'MYTEST_TOKEN_FILE=/etc/creds/jira' <<< "$named"; then
    ok "leaves a path alone — configuration, not a secret"
else
    no "leaves a path alone — configuration, not a secret" "the path was masked"
fi

# A Windows path is configuration too, and a Git Bash or WSL shell is handed one
# routinely. The port excluded these and the POSIX side did not — found by
# tests/test_parity_safe_env.sh, review-2026-09-17-safe-env-ps1.md item A1.
winpath="$(MYTEST_TOKEN_WIN='C:/Users/me/token' \
           MYTEST_TOKEN_BS='C:\Users\me\token' \
           MYTEST_TOKEN_REL='./secrets/token' \
           run_tool 2>/dev/null)"
for want in 'MYTEST_TOKEN_WIN=C:/Users/me/token' \
            'MYTEST_TOKEN_BS=C:\Users\me\token' \
            'MYTEST_TOKEN_REL=./secrets/token'; do
    if grep -qxF "$want" <<< "$winpath"; then
        ok "leaves a path alone: ${want#*=}"
    else
        no "leaves a path alone: ${want#*=}" "it was masked or dropped"
    fi
done

# An empty value prints as NAME=, which is what env itself prints and what
# grep '^NAME=' expects. The POSIX side printed a bare NAME until 2026-09-17.
empty="$(MYTEST_EMPTY= run_tool 2>/dev/null)"
if grep -qx 'MYTEST_EMPTY=' <<< "$empty"; then
    ok "an empty value prints as NAME="
else
    no "an empty value prints as NAME=" \
       "got: $(grep '^MYTEST_EMPTY' <<< "$empty" || echo '<no line at all>')"
fi

# The worst defect this file has carried: a value with a newline in it used to
# be read as several records, and everything after the first line was printed
# verbatim. A private key came out as a masked header followed by its own body.
# review-2026-09-17-safe-env.md item A1. The body below is invented.
key_body='MIIEpAIBAAKCAQEAxGZlbGxvd3NoaXBvZnRoZXJpbmdvbmU'
key_value="-----BEGIN RSA PRIVATE KEY-----
$key_body
-----END RSA PRIVATE KEY-----"
multi="$(MYTEST_PK="$key_value" run_tool 2>/dev/null)"
if grep -Fq -- "$key_body" <<< "$multi"; then
    no "a multi-line value is masked whole" "the key body reached the output"
else
    ok "a multi-line value is masked whole"
fi
# ...and the length in the mask is the value's, not the first line's.
if grep -qx "MYTEST_PK=<REDACTED:${#key_value}>" <<< "$multi"; then
    ok "the mask reports the length of the whole value"
else
    no "the mask reports the length of the whole value" \
       "got: $(grep '^MYTEST_PK' <<< "$multi" || echo '<no line at all>')"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
