#!/usr/bin/env bash
# Behaviour tests for the guard: every case is one command string fed to
# secrets-guard, and one expected exit code (2 denies, 0 lets through).
#
#   ./tests/test_guard.sh                  test the POSIX guard in ../bin
#   ./tests/test_guard.sh --pwsh           test the PowerShell port instead
#   ./tests/test_guard.sh --guard PATH     test an installed copy
#
# The cases live in a file rather than in a shell one-liner for a reason: a
# command line containing `cat .env` is itself something the guard denies, so
# testing it by hand blocks the test run.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$SRC/bin/secrets-guard"
RUNNER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --pwsh)  GUARD="$SRC/bin/secrets-guard.ps1"; RUNNER="pwsh -NoProfile -File" ;;
        --guard) GUARD="${2:-}"; shift ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -e "$GUARD" ] || { echo "guard not found: $GUARD" >&2; exit 2; }

pass=0
fail=0

# check <expected-exit> <command-string>
check() {
    local want="$1" cmd="$2" got payload
    # The python program is single-quoted on purpose: its $ and quotes belong
    # to python, not to the shell.
    # shellcheck disable=SC2016
    payload="$(printf '%s' "$cmd" | python3 -c \
        'import json,sys; print(json.dumps({"tool_input":{"command":sys.stdin.read()}}))')"
    if [ -n "$RUNNER" ]; then
        printf '%s' "$payload" | $RUNNER "$GUARD" >/dev/null 2>&1
    else
        printf '%s' "$payload" | "$GUARD" >/dev/null 2>&1
    fi
    got=$?
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
        printf '  ok    %-52s exit=%s\n' "$cmd" "$got"
    else
        fail=$((fail + 1))
        printf '  FAIL  %-52s exit=%s (expected %s)\n' "$cmd" "$got" "$want"
    fi
}

echo "guard: $GUARD"
echo
echo "denied — dumps the whole environment"
check 2 'env'
check 2 'env | grep FOO'
check 2 'printenv'
check 2 'export -p'
check 2 'set'
check 2 'declare'
check 2 'typeset'
check 2 'history'
check 2 'rtk env'
check 2 'sudo env'
check 2 'ls && env'

echo
echo "denied — reads a file that holds credentials"
check 2 'cat .env'
check 2 'cat /srv/app/.env.production'
check 2 'head ~/.bashrc'
check 2 'tail /home/user/.zshrc'
check 2 'cat /proc/1/environ'
check 2 'head /home/user/.aws/credentials'
check 2 'cat ~/.ssh/id_rsa'
check 2 'cat ~/.npmrc'
check 2 'cat ~/.git-credentials'
check 2 'cat ~/.azure/msal_token_cache.json'

echo
echo "denied — the same stores spelled the Windows way"
check 2 'type C:\Users\me\.aws\credentials'
check 2 'gc $HOME\.kube\config'
check 2 'cat C:\Users\me\_netrc'
check 2 'type C:\Users\me\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'

echo
echo "allowed — one variable, or an ordinary command"
check 0 'echo hi'
check 0 'printenv PATH'
# The command strings below are test data, not commands to run: `$` inside them
# must reach the guard exactly as an assistant would have written it.
# shellcheck disable=SC2016
check 0 'echo "$ANTHROPIC_MODEL"'
check 0 'safe-env'
check 0 'safe-env | grep MODEL'
check 0 'cat README.md'
check 0 'head -20 install.sh'
check 0 'env VAR=1 mycommand'
check 0 'set -e'
check 0 'declare X=1'
check 0 'helm history release'
check 0 'docker history image'

echo
echo "allowed — the word env in everyday work, where it is not the command"
check 0 'source env/bin/activate'
check 0 'python -m venv env'
check 0 'git commit -m "fix env parsing"'
check 0 'grep -rn "env" src/'

echo
echo "allowed — a secret path named inside prose, not read by a command"
check 0 'git commit -m "docs: cat .env ends the same way"'
check 0 'echo "never cat ~/.bashrc in a session"'
check 0 'grep -rn "cat .env" docs/'

echo
echo "allowed — the word appears inside a quoted program, not as a command"
check 0 "awk '/env|printenv|set/ {print}' file.txt"
check 0 "rg -e 'env|history|export' notes.md"
check 0 "jq -r '.a | select(.k|test(\"^(env|set)\"))' f.json"

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
