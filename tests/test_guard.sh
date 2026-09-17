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

# When set, every check runs under `timeout <seconds>`. Exit 124 then means the
# guard did not finish, which for a PreToolUse hook means the call went through
# unguarded — a distinct failure from "allowed it", and worth seeing as itself.
CHECK_TIMEOUT=""

# check <expected-exit> <command-string> [label]
# The label is what gets printed. A command of a few thousand sub-commands is a
# legitimate case and an illegible line.
check() {
    local want="$1" cmd="$2" label="${3:-$2}" got payload
    # The python program is single-quoted on purpose: its $ and quotes belong
    # to python, not to the shell.
    # shellcheck disable=SC2016
    payload="$(printf '%s' "$cmd" | python3 -c \
        'import json,sys; print(json.dumps({"tool_input":{"command":sys.stdin.read()}}))')"
    # $RUNNER is a command plus its flags and has to split into words; so does
    # the optional timeout prefix.
    # shellcheck disable=SC2086
    if [ -n "$RUNNER" ]; then
        printf '%s' "$payload" | ${CHECK_TIMEOUT:+timeout $CHECK_TIMEOUT} $RUNNER "$GUARD" >/dev/null 2>&1
    else
        printf '%s' "$payload" | ${CHECK_TIMEOUT:+timeout $CHECK_TIMEOUT} "$GUARD" >/dev/null 2>&1
    fi
    got=$?
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
        printf '  ok    %-52s exit=%s\n' "$label" "$got"
    else
        fail=$((fail + 1))
        printf '  FAIL  %-52s exit=%s (expected %s)\n' "$label" "$got" "$want"
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
# $HOME here is text the guard must see, not something the shell should expand.
# shellcheck disable=SC2016
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
echo "allowed — a key handed to ssh is what authenticates, not a file being read"
check 0 'rsync -e "ssh -i /root/.ssh/id.pem" host:/src /dst | head -5'
check 0 'scp -i ~/.ssh/id_rsa host:/tmp/log . && tail -20 log'
check 0 'ssh -i ~/.ssh/id_ed25519 host "uptime" | head -3'
check 0 'rsync -e "ssh -i ~/.ssh/id.pem" a b; cat report.txt'

echo
echo "denied — locality is per sub-command, so a real read still counts"
check 2 'rsync -e "ssh -i ~/.ssh/id.pem" a b | head -5; cat ~/.ssh/id_rsa'
check 2 'ssh -i ~/.ssh/id.pem host uptime && cat .env'
check 2 'cat ~/.ssh/id_rsa | head -5'
check 2 'head -5 .env | grep TOKEN'

echo
echo "denied — printing a credential-named variable, the one hand-operated leak"
# The value arrives alone on its line with no label beside it, so redaction has
# nothing to key on: tier 2 needs a label, tier 1 needs a provider prefix, and a
# Huawei key has neither.
check 2 'echo "$HW_SECRET_KEY"'
check 2 'echo $HW_ACCESS_KEY'
check 2 'echo "${GITHUB_TOKEN}"'
check 2 'printf "%s\n" "$AWS_SECRET_ACCESS_KEY"'
check 2 'echo "$MY_API_KEY"'
check 2 'cd /tmp && echo "$OS_SECRET_KEY"'
check 2 'echo "$db_password"'

echo
echo "allowed — an ordinary variable, and the word echo where it prints nothing"
check 0 'echo "$PATH"'
check 0 'echo "$HOME/bin"'
check 0 'echo "$ANTHROPIC_MODEL"'
check 0 'grep -r echo /etc/profile.d'
check 0 'safe-env | grep HW_SECRET_KEY'
check 0 'rg "TOKEN" src/'

echo
echo "allowed — single quotes expand nothing, so a template is not a leak"
# Writing a file that contains ${secret_name} is ordinary work. The guard used
# to read the raw text and deny it, which caught real editing sessions.
check 0 "printf 'key: \${secret_name}\n' > deploy.yaml"
check 0 "echo 'set \$API_KEY in the env first'"
check 0 "printf '%s\n' 'password=\${db_password}'"
# ...but the double-quoted form still expands, and is still denied
check 2 'echo "${db_password}"'

echo
echo "allowed — a credential name has to be a whole component, not a substring"
# A6 of review-2026-09-17-secrets-guard.md. The first line below is this file's
# own summary line: matched as a substring, PASS denied the test harness
# reporting its results. PASS needs a neighbouring component to count, because
# on its own the word is a counter as often as a credential.
check 0 'printf "\npassed %d, failed %d\n" "$pass" "$fail"'
check 0 'echo "$passed of $total"'
check 0 'echo "$bypass_cache"'
check 0 'echo "$compass_dir"'
check 0 'echo "$PASSENGER_ROOT"'
check 0 'echo "$pass"'
check 2 'echo "$DB_PASS"'
check 2 'echo "$PASS_FILE"'
check 2 'echo "$password"'

echo
echo "allowed — .env templates hold no values and are read all the time"
# A7 of the same review. `.env.production` must stay denied: the exemption is
# the well-known template suffixes and nothing wider.
check 0 'cat .env.example'
check 0 'head -1 .env.sample'
check 0 'cat .env.template'
check 0 'cat .env.dist'
check 0 'cat .env.defaults'
check 2 'cat .env.production'
check 2 'cat .env'
# both in one sub-command: the real one still trips it
check 2 'cat .env.example .env'

echo
echo "allowed — a credential handed to another command, not printed"
# The value goes to curl inside a command substitution, and what the printing
# command emits is curl's output. Denying this taught nothing and cost a
# working command a rewrite.
check 0 'printf "%s" "$(curl -s -u "$E:$JIRA_API_TOKEN" https://example.com)"'
check 0 'echo "$(cat /tmp/x)" && curl -H "Authorization: $API_TOKEN" https://x'
# ...but a printing command *inside* the substitution is still printing it
check 2 'echo "$(printf %s "$JIRA_API_TOKEN")"'

echo
echo "multi-line — a newline separates sub-commands, like ; does"
# A1 of review-2026-09-17-secrets-guard-ps1.md. The POSIX guard never had to say
# this: its awk program reads records, and a record is a line. The port was
# written from the separator list alone, so every case below diverged — in both
# directions. A label is passed because a command with a newline in it does not
# fit on a result line.
check 2 $'ls -la\nenv'                          'dump on the second line'
check 2 $'cd /tmp\nsudo env'                    'dump after a wrapper, second line'
check 2 $'echo hi && \\\nenv'                   'backslash continuation into a dump'
check 2 $'ls -la\ncat .env'                     'read on the second line'
check 0 $'git log --oneline |\n  head -20'      'a pipeline broken over two lines'
# locality has to survive the newline too: these are the cases the suite already
# pins on one line, written on two
check 0 $'ssh -i ~/.ssh/id.pem host uptime\nhead -5 report.txt'      'key on one line, reader on the next'
check 0 $'rsync -e "ssh -i ~/.ssh/id.pem" a b\ncat report.txt'       'rsync key, reader on the next line'
check 0 $'git commit -m "docs: cat .env ends the same way"\nhead -5 CHANGELOG.md' 'commit message, reader next line'

echo
echo "size — the guard has to finish inside its own hook timeout"
# A1 of review-2026-09-17-secrets-guard.md. The cost used to be per
# sub-command, with two forks each, so a heredoc of 550 lines outlived
# "timeout": 5 — and a PreToolUse hook killed at its timeout does not deny, it
# lets the call through with nothing said. Exit 124 below is that failure, and
# it reads differently from exit 0.
#
# The denied read sits at the END on purpose: everything before it has to be
# walked before the guard can reach it.
CHECK_TIMEOUT=10
big_sep="$(printf ':;%.0s' $(seq 1 2000))cat .env"
check 2 "$big_sep" '2000 sub-commands, then a read'
# $( ) strips trailing newlines, so the last line is joined to what follows
# unless one is put back explicitly.
big_lines="$(printf 'echo line %s\n' $(seq 1 2000))"$'\n'"cat .env"
check 2 "$big_lines" '2000 lines, then a read'
CHECK_TIMEOUT=""

echo
echo "structure — no early-exit grep behind a pipe, anywhere in the shipped code"
# `set -o pipefail` plus `printf '%s' "$x" | grep -q PATTERN` is a race, and it
# fails in the unsafe direction. `grep -q` exits on the first match; the printf
# feeding it then dies of SIGPIPE with status 141; pipefail makes 141 the status
# of the whole pipeline — so a *successful* match reads as a failure.
#
# Measured 2026-09-14: test_safe_env.sh failed 17 times in 120 runs, on six
# different assertions, always with byte-identical data — one diagnostic printed
# "expected MYTEST_PLAIN=hello-world; got MYTEST_PLAIN=hello-world". At 200 KB
# it stops being a race: 200 misses out of 200.
#
# In the tests that was noise. In bin/secrets-guard it was a hole: the same
# construct drove the loop that strips nested command substitutions and both
# checks inside it, so under the race the guard skipped the strip and allowed a
# command it exists to deny. Short command lines make it rare, and rare is the
# wrong guarantee for a gate.
#
# A here-string has no writer to kill, so the hazard is gone by construction.
# This check is what keeps it gone.
# `[^|]|` and not `|`: a plain pipe, never the second bar of `||`, where the
# grep that follows is a command in its own right and has nothing feeding it.
# Comment lines are dropped too — this very paragraph names the construct.
offenders="$(cd "$SRC" && grep -rn -- '[^|]|[^|]*grep  *-[A-Za-z]*q' \
             bin tools tests 2>/dev/null | grep -v ':[[:space:]]*#' || true)"
if [ -z "$offenders" ]; then
    pass=$((pass + 1)); printf '  ok    no pipe feeds a grep that can exit early\n'
else
    fail=$((fail + 1))
    printf '  FAIL  no pipe feeds a grep that can exit early — use `grep -q P <<< "$v"`:\n'
    printf '%s\n' "$offenders" | sed 's/^/        /'
fi

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
