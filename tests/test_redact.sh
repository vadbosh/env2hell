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

# ── one pwsh process for the whole run ──────────────────────────────────────
# `pwsh -File` costs about a second of startup and the tool is called two dozen
# times, so the port's run was 72 seconds of starting PowerShell. The server
# takes {args, stdin} as one JSON line and answers {rc, out}; the cases are
# unchanged.
#
# Not used when NO_SERVER is set: two cases set TMPDIR per call and one of them
# backgrounds the tool in order to kill it, and a shared server can do neither.
# Two FIFOs and not `coproc`: run_tool is always the middle of a pipeline, a
# pipeline element runs in a subshell, and a coproc's file descriptors are not
# inherited by subshells. Descriptors opened with `exec` are. The symptom was
# every case reporting "the hook issued no replacement at all" in two seconds —
# fast, green-looking plumbing, and no tool ever ran.
srv_dir=""
SERVER=""
if [ "$PORT" = pwsh ] && [ -e "$SRC/tests/pwsh_serve_filter.ps1" ]; then
    srv_dir="$(mktemp -d)"
    mkfifo "$srv_dir/req" "$srv_dir/rep"
    pwsh -NoProfile -File "$SRC/tests/pwsh_serve_filter.ps1" "$TOOL" \
        < "$srv_dir/req" > "$srv_dir/rep" 2>/dev/null &
    srv_pid=$!
    exec {REQ}>"$srv_dir/req"
    exec {REP}<"$srv_dir/rep"
    SERVER=1
fi
close_server () {
    [ -n "$SERVER" ] || return 0
    exec {REQ}>&-
    wait "$srv_pid" 2>/dev/null
    exec {REP}<&-
    rm -rf "${srv_dir:?}"
    SERVER=""
}
trap close_server EXIT

# $RUNNER is a command plus its flags and has to split into words.
# shellcheck disable=SC2086
run_tool () {
    if [ -z "$SERVER" ] || [ -n "${NO_SERVER:-}" ]; then
        $RUNNER "$TOOL" "$@"
        return $?
    fi
    # The argument array is built by hand rather than with `jq --args`, which
    # still parses a leading `-` as one of its own options and rejects
    # `--filter`. Every argument this tool takes is a flag of letters and
    # hyphens, so quoting them needs nothing cleverer.
    local argv="[" first=1 x sjson reply
    for x in "$@"; do
        [ "$first" = 1 ] || argv="$argv,"
        argv="$argv\"$x\""
        first=0
    done
    argv="$argv]"
    sjson="$(jq -Rs .)"             # stdin, JSON-encoded, newlines and all
    printf '{"args":%s,"stdin":%s}\n' "$argv" "$sjson" >&"$REQ"
    IFS= read -r reply <&"$REP"
    printf '%s' "$reply" | jq -j '.out'
    return "$(printf '%s' "$reply" | jq -r '.rc')"
}

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
# SQL names the password in two words, and the statement is quoted verbatim in
# a runbook, a migration and every "how do I reset it" answer. `bin/safe-env`
# has masked it since the first commit while the redactor did not — a rule in
# one implementation of a policy and not the other, which is what the parity
# suites exist to surface.
#
# Both cases quote the value with `'`, because hook_out interpolates the line
# into a JSON string unescaped: a literal `"` in the payload makes the JSON
# invalid, the tool declines to parse it, and the result reads as "the hook
# masked nothing". The double-quoted spelling is covered through --filter
# below, where no JSON is involved.
check_labelled "CREATE USER app IDENTIFIED BY '$HEX';"  'IDENTIFIED BY'
check_labelled "alter user app identified by '$HEX';"   'identified by'

check_labelled "HW_ACCESS_KEY=$HEX"          'HW_ACCESS_KEY='
check_labelled "HW_SECRET_KEY: $HEX"         'HW_SECRET_KEY:'
check_labelled "OS_SECRET_KEY=$HEX"          'OS_SECRET_KEY='
check_labelled "HUAWEICLOUD_SECRET_KEY=$HEX" 'HUAWEICLOUD_SECRET_KEY='

# ── a credential glued to its flag ─────────────────────────────────────────
# Tier 2 needs a separator between the label and the value. Four client idioms
# have none, and all four are in daily use: the MySQL client documents
# `-p<password>`, every Redis tutorial shows `-a <password>`, smbclient takes
# `-U user%password`, and curl takes `-u user:password`. Each rule is gated on
# the command that owns it, because the flag letters mean other things
# elsewhere — `ls -p`, `grep -a`, `sort -u` must stay untouched.
check_glued () {                        # <line> <text that must survive>
    local line="$1" keep="$2" out
    out="$(printf '%s\n' "$line" | run_tool --filter)"
    if grep -q "$HEX" <<< "$out"; then
        no "masks $keep" "the raw value reached the output"
    elif ! grep -qF -- "$keep" <<< "$out"; then
        no "masks $keep" "the flag or the user name was masked too: $out"
    elif ! grep -q 'REDACTED' <<< "$out"; then
        no "masks $keep" "nothing was masked: $out"
    else
        ok "masks $keep, keeping the flag readable"
    fi
}

check_glued "mysql -uroot -p$HEX -h db"                  '-p<REDACTED'
check_glued "mysqldump -uroot -p$HEX db"                 '-p<REDACTED'
check_glued "redis-cli -a $HEX ping"                     '-a <REDACTED'
check_glued "smbclient //srv/share -U admin%$HEX"        'admin%<REDACTED'
check_glued "curl -u admin:$HEX https://api.example"     'admin:<REDACTED'
check_glued "curl --user admin:$HEX https://api.example" 'admin:<REDACTED'

# The same flag letters where they mean something else. --filter exits 1 when
# it masked nothing, which is the assertion here.
for line in 'ls -p /tmp' 'grep -a1 pattern file.txt' 'sort -u names.txt' \
            'mysql -p -h db' 'curl https://api.example/users'; do
    left="$(printf '%s\n' "$line" | run_tool --filter)"
    if grep -q 'REDACTED' <<< "$left"; then
        no "leaves alone: $line" "something was masked"
    else
        ok "leaves alone: $line"
    fi
done

# ── a label followed by a name is not a secret ──────────────────────────────
# Tier 2 keys on a label plus any run of 16+ token characters, and an ordinary
# identifier fits that exactly. Measured 2026-09-14 over 69 Codex transcripts:
# of 51 flagged lines about 35 were a name — `usage.outputTokens` in JavaScript,
# `ANTHROPIC_API_KEY` as a metavar in --help output, `data.aws_eks_cluster_auth
# .this.token` in Terraform, a Kubernetes object name after `get secret`.
#
# In the hook that is not noise, it is damage: the model was handed
# `<REDACTED:18>` where the variable name should be. Both directions are
# asserted, because a filter written too wide stops masking real keys — and the
# shapes it must not take are the ones a cloud vendor chose: a Huawei access key
# is 20 characters of upper case and digits, which is why the metavar rule
# requires an underscore instead of matching upper case alone.
#
# --filter reports the verdict in its exit status, which is what is read here:
# comparing the text would be comparing it against a hook that may also have
# masked this very test run's output.
verdict () {                            # verdict <line> -> "mask" | "keep"
    if printf '%s\n' "$1" | run_tool --filter >/dev/null 2>&1; then
        printf 'mask'
    else
        printf 'keep'
    fi
}

check_shape () {                        # <mask|keep> <line> <what it is>
    local want="$1" line="$2" what="$3" got
    got="$(verdict "$line")"
    if [ "$got" = "$want" ]; then
        ok "$want: $what"
    else
        no "$want: $what" "got $got"
    fi
}

check_shape keep 'output_tokens: usage.outputTokens,'            'a dotted identifier in source'
check_shape keep '  --anthropic-api-key ANTHROPIC_API_KEY'       'a metavar in --help output'
check_shape keep '  token = data.aws_eks_cluster_auth.this.token' 'a Terraform reference'
check_shape keep 'client_secret = var.oidc_application_client_secret' 'a Terraform variable'
check_shape keep 'kubectl get secret prometheus-operator -n mon' 'a kebab-case object name'
check_shape keep 'token = $GITHUB_TOKEN_VALUE'                   'a shell variable, not its value'
check_shape keep 'private_key = /etc/ssl/private/server.key'     'a path'
# `sk-` inside a hyphenated name. The boundary has to count `-` as part of a
# word, because that is what precedes `sk-` here — a plain word boundary
# changes nothing. The value is invented.
check_shape keep 'ANTHROPIC_MODEL=zai-sk-glm-4-6-turbo-preview'  'a model name containing sk-'
check_shape mask 'OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx'    'the same prefix starting a value'
# A timestamped backup name is fifteen digits and a hyphen — the shape of a
# secret to anything that scores on length alone, and the shape this project's
# own installer writes on every patch (%Y%m%d-%H%M%S). It passes today because
# tier 1 has no pattern for it and tier 2 needs a credential label on the line;
# nothing pinned that, so a later widening of tier 2 would turn every `ls -la`
# of a config directory into <REDACTED:…> and nobody would learn it here.
check_shape keep 'settings.json.bak.20260915-224647'             'a timestamped backup name'
# shellcheck disable=SC2088  # the tilde is the text under test, not a path to
                             # expand — this is how such a name is printed
check_shape keep '~/.claude/settings.json.bak.20260915-224647'   'the same with a path'
check_shape keep '-rw------- 1 root root 4096 Sep 15 22:46 settings.json.bak.20260915-224647' 'an ls -la line carrying one'
check_shape keep 'settings.json.env2hell.tmp'                    'the installer temp name'

# ── shapes a secret takes that the label rules used to miss ─────────────────
# Each of these came back byte for byte before 2026-09-16, through both ports.

# An HTTP header is where a token appears most often outside a shell, and the
# scheme word sits between the label and the value. The scheme stays readable
# for the same reason the label does: the model has to see what kind of
# credential went.
BEARER='abcdefghijklmnopqrstuvwxyz0123456789'
check_shape mask "Authorization: Bearer $BEARER"                 'an HTTP bearer token'
check_shape mask "authorization: bearer $BEARER"                 'the same, lower case'
check_shape keep 'Authorization: Bearer'                         'a header with no value after it'

got="$(hook_out "Authorization: Bearer $BEARER")"
if grep -qF -- 'Authorization: Bearer <REDACTED:' <<< "$got"; then
    ok "keeps the scheme word readable"
else
    no "keeps the scheme word readable" "expected 'Authorization: Bearer <REDACTED:…>', got: $got"
fi

# A password is exactly the string that carries punctuation, and VALUE's
# character class stops at the first `!`. Inside quotes the writer has already
# marked where the value ends, so that is the boundary to use.
PUNCT='S3cr3t!Passw0rd#2026'
check_shape mask "password = \"$PUNCT\""                         'a quoted password with punctuation'
check_shape mask "PGPASSWORD='$PUNCT'"                           'the same in single quotes'
check_shape keep 'password_field = "user_password"'              'a quoted name, not a value'
check_shape keep 'password = "short"'                            'a quoted value too short to be a secret'

# The JSON spelling: a closing quote sits between the label and the colon, and
# neither separator admitted it. JSON is what an API error, a config dump and
# `kubectl get -o json` print.
check_shape mask '{"password": "hunter2-hunter2-hunter2"}'       'the JSON spelling of a labelled secret'
check_shape keep '{"password_field": "user_password"}'           'the JSON spelling of a name'

# A private key is a block, not a line, and awk sees lines. Tier 1 masks the
# BEGIN text — which made the result *look* handled while the key itself went
# through underneath it.
check_block () {                        # <what it is> <line…>
    local what="$1"; shift
    local text out
    text="$(printf '%s\n' "$@")"
    out="$(printf '%s' "$text" | run_tool --filter 2>/dev/null)"
    if grep -q 'b3BlbnNzaC1rZXktdjEA\|MIIEpAIBAAKCAQEA' <<< "$out"; then
        no "masks $what" "the key body reached the output:
$(printf '%s\n' "$out" | sed 's/^/        /')"
    elif [ "$(printf '%s\n' "$out" | wc -l)" -ne "$(printf '%s\n' "$text" | wc -l)" ]; then
        no "masks $what" "the line count changed: $(printf '%s\n' "$text" | wc -l) in, $(printf '%s\n' "$out" | wc -l) out"
    else
        ok "masks $what, line for line"
    fi
}

check_block 'an OpenSSH private key' \
    '-----BEGIN OPENSSH PRIVATE KEY-----' \
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt' \
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt' \
    '-----END OPENSSH PRIVATE KEY-----'
check_block 'an RSA private key' \
    '-----BEGIN RSA PRIVATE KEY-----' \
    'MIIEpAIBAAKCAQEAvtbqvKZ9pQ3Xp7nZ0oR2lM4cW8sT1yU6iE5aB3dF7gH9jK2mN4pQ' \
    '-----END RSA PRIVATE KEY-----'

# The words in prose must not start swallowing the rest of a document. Tier 1
# masks the phrase itself wherever it appears, and that is deliberate — the RE
# is shared character for character with bin/safe-env. What must not happen is
# the *block* rule latching on: the lines after a sentence are ordinary text.
prose="$(printf '%s\n' 'the file starts with BEGIN RSA PRIVATE KEY, like every key does' \
                       'and this ordinary line comes after it' |
         run_tool --filter 2>/dev/null)"
if grep -qF 'and this ordinary line comes after it' <<< "$prose"; then
    ok "the phrase in a sentence does not swallow what follows"
else
    no "the phrase in a sentence does not swallow what follows" "got:
$(printf '%s\n' "$prose" | sed 's/^/        /')"
fi

# ── what a killed run leaves behind ─────────────────────────────────────────
# A SIGKILL runs no trap, and the harness kills this hook exactly when it is
# slow, so a killed run used to leave its whole payload in /tmp for good — 74 MB
# from one kill, with somebody's tool output inside it. POSIX only: the port
# keeps everything in memory and writes nothing.
#
# TMPDIR points inside this suite's own directory, so nothing here can sweep or
# leave anything in the real one.
if [ "$PORT" = posix ]; then
    scratch_home="$(mktemp -d)"
    trap 'rm -rf "${scratch_home:?}"' EXIT
    big="$scratch_home/big.json"
    python3 - "$big" <<'PY'
import json, sys
json.dump({"tool_name": "Bash",
           "tool_response": {"stdout": ("ordinary line of output " * 40 + "\n") * 12000}},
          open(sys.argv[1], "w"))
PY

    NO_SERVER=1 TMPDIR="$scratch_home" run_tool < "$big" >/dev/null 2>&1 &
    redact_pid=$!
    sleep 1
    kill -9 "$redact_pid" 2>/dev/null
    wait "$redact_pid" 2>/dev/null

    runs () {                           # runs — how many run directories exist
        find "$scratch_home/secrets-redact" -maxdepth 1 -mindepth 1 \
             -name 'run.*' -type d 2>/dev/null | wc -l
    }
    left="$(runs)"
    mode="$(python3 -c 'import os,sys; print(format(os.stat(sys.argv[1]).st_mode & 0o777, "o"))' \
            "$scratch_home/secrets-redact" 2>/dev/null || printf 'unknown')"

    if [ "$mode" = 700 ]; then
        ok "the scratch directory is private whatever the umask says"
    else
        no "the scratch directory is private" "mode is $mode"
    fi

    # Back-dated on purpose: the sweep must never take a directory young enough
    # to belong to a run happening right now.
    find "$scratch_home/secrets-redact" -maxdepth 1 -mindepth 1 -name 'run.*' -type d \
         -exec touch -t 200001010000 {} + 2>/dev/null
    printf 'x --pass %s\n' "$HEX" | NO_SERVER=1 TMPDIR="$scratch_home" run_tool --filter >/dev/null 2>&1
    after="$(runs)"

    if [ "$left" -ge 1 ] && [ "$after" -eq 0 ]; then
        ok "a later run sweeps what a killed one left ($left left, then $after)"
    elif [ "$left" -eq 0 ]; then
        no "a later run sweeps what a killed one left" \
           "the kill left nothing — the payload finished before it landed"
    else
        no "a later run sweeps what a killed one left" "$left left, $after still there"
    fi
fi

# ── the count in the warning, and the bytes on the way out ──────────────────
# --warn-only is read by a human who decides whether to rotate. Counting lines
# instead of values reports fewer credentials than are in the output, and
# always downwards.
warn_count () {                         # warn_count <stdout-text> -> the number
    printf '{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"%s","stderr":""}}' "$1" |
        run_tool --warn-only |
        jq -r 'try (.hookSpecificOutput.additionalContext | capture("contains (?<n>[0-9]+) credential").n) // "none"'
}

got="$(warn_count "$GHP $GHP $GHP")"
if [ "$got" = 3 ]; then
    ok "the warning counts values, not lines (three on one line)"
else
    no "the warning counts values, not lines" "three values on one line, the warning says $got"
fi

got="$(warn_count "$GHP $GHP\n$GHP $GHP")"
if [ "$got" = 4 ]; then
    ok "the warning counts values across lines"
else
    no "the warning counts values across lines" "four values on two lines, the warning says $got"
fi

# awk's print terminates every line, so text that did not end in a newline came
# back one byte longer. The hook path repairs that; --filter is the mode the
# Opencode plugin calls, and it never did.
filter_bytes () {                       # filter_bytes <printf-format> -> byte count
    # shellcheck disable=SC2059  # the argument IS the format: these cases are
                                 # about whether a trailing \n is there at all
    printf "$1" | run_tool --filter 2>/dev/null | wc -c
}
in_bytes="$(printf 'x --pass %s' "$HEX" | wc -c)"
out_bytes="$(filter_bytes "x --pass $HEX")"
want=$(( in_bytes - ${#HEX} + 13 ))     # <REDACTED:32> is 13 characters
if [ "$out_bytes" -eq "$want" ]; then
    ok "--filter adds no newline the input did not have"
else
    no "--filter adds no newline the input did not have" \
       "$in_bytes bytes in, $out_bytes out, expected $want"
fi
if [ "$(filter_bytes "x --pass $HEX\n")" -eq $(( want + 1 )) ]; then
    ok "--filter keeps the newline the input did have"
else
    no "--filter keeps the newline the input did have" "got $(filter_bytes "x --pass $HEX\n")"
fi

# The floor of 16 for a bare value, decided 2026-09-16 rather than inherited.
# Lowering it to 12 masks the word after "token" in ordinary documentation, and
# the obvious mitigation — "a bare lowercase word is prose" — keeps the
# md5-shaped relay password this hook was written for, because `deadbeef` is
# letters all the way down. Both directions are pinned here.
check_shape keep 'the token configuration lives in git'           'a long word after a label, in prose'
check_shape keep 'pass the credentials file to the job'           'the same, another label'
check_shape mask 'password = "S3cr3t!Pass"'                       'a short password, but quoted'
check_shape mask 'password=Tr0ub4dor'                             'a short password, unquoted: was the accepted gap until 0.9.0'

# 2026-09-21: the gap above stopped being acceptable. A docker-compose comment
# came back from a remote host through ssh with
#
#   # - BasicAuth__Password=<10 characters, mixed case and digits>
#
# and the value reached the transcript because 10 is under the floor of 16. The
# hook was installed, wired to Bash and working: three other values in the same
# session were masked correctly. Only length decided it.
#
# So a short unquoted value is now decided by composition instead: lower, upper
# and a digit together. Both directions are pinned, because the floor exists to
# protect ordinary words after a label and that protection must survive.
check_shape mask '      # - BasicAuth__Password=Ab3xKp9Qz7'       'the leak of 2026-09-21, exactly as it arrived'
check_shape mask 'DB_PASSWORD=Xy7kLm2pQ'                          'a short generated password'
check_shape keep 'token: deploy_v2'                               'a short value with no upper case'
check_shape keep 'secret: utf8mb4'                                'a short value with no upper case, again'
check_shape keep 'password = hello-world'                         'two ordinary words'
check_shape keep 'api_key: MAIN_BRANCH'                           'a short value with no lower case'
# The cost of the rule, stated rather than hidden: `token=Release2026` carries
# all three classes and is masked, though it is a tag name. The trade was made
# knowing this -- a masked tag costs a re-read, a leaked password costs a
# rotation -- and it is pinned here so that anyone loosening the rule sees what
# they are buying back.
check_shape mask 'token=Release2026'                              'a release tag: the false positive this rule accepts'

# The SQL spelling, through --filter where no JSON escaping is in the way, so
# the double-quoted form can be asserted too. The last line is the reason the
# label needs a quoted value beside it: the statement is quoted in prose far
# more often than it is run.
check_shape mask "CREATE USER app IDENTIFIED BY 'Tr0ub4dor-and-horse'" 'a SQL password, single-quoted'
check_shape mask 'ALTER USER app IDENTIFIED BY "Tr0ub4dor-and-horse"' 'a SQL password, double-quoted'
check_shape keep 'the syntax is IDENTIFIED BY followed by a quoted password' 'the SQL clause named in prose'

check_shape mask "croc --pass $HEX code"                         'a labelled hex password'
check_shape mask "TOKEN: $HEX"                                   'an uppercase label'
check_shape mask 'HW_ACCESS_KEY=ABCD1234EFGH5678IJKL'            'a Huawei access key: caps and digits, no underscore'
check_shape mask 'HW_SECRET_KEY=aB3xY7zQ1mN8pR4sT6uV0wX2yZ5cD9eF1gH3jK5l' 'a Huawei secret: mixed base62'
check_shape mask 'password=Xk8mP2qR9vT4wY7z'                     'a mixed-case password'
check_shape mask 'api_key=0123456789abcdef0123'                  'a bare hex api key'

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

# ── the shape the 2026-09-21 leak actually arrived in ───────────────────────
# Everything above hands the hook one line. The leak came as sixty lines of
# somebody else's docker-compose, printed by ssh into a heredoc, with the
# password on line forty. The investigation could not tell "the pattern did not
# match" from "the hook was not called", so both are asserted here: the value
# is gone AND the lines around it came back untouched.
multi="$(printf 'services:\n  api:\n    image: registry/app:2026-09\n    environment:\n      # - BasicAuth__Password=Ab3xKp9Qz7\n      - ASPNETCORE_URLS=http://+:8080\n' |
         jq -Rs .)"
mout="$(printf '{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":%s,"stderr":"","interrupted":false}}' "$multi" |
        run_tool | jq -r '.hookSpecificOutput.updatedToolOutput.stdout // empty' 2>/dev/null)"
if [ -z "$mout" ]; then
    no "masks a value inside a multi-line tool result" "the hook issued no replacement at all"
elif grep -q 'Ab3xKp9Qz7' <<< "$mout"; then
    no "masks a value inside a multi-line tool result" "the raw value reached the output"
elif ! grep -q 'ASPNETCORE_URLS=http://+:8080' <<< "$mout"; then
    no "masks a value inside a multi-line tool result" "the neighbouring lines did not survive"
else
    ok "masks a value inside a multi-line tool result, leaving its neighbours"
fi

# Output that the command did not produce itself. A tool result carrying the
# stdout of ssh, docker or kubectl is the commonest way another machine's
# configuration enters a session, and the hook sees a string either way -- this
# asserts that there is no path where it does not.
foreign="$(sh -c 'printf "remote:\n  # - BasicAuth__Password=Ab3xKp9Qz7\n"')"
fout="$(printf '{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":%s,"stderr":""}}' "$(printf '%s' "$foreign" | jq -Rs .)" |
        run_tool | jq -r '.hookSpecificOutput.updatedToolOutput.stdout // empty' 2>/dev/null)"
if [ -n "$fout" ] && ! grep -q 'Ab3xKp9Qz7' <<< "$fout"; then
    ok "masks a value in the stdout of another process"
else
    no "masks a value in the stdout of another process" "the value survived, or nothing was replaced"
fi

# ── the journal ─────────────────────────────────────────────────────────────
# Added after 2026-09-21, when a leak could not be diagnosed because "the hook
# never ran" and "it ran and matched nothing" leave the same trace: none. One
# line per invocation, and never a fragment of the input -- a log that quotes
# what it masked is a second copy of the secret, in a file nobody watches.
#
# POSIX only, and the reason is the harness rather than the port: the pwsh side
# runs through one long-lived server process started before these lines, so a
# variable exported for a single call never reaches it. The port writes the same
# format to the same file -- checked by hand with
# `ENV2HELL_LOG=… pwsh -File bin/secrets-redact.ps1 --filter`.
jlog="$(mktemp -u)"
if [ "$PORT" = "pwsh" ]; then
    ok "journal: skipped on the pwsh port — per-call env cannot reach its server"
else
ENV2HELL_LOG="$jlog" run_tool --filter <<< "password=Ab3xKp9Qz7" >/dev/null 2>&1
ENV2HELL_LOG="$jlog" run_tool <<< '{"tool_name":"Read","tool_response":{"stdout":"nothing to see"}}' >/dev/null 2>&1
if [ ! -s "$jlog" ]; then
    no "writes one journal line per invocation" "nothing was written to $jlog"
elif [ "$(wc -l < "$jlog")" -ne 2 ]; then
    no "writes one journal line per invocation" "got $(wc -l < "$jlog") lines for two calls"
elif grep -q 'Ab3xKp9Qz7' "$jlog"; then
    no "the journal never holds a value" "the masked value is in the log"
elif grep -q 'masked=yes' "$jlog" && grep -q 'masked=no' "$jlog"; then
    ok "writes one journal line per invocation, recording whether anything was masked"
else
    no "the journal distinguishes a hit from a miss" "$(cat "$jlog")"
fi
fi
rm -f "$jlog"

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
    # SK is in the comparison too: it left RE on 2026-09-17 because it needs a
    # left boundary, and a pattern that leaves the compared block stops being
    # compared — which is the drift this test exists to catch.
    strip () { grep -E '^  (RE|SK) = ' "$1"; }
fi
if diff <(strip "$peer") <(strip "$TOOL") >/dev/null 2>&1; then
    ok "tier-1 patterns match ${peer##*/} character for character"
else
    no "tier-1 patterns match bin/safe-env" \
       "the provider list has drifted; run: diff <(grep '^  RE = ' bin/safe-env) <(grep '^  RE = ' bin/secrets-redact)"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
