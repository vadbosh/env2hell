<#
.SYNOPSIS
    secrets-guard — block shell commands that would print secrets into the
    transcript. PowerShell port of the POSIX `secrets-guard`, for Windows
    machines with neither Git Bash nor WSL.

.DESCRIPTION
    Reads the assistant's PreToolUse payload as JSON on stdin and inspects
    .tool_input.command. Exit 2 (with a message on stderr) denies the call;
    exit 0 lets it through.

    Two passes, deliberately:

      A. dump commands — scanned on QUOTE-STRIPPED text, so a word inside a
         quoted jq/awk program or a regular expression alternation is not
         mistaken for a command. Without this split, `... -match 'env|set'`
         would block itself.

      B. secret-file reads — scanned on the RAW text, because the path is
         often quoted and pass A would have erased it.

    Policy is kept identical to the POSIX version on purpose: one behaviour to
    learn, one set of documentation, whichever machine you are on.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$EnvMessage = '[secrets-guard] Blocked: bare env/printenv/export/set/declare/Get-ChildItem Env: leaks secrets to the session. Use `safe-env` (values masked), or $env:NAME for one value.'

function Deny([string]$Message) {
    [Console]::Error.WriteLine($Message)
    exit 2
}

$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

try {
    $payload = $raw | ConvertFrom-Json
} catch {
    exit 0   # not our payload — never break the assistant over a parse error
}

$command = $null
if ($payload.PSObject.Properties.Name -contains 'tool_input') {
    if ($payload.tool_input.PSObject.Properties.Name -contains 'command') {
        $command = [string]$payload.tool_input.command
    }
}
if ([string]::IsNullOrWhiteSpace($command)) { exit 0 }

# ---------- pass A: dump commands, on quote-stripped text ----------
$scan = $command -replace "'[^']*'", 'Q' -replace '"[^"]*"', 'Q'

# Wrappers that precede the real command and must be stepped over.
$wrappers = @('sudo', 'rtk', 'time', 'command', 'exec', 'xargs', 'nice', 'nohup', '&')

# A newline separates sub-commands as surely as `;` does. The POSIX guard never
# had to say so — its awk program reads records, and a record is a line — so the
# port was written from the separator list alone and a dump on the second line
# of a two-line command went straight through. `\r?\n` and not `\n`, because
# this is the implementation that runs where line endings are CRLF.
foreach ($part in ($scan -split '\|\||&&|;|&|\||\r?\n')) {
    $piece = $part.Trim()
    if ([string]::IsNullOrWhiteSpace($piece)) { continue }

    $tokens = @($piece -split '\s+' | Where-Object { $_ -ne '' })
    while ($tokens.Count -gt 0 -and $wrappers -contains $tokens[0].ToLower()) {
        $tokens = @($tokens[1..($tokens.Count - 1)])
    }
    if ($tokens.Count -eq 0) { continue }

    $first = $tokens[0]
    # Only a plain word can be a command name; "…, =…, {…, […, $…, *… are not.
    if ($first -notmatch '^[A-Za-z_][A-Za-z0-9_.:-]*$') { continue }

    $rest = @()
    if ($tokens.Count -gt 1) { $rest = @($tokens[1..($tokens.Count - 1)]) }
    $name = $first.ToLower()

    switch -Regex ($name) {
        '^(env)$' {
            # `env VAR=value command` launches something; a bare dump does not.
            $launches = $false
            foreach ($t in $rest) {
                if ($t -notlike '-*' -and $t -notlike '*=*') { $launches = $true }
            }
            if (-not $launches) { Deny $EnvMessage }
        }
        '^(printenv)$'          { if ($rest.Count -eq 0) { Deny $EnvMessage } }
        '^(export)$'            { if ($rest.Count -eq 0 -or $rest[0] -eq '-p') { Deny $EnvMessage } }
        '^(set)$'               { if ($rest.Count -eq 0) { Deny $EnvMessage } }
        '^(history)$'           { Deny $EnvMessage }
        '^(declare|typeset)$'   {
            $assigns = $false
            foreach ($t in $rest) { if ($t -like '*=*') { $assigns = $true } }
            if (-not $assigns) { Deny $EnvMessage }
        }
        # PowerShell's own spellings of the same dump.
        '^(gci|dir|ls|get-childitem)$' {
            if ($rest -join ' ' -match '(?i)\benv:') { Deny $EnvMessage }
        }
        '^(get-variable|gv)$'   { if ($rest.Count -eq 0) { Deny $EnvMessage } }
    }
}

# ---------- pass B: secret-file reads ----------
# The reader has to be a real command, so it is looked for in the quote-stripped
# text; the path may legitimately be quoted, so it is looked for in the raw one.
# That split keeps prose out of the decision: a commit message containing the
# words `cat .env` is an argument, not a command.
$readers = '(^|[\s;|&(])(cat|bat|batcat|tac|nl|head|tail|less|more|view|od|xxd|strings|type|gc|get-content)([\s]|$)'

# Kept identical to the POSIX version, store for store. Both path separators are
# accepted everywhere: a Windows path uses a backslash, and a Git Bash or WSL
# shell is routinely handed the other spelling.
$secrets = '((^|[\s"''/=])\.env([.\s"'']|$)' +          # .env
           '|[/\\][._](bashrc|zshrc|profile|bash_profile|zshenv|zprofile|netrc)' +
           '|id_rsa|id_ed25519|id_ecdsa' +              # private keys
           '|\.(pem|p12|pfx)([\s"'']|$)' +              # certificates
           '|\.aws[/\\]credentials|\.docker[/\\]config\.json' +
           '|\.kube[/\\]config|\.azure[/\\]' +
           '|\.git-credentials|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf' +
           '|Microsoft\.PowerShell_profile\.ps1' +      # where $env:KEY is set
           # The stores of the tools a developer has open on the same day. Each
           # held a live token and printed it on request until 2026-09-17.
           # review-2026-09-17-secrets-guard.md item A11.
           '|[/\\]gh[/\\]hosts\.yml' +                  # gh, a token in plain text
           '|\.terraformrc|terraform\.rc|credentials\.tfrc\.json' +
           '|[/\\]gcloud[/\\](credentials\.db|access_tokens\.db' +
           '|application_default_credentials\.json)' +
           '|\.cargo[/\\]credentials|\.gem[/\\]credentials' +
           '|\.m2[/\\]settings(-security)?\.xml' +
           '|rclone\.conf|\.vault-token|\.databrickscfg' +
           '|\.snowflake[/\\]config|[/\\]containers[/\\]auth\.json' +
           '|[/\\]helm[/\\]registry[/\\]config\.json' +
           # `~/.ssh/config` is deliberately NOT here: hostnames and
           # IdentityFile paths, not keys. Pinned as an `allow` in
           # tests/test_policy.sh so nobody adds it by tidiness.
           '|/proc/[0-9]+/environ)'                     # Linux only, by nature

# The reader and the path have to be in the SAME sub-command. Looking for them
# anywhere in the whole line denied things that read nothing:
#
#   rsync -e "ssh -i ~/.ssh/id.pem" host:/src /dst | head -5
#
# `.pem` there is the identity ssh authenticates with, and `head` reads rsync's
# output — two different commands, neither reading a key. Requiring locality
# keeps every real case (`cat .env`, `cat .env | grep X`, `ls && cat .env` all
# have both halves in one sub-command) and drops that class of false positive.
#
# The split runs on the RAW text, because the path is what is being looked for
# and the quote-stripping above would erase a quoted one. A separator inside
# quotes is not a separator, so a quoted program holding `;` or `|` stays whole.
$rawSubs = @()
$buf = ''
$quote = ''
foreach ($ch in $command.ToCharArray()) {
    if ($quote -eq '') {
        if ($ch -eq '"' -or $ch -eq "'") { $quote = $ch; $buf += $ch; continue }
        # The newline is a separator here too, and for a sharper reason than in
        # pass A: without it the reader on one line and the secret path on
        # another counted as one sub-command, which is exactly the locality the
        # `rsync -e "ssh -i …pem" … | head` incident bought. Written on two
        # lines, that command and the commit-message case were both denied.
        if ($ch -eq ';' -or $ch -eq '&' -or $ch -eq '|' -or
            $ch -eq "`n" -or $ch -eq "`r") { $rawSubs += $buf; $buf = ''; continue }
        $buf += $ch
    } else {
        if ($ch -eq $quote) { $quote = '' }
        $buf += $ch
    }
}
$rawSubs += $buf

# `.env.example` and its siblings are the opposite of a secret store: they are
# committed precisely because they hold no values, and reading one is the first
# thing anybody does in an unfamiliar repository. The `.env` pattern ends in
# `[.\s"']`, which is what makes `.env.production` match — and matched these
# with it. There is no negative lookahead worth writing here, so the template
# names are renamed out of the text before the path is looked for. The
# replacement contains no `env`, because -match is case-insensitive.
$envTemplates = '\.env\.(example|sample|template|dist|defaults)'

foreach ($rawSub in $rawSubs) {
    if ([string]::IsNullOrWhiteSpace($rawSub)) { continue }
    # Same stripping as pass A: the reader must be a command, not a word inside
    # a quoted program.
    $subScan = $rawSub -replace "'[^']*'", 'Q' -replace '"[^"]*"', 'Q'
    $pathScan = $rawSub -replace $envTemplates, '.TPLFILE'
    if ($subScan -match $readers -and $pathScan -match $secrets) {
        Deny '[secrets-guard] Blocked: that file can contain secrets. Read the one non-secret line you need, or use safe-env.'
    }
}

# ── printing a credential-named variable ───────────────────────────────────
# The message above offers `echo "$VAR"` as the safe way to read one value, and
# for PATH or EDITOR it is. For a variable whose NAME says "credential" it is
# the last hand-operated way to put a key into the transcript: the value comes
# out bare, alone on its line, with no label beside it. secrets-redact's tier 2
# has nothing to key on there, and tier 1 cannot recognise a provider-less
# token — a Huawei access key is 20 characters of uppercase and digits, its
# secret 40 of base62, shapes indistinguishable from a git SHA. Shape cannot
# decide it; the name can, and the name is visible here.
$credName = '(PASSWD|PASSWORD|PASSPHRASE|TOKEN|SECRET|API_?KEY|APIKEY' +
            '|AUTH_?TOKEN|ACCESS_?KEY|SECRET_?KEY|CLIENT_?SECRET' +
            '|PRIVATE_?KEY|CREDENTIAL)'

# The name has to be a WHOLE component of the variable name, not a substring of
# one. Matched as a substring it denied `$passed`, `$bypass_cache` and
# `$PASSENGER_ROOT` — and `printf 'passed %d, failed %d\n' "$pass" "$fail"`,
# which is this project's own test harness reporting its results.
#
# `PASS` needs a neighbour: `DB_PASS` is how half the compose files in existence
# spell a password, but a lone `$pass` is a counter at least as often as a
# credential. `PASSWORD`, `PASSWD` and `PASSPHRASE` say it on their own.
$credBound = '([^A-Za-z0-9_]|$)'
$credVar = '\$\{?([A-Za-z0-9]+_)*' + $credName + '(_[A-Za-z0-9]+)*' + $credBound +
           '|\$\{?(([A-Za-z0-9]+_)+PASS(_[A-Za-z0-9]+)*' +
           '|PASS(_[A-Za-z0-9]+)+)' + $credBound

foreach ($rawSub in $rawSubs) {
    if ([string]::IsNullOrWhiteSpace($rawSub)) { continue }
    # Only the printing commands, and only when they are the command — a
    # `grep echo` prints nothing of its own.
    if ($rawSub -notmatch '(^|\s)(echo|printf)(\s|$)') { continue }
    # Single-quoted spans are removed before the match. Inside them the shell
    # performs no expansion at all, so `$SECRET` there is four literal
    # characters — and writing a template that contains one is ordinary work:
    #
    #     printf 'key: ${secret_name}\n' > deploy.yaml
    #
    # Double quotes are deliberately left in place: `echo "$HW_SECRET_KEY"`
    # does expand, and that is the case this rule exists for.
    $sqStripped = $rawSub -replace "'[^']*'", 'Q'
    # A command substitution is a different command, and its arguments are not
    # this one's output. `echo "$(curl -u "$E:$API_TOKEN" ...)"` prints what
    # curl returned, not the token — denying it teaches nothing and costs a
    # rewrite of a working command. Innermost-first, so nesting collapses; each
    # body is checked on its own, which keeps `echo "$(printf '%s' "$TOKEN")"`
    # caught.
    #
    # The POSIX guard has had this since the rule was written; the port did not,
    # and denied the curl line above. A guard that blocks ordinary work is a
    # guard someone switches off, so a false denial is not the harmless
    # direction to fail in.
    $cmdSub = [regex]'\$\([^()]*\)'
    while ($sqStripped -match '\$\([^()]*\)') {
        $inner = [regex]::Match($sqStripped, '\$\(([^()]*)\)').Groups[1].Value
        if ($inner -match '(^|\s)(echo|printf)(\s|$)' -and $inner -match $credVar) {
            Deny '[secrets-guard] Blocked: printing a credential-named variable puts its value in the transcript unlabelled, where redaction cannot see it. Use `safe-env` and filter by name to check it is set without printing it.'
        }
        $sqStripped = $cmdSub.Replace($sqStripped, 'CMDSUB', 1)
    }
    if ($sqStripped -match $credVar) {
        Deny '[secrets-guard] Blocked: printing a credential-named variable puts its value in the transcript unlabelled, where redaction cannot see it. Use `safe-env` and filter by name to check it is set without printing it.'
    }
}

exit 0
