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

foreach ($part in ($scan -split '\|\||&&|;|&|\|')) {
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
        if ($ch -eq ';' -or $ch -eq '&' -or $ch -eq '|') { $rawSubs += $buf; $buf = ''; continue }
        $buf += $ch
    } else {
        if ($ch -eq $quote) { $quote = '' }
        $buf += $ch
    }
}
$rawSubs += $buf

foreach ($rawSub in $rawSubs) {
    if ([string]::IsNullOrWhiteSpace($rawSub)) { continue }
    # Same stripping as pass A: the reader must be a command, not a word inside
    # a quoted program.
    $subScan = $rawSub -replace "'[^']*'", 'Q' -replace '"[^"]*"', 'Q'
    if ($subScan -match $readers -and $rawSub -match $secrets) {
        Deny '[secrets-guard] Blocked: that file can contain secrets. Read the one non-secret line you need, or use safe-env.'
    }
}

exit 0
