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
# The Read tool names a file instead of running a command. Only the path is
# judged, against the list of credential stores `cat` is judged by below; the
# content is not — a file of test fixtures has to stay readable, or it cannot be
# edited, since an edit requires a read first.
$readPath = $null
if (($payload.PSObject.Properties.Name -contains 'tool_name') -and
    ([string]$payload.tool_name -ieq 'read') -and
    ($payload.PSObject.Properties.Name -contains 'tool_input')) {
    foreach ($k in @('file_path', 'filePath')) {
        if ($payload.tool_input.PSObject.Properties.Name -contains $k) {
            $readPath = [string]$payload.tool_input.$k; break
        }
    }
}
# A relative path in pass E means the session's directory, which the payload names.
$sessionDir = $null
if ($payload.PSObject.Properties.Name -contains 'cwd') { $sessionDir = [string]$payload.cwd }
if ([string]::IsNullOrWhiteSpace($command) -and [string]::IsNullOrWhiteSpace($readPath)) { exit 0 }
if ($null -eq $command) { $command = '' }

# A heredoc body is data being written to a file, not a list of commands. Both
# passes below used to read it as commands, so writing a file whose text
# mentions `env` or `cat .env` was denied. `<<<` is a here-string, not a
# heredoc: after the second `<` comes a third, which is neither `-`, a space, a
# quote nor a letter, so it cannot match. The `cat > file` in front of the
# heredoc is still a command and is still scanned.
$kept = @()
$heredoc = ''
foreach ($line in ($command -split '\r?\n')) {
    if ($heredoc -ne '') {
        if ($line.Trim() -eq $heredoc) { $heredoc = '' }
        continue
    }
    if ($line -match '<<-?\s*["'']?([A-Za-z_][A-Za-z0-9_]*)') {
        $heredoc = $Matches[1]
    }
    $kept += $line
}
$command = $kept -join "`n"
if ([string]::IsNullOrWhiteSpace($command) -and [string]::IsNullOrWhiteSpace($readPath)) { exit 0 }

# ---------- too large to check ----------
# Failing open is the right answer to an unexpected payload — that contract
# stays. A command too big to finish is not an unexpected payload: it is the
# guard not doing its job, and a PreToolUse hook killed at the runner's timeout
# does not deny. The limit is a count rather than a clock, so it answers the
# same on every machine and needs nothing that has to be installed.
$GuardMaxSubs = 50000
$subCount = 0
foreach ($line in ($command -split '\r?\n')) {
    $subCount += 1 + ([regex]::Matches($line, '[;&|]')).Count
}
if ($subCount -gt $GuardMaxSubs) {
    Deny "[secrets-guard] Blocked: $subCount sub-commands is more than this guard can check ($GuardMaxSubs), so the command was never checked. Split it, or write the file with an editor instead of a heredoc."
}

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

    # `$tokens[1..($tokens.Count - 1)]` on a single-element array is
    # `$tokens[1..0]`, which PowerShell reads as a DESCENDING range and indexes
    # element 1 — out of bounds, and under Set-StrictMode that throws. The
    # sub-command `ANTHROPIC_MODEL=glm-5.2` is one token and an assignment, so
    # it hit this on the first line of the corpus. tests/test_parity_guard.sh
    # caught it; tests/test_guard.sh did not, because no case there is a bare
    # assignment.
    # The leading comma is load-bearing: a function returning @() unrolls it to
    # $null, and the next .Count throws under StrictMode. `,@()` returns the
    # empty array itself.
    function Drop-First ($t) {
        if ($t.Count -gt 1) { return ,@($t[1..($t.Count - 1)]) }
        return ,@()
    }

    while ($tokens.Count -gt 0 -and $wrappers -contains $tokens[0].ToLower()) {
        $tokens = Drop-First $tokens
    }
    # A leading assignment sets a variable for the command that follows; it is
    # not the command. Skipping only the token would have been right, and
    # instead the `=` failed the test below and the WHOLE sub-command was
    # abandoned — so `FOO=bar env` dumped the environment.
    while ($tokens.Count -gt 0 -and $tokens[0] -match '^[A-Za-z_][A-Za-z0-9_]*=') {
        $tokens = Drop-First $tokens
    }
    if ($tokens.Count -eq 0) { continue }

    # `\env` is the ordinary way to bypass an alias and `/usr/bin/env` the
    # ordinary way to bypass PATH. Neither is an evasion and both dumped the
    # environment. The basename names the program — the same reading
    # Test-OurCommand uses to decide whose hook entry is whose.
    $first = $tokens[0] -replace '^\\', ''
    $first = ($first -split '[\\/]')[-1]
    # Only a plain word can be a command name; "…, =…, {…, […, $…, *… are not.
    if ($first -notmatch '^[A-Za-z_][A-Za-z0-9_.:-]*$') { continue }

    $rest = Drop-First $tokens
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
        '^(printenv)$'          {
            # `-0` and `--null` change the separator, not the scope: with no
            # VARIABLE named, printenv still prints every pair.
            $named = $false
            foreach ($t in $rest) { if ($t -notlike '-*') { $named = $true } }
            if (-not $named) { Deny $EnvMessage }
        }
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


function Test-StoreRead([string]$rawSub) {
    $subScan = $rawSub -replace "'[^']*'", 'Q' -replace '"[^"]*"', 'Q'
    $pathScan = $rawSub -replace $script:envTemplates, '.TPLFILE'
    $reads = $subScan -match $script:readers
    $pathForStore = $pathScan
    $edit = (($rawSub -match $script:inplaceCmd) -and ($rawSub -match $script:inplaceFlag)) -or ($rawSub -match $script:awkInplace)
    if (-not $reads -and ($subScan -match $script:extractors) -and -not $edit) {
        $reads = $true
        # The first quoted span of a grep-like command is the pattern, not a
        # path: `grep -rn "cat .env" docs/` searches for the words. Dropped only
        # when nothing but flags precedes it, so `grep KEY "$HOME/.env"` keeps
        # its path.
        $pathForStore = Remove-FirstQuotedArgument $pathScan
    }
    return ($reads -and $pathForStore -match $script:secrets)
}

function Remove-FirstQuotedArgument([string]$text) {
    $out = New-Object System.Text.StringBuilder
    $inq = ''
    $dropped = $false
    for ($i = 0; $i -lt $text.Length; $i++) {
        $c = $text[$i]
        if ($inq -eq '') {
            if (($c -eq '"' -or $c -eq "'") -and -not $dropped) {
                $pre = $text.Substring(0, $i)
                # @() so a single token still has .Count — PowerShell unrolls
                # a one-element pipeline result into a bare string otherwise.
                $tokens = @($pre -split '\s+' | Where-Object { $_ -ne '' })
                $onlyFlags = $true
                for ($j = 1; $j -lt $tokens.Count; $j++) {
                    if (-not $tokens[$j].StartsWith('-')) { $onlyFlags = $false }
                    # `grep -f FILE` reads patterns FROM a file: the span after
                    # it is a path, not a pattern.
                    if ($tokens[$j] -eq '-f' -or $tokens[$j] -eq '--file') { $onlyFlags = $false }
                }
                if ($onlyFlags) { $inq = $c; $dropped = $true; continue }
            }
            [void]$out.Append($c)
        } elseif ($c -eq $inq) { $inq = '' }
    }
    return $out.ToString()
}

$readers = '(^|[\s;|&(])(cat|bat|batcat|tac|nl|head|tail|less|more|view|od|xxd|strings|type|gc|get-content)([\s]|$)'

# The extracting readers, kept apart because one of them is not always a read:
# `sed -i` and `awk -i inplace` write the file and print nothing. The POSIX
# guard carries the same two lists and the same exception.
$extractors = '(^|[\s;|&(])(grep|egrep|fgrep|rg|ag|ack|sed|awk|gawk|mawk|sort|uniq|cut|rev|column|jq|yq|select-string)([\s]|$)'
# Per command, not globally: `-i` is `--in-place` for sed and perl and
# `--ignore-case` for grep, rg, ag and ack. The POSIX guard carries the same
# three patterns.
$inplaceCmd = '(^|[\s;|&(])(sed|perl)\s'
$inplaceFlag = '(^|\s)(-i([^\s]*)?|--in-place([^\s]*)?)(\s|$)'
$awkInplace = '(^|[\s;|&(])(awk|gawk|mawk)\s.*-i\s+inplace'

# Kept identical to the POSIX version, store for store. Both path separators are
# accepted everywhere: a Windows path uses a backslash, and a Git Bash or WSL
# shell is routinely handed the other spelling.
$secrets = '((^|[\s"''/=])\.env([.\s"'']|$)' +          # .env
           '|(^|[\s"''/=])[A-Za-z0-9_-]+\.env([.\s"'']|$)' +   # prod.env, config/production.env
           '|[/\\][._](bashrc|zshrc|profile|bash_profile|zshenv|zprofile|netrc)' +
           '|(^|[\s"''/=])\.envrc([\s"'']|$)' +          # direnv

           '|id_rsa|id_ed25519|id_ecdsa' +              # private keys
           '|\.(pem|p12|pfx|key)([\s"'']|$)' +          # certificates and keys
           '|\.aws[/\\]credentials|\.docker[/\\]config\.json' +
           '|\.kube[/\\]config|\.azure[/\\]' +
           '|\.git-credentials|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf' +
           '|Microsoft\.PowerShell_profile\.ps1' +      # where $env:KEY is set
           # The stores of the tools a developer has open on the same day. Each
           # held a live token and printed it on request until 2026-09-17.
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
           '|/proc/([0-9]+|self|thread-self)/environ)'   # Linux only, by nature

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

# ── the Read tool: a path from the same list ───────────────────────────────
# Claude Code masks what Read returns afterwards, but a masked .env is still a
# list of every variable name and every value too short to look like a key.
if (-not [string]::IsNullOrWhiteSpace($readPath)) {
    $probe = ' ' + ($readPath -replace $envTemplates, '.TPLFILE')
    if ($probe -match $secrets) {
        Deny "[secrets-guard] Blocked: $readPath is a credential store, and reading it puts its values in the transcript. Check the one name you need with safe-env, or read a template such as .env.example."
    }
    if ([string]::IsNullOrWhiteSpace($command)) { exit 0 }
}

# ---------- pass D: a dump reached through something that runs commands -----
# `bash -c env`, `eval env` and `python3 -c "print(os.environ)"` are not
# evasions; they are shapes an assistant writes by habit, and pass A cannot see
# inside them because it works on quote-stripped text.
#
# The payload has to BE the dump command, not merely contain the word: that is
# what keeps `sh -c "set -e; make"` and `bash -c "echo env"` working. For the
# interpreters the test is the idiom instead, because the payload is not shell
# and parsing it is not on the table. Both lists are partial by construction —
# docs/design.md says so under "what this does not do".
$dumpWord = '(env|printenv|set|declare|typeset|history)'
$payload  = '(-c|-e|eval)\s*["'']?\s*' + $dumpWord + '\s*["'']?\s*$'
$idiom    = '(os\.environ|process\.env|%ENV|ENV\.to_h|ENV\.to_hash|ENV\.each)'
# A command substitution runs its body as a command, and pass A never sees it.
$subst    = '\$\(\s*' + $dumpWord + '\s*(\)|\|)'

foreach ($rawSub in $rawSubs) {
    if ([string]::IsNullOrWhiteSpace($rawSub)) { continue }
    if ($rawSub -cmatch $payload -or $rawSub -cmatch $subst -or $rawSub -cmatch $idiom) {
        Deny $EnvMessage
    }
}

foreach ($rawSub in $rawSubs) {
    if ([string]::IsNullOrWhiteSpace($rawSub)) { continue }
    # Same stripping as pass A: the reader must be a command, not a word inside
    # a quoted program.
    # A command substitution runs a command of its own, and the splitter does
    # not cut inside quotes — so `echo "$(cat ~/.env)"` arrives as one
    # sub-command whose reader sits in a stripped span. Each body is tested on
    # its own first. The POSIX guard does the same.
    $inner = $rawSub
    while ($inner -match '\$\(([^()]*)\)') {
        $body = $Matches[1]
        if (Test-StoreRead $body) {
            Deny '[secrets-guard] Blocked: that file can contain secrets. Read the one non-secret line you need, or use safe-env.'
        }
        $inner = $inner -replace [regex]::Escape($Matches[0]), 'CMDSUB'
    }
    if (Test-StoreRead $rawSub) {
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
    # A here-string prints its text too: `cat <<< "$GITHUB_TOKEN"` and
    # `tee <<< "$API_KEY"` put the value on stdout exactly as `echo` would, and
    # the gate used to be echo|printf only.
    if ($rawSub -notmatch '(^|\s)(echo|printf)(\s|$)' -and $rawSub -notmatch '<<<') { continue }
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


# ── pass E: what a reader would print, looked at before it prints it ────────
# Same pass as in bin/secrets-guard, and docs/design.*.md explains it: for a
# sub-command whose command prints files, every argument that names an existing
# regular file is run through the redactor's own --filter, and a line it changes
# — within the lines the command prints — denies the call. No redactor, a file
# over the size limit, or anything unreadable: the pass is skipped, never fatal.
$scanMax = 1048576
if ($env:SECRETS_GUARD_SCAN_MAX -match '^\d+$') { $scanMax = [int64]$env:SECRETS_GUARD_SCAN_MAX }
$redactor = $env:SECRETS_REDACT_BIN
if (-not $redactor) { $redactor = Join-Path $PSScriptRoot 'secrets-redact.ps1' }

function Get-ReaderTargets([string]$text) {
    $out = @()
    foreach ($line in ($text -split "`n")) {
        # Quote-aware tokens, with sub-command boundaries at ; & | ( ).
        $groups = @(); $tok = @(); $cur = ''; $q = ''; $have = $false
        foreach ($c in $line.ToCharArray()) {
            if ($q) { if ($c -eq $q) { $q = '' } else { $cur += $c }; continue }
            if ($c -eq '"' -or $c -eq "'") { $q = $c; $have = $true; continue }
            if (';&|()'.Contains($c)) {
                if ($have) { $tok += $cur; $cur = ''; $have = $false }
                if ($tok.Count) { $groups += ,$tok }; $tok = @(); continue
            }
            if ($c -eq ' ' -or $c -eq "`t") {
                if ($have) { $tok += $cur; $cur = ''; $have = $false }
                continue
            }
            $cur += $c; $have = $true
        }
        if ($have) { $tok += $cur }
        if ($tok.Count) { $groups += ,$tok }

        foreach ($g in $groups) {
            $j = 0
            while ($j -lt $g.Count -and ($g[$j] -in @('sudo', 'command', 'rtk') -or $g[$j] -match '^[A-Za-z_][A-Za-z0-9_]*=')) { $j++ }
            if ($j -ge $g.Count) { continue }
            $name = ($g[$j] -split '[/\\]')[-1]
            if ($name -notmatch '^(cat|bat|batcat|tac|nl|head|tail|less|more|view|od|xxd|strings|sed)$') { continue }
            $rest = @($g | Select-Object -Skip ($j + 1))
            if ($name -eq 'sed' -and ($rest | Where-Object { $_ -match '^(-i|--in-place)' })) { continue }

            # Which lines it prints. A = all, H = first N, T = last N,
            # F = from line N, S = lines a..b.
            $spec = 'A'
            if ($name -eq 'head' -or $name -eq 'tail') {
                $n = '10'
                for ($k = 0; $k -lt $rest.Count; $k++) {
                    if ($rest[$k] -eq '-n' -and $k + 1 -lt $rest.Count) { $n = $rest[$k + 1] }
                    elseif ($rest[$k] -match '^-n(\+?\d+)$') { $n = $Matches[1] }
                    elseif ($rest[$k] -match '^--lines=(.+)$') { $n = $Matches[1] }
                    elseif ($rest[$k] -match '^-(\d+)$') { $n = $Matches[1] }
                }
                if ($name -eq 'tail' -and $n -match '^\+(\d+)$') { $spec = "F:$($Matches[1])" }
                elseif ($n -match '^\d+$') { $spec = $(if ($name -eq 'head') { "H:$n" } else { "T:$n" }) }
            }
            if ($name -eq 'sed') {
                $quiet = $false; $script = ''
                foreach ($t in $rest) {
                    if ($t -in @('-n', '--quiet', '--silent')) { $quiet = $true }
                    elseif ($t -notmatch '^-' -and -not $script) { $script = $t }
                }
                if ($quiet -and $script -match '^(\d+)(,(\d+))?p$') {
                    $spec = 'S:' + $Matches[1] + ',' + $(if ($Matches[3]) { $Matches[3] } else { $Matches[1] })
                }
            }

            $skip = $false
            foreach ($w in $rest) {
                if ($skip) { $skip = $false; continue }
                if (($name -eq 'head' -or $name -eq 'tail') -and ($w -eq '-n' -or $w -eq '--lines')) { $skip = $true; continue }
                if ($w -match '^\d*>>?$' -or $w -eq '&>') { $skip = $true; continue }
                if ($w -match '^\d*>>?.' -or $w -match '^&>.') { continue }
                if ($w -eq '<') { continue }
                if ($w -match '^<[^<]') { $w = $w.Substring(1) }
                if ($w -match '^-') { continue }
                $out += [pscustomobject]@{ Spec = $spec; Path = $w }
            }
        }
    }
    return $out
}

if ($command -and (Test-Path -LiteralPath $redactor -PathType Leaf)) {
    if ($sessionDir -and (Test-Path -LiteralPath $sessionDir -PathType Container)) {
        Set-Location -LiteralPath $sessionDir
    }
    foreach ($t in (Get-ReaderTargets $command)) {
        $f = $t.Path
        if ($f -like '~/*') { $f = Join-Path $HOME $f.Substring(2) }
        elseif ($f -like '$HOME/*') { $f = Join-Path $HOME $f.Substring(6) }
        elseif ($f -like '${HOME}/*') { $f = Join-Path $HOME $f.Substring(8) }
        elseif ($f -match '[$*?\[]') { continue }
        try {
            if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
            $item = Get-Item -LiteralPath $f
            if ($item.Length -gt $scanMax) { continue }
            $orig = [System.IO.File]::ReadAllText($item.FullName)
            $pwshExe = (Get-Process -Id $PID).Path
            $masked = $orig | & $pwshExe -NoProfile -File $redactor --filter 2>$null
            $masked = ($masked -join "`n")
        } catch { continue }

        $a = $orig -split "`r?`n"; $b = $masked -split "`r?`n"
        $first = 1; $last = 0
        switch -regex ($t.Spec) {
            '^H:(\d+)$' { $last = [int]$Matches[1] }
            '^F:(\d+)$' { $first = [int]$Matches[1] }
            '^T:(\d+)$' {
                $total = $a.Count; if ($orig.EndsWith("`n")) { $total-- }
                $first = [Math]::Max(1, $total - [int]$Matches[1] + 1)
            }
            '^S:(\d+),(\d+)$' { $first = [int]$Matches[1]; $last = [int]$Matches[2] }
        }
        $hits = 0; $lines = @()
        for ($i = 0; $i -lt $b.Count; $i++) {
            $ln = $i + 1
            if ($ln -lt $first -or ($last -gt 0 -and $ln -gt $last)) { continue }
            $was = if ($i -lt $a.Count) { $a[$i] } else { $null }
            if ($b[$i] -ne $was) {
                $hits += ([regex]::Matches($b[$i], '<REDACTED:')).Count
                $lines += $ln
            }
        }
        if ($hits -gt 0) {
            $shown = ($lines | Select-Object -First 5) -join ','
            if ($lines.Count -gt 5) { $shown += ',…' }
            Deny "[secrets-guard] Blocked: $($t.Path) holds $hits credential-shaped value(s) on line(s) $shown, and printing it puts them in the transcript. Read it masked instead: secrets-redact --filter < $($t.Path)"
        }
    }
}
exit 0
