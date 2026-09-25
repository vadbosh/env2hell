<#
.SYNOPSIS
    secrets-redact — mask a secret a command already printed, before the model
    reads it. PowerShell port of bin/secrets-redact.

.DESCRIPTION
    secrets-guard stops a command that would *read* a secret. It cannot stop a
    command whose output happens to *contain* one: a program invoked with a
    password prints that password back, and nothing in a PreToolUse hook can
    know that in advance.

    This runs after the tool and replaces the output before the model sees it.
    Two tiers, deliberately:

      tier 1  provider-shaped tokens (ghp_, glpat-, AKIA, JWT, credentials
              inside a URL). Unambiguous — masked anywhere. A private key is
              the one member of this tier that is a *block* rather than a
              match: the header line starts it, the footer ends it, and the
              body between them is replaced line for line.

      tier 2  a high-entropy run only when a label on the same line says it is
              a secret: --pass, --token, password=, Authorization: Bearer, or
              an assignment whose NAME reads like a credential. Tier 1 cannot
              catch an unprefixed hex password, and matching bare hex
              everywhere would redact every md5sum and git SHA the model needs.
              The label is what separates the two.

    Fails open: unparsable input or nothing to mask means exit 0 with no
    output, which leaves the tool result exactly as it was. A hook that breaks
    the session is worse than a hook that misses one secret.

    The exit code means different things in the two roles:

      as a hook (JSON in)     always 0, including "nothing matched". That is
                              the fail-open contract above.
      as a filter (text in)   0 something was masked, 1 the text came through
                              unchanged — grep's convention, so a caller can
                              skip the assignment rather than rewrite a string
                              with itself. In a pipeline that treats non-zero
                              as failure, that 1 is a trap.

.EXAMPLE
    Get-Content out.txt | secrets-redact.ps1 --filter
    secrets-redact.ps1 --self-test
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── tier 1: provider-shaped tokens ──────────────────────────────────────────
# Character for character the list in bin/safe-env.ps1. The two are kept in
# step by tests/test_redact.sh, which compares them; edit both or neither.
$patterns = @(
    'AKIA[0-9A-Z]{16}'
    '(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,}'
    'github_pat_[A-Za-z0-9_]{22,}'
    'glpat-[A-Za-z0-9_-]{20,}'
    'xox[baprs]-[A-Za-z0-9-]{10,}'
    'tvly-[A-Za-z0-9-]{10,}'
    'AIza[A-Za-z0-9_-]{35}'
    '(sk|rk)_live_[A-Za-z0-9]{20,}'
    '(?<![A-Za-z0-9_-])sk-(or-v1-|proj-|ant-)?[A-Za-z0-9-]{20,}'
    'at-[A-Za-z0-9]{30,}'
    'ATATT[A-Za-z0-9_=.-]{20,}'
    'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.'
    '://[^/:@\s]+:[^/:@\s]{3,}@'
    'BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY'
)
# Case-sensitive, like the POSIX version: `akia…` in lower case is not an AWS
# key, and masking it would eat ordinary words.
$patternsRe = [regex]::new(($patterns -join '|'), 'None')

# ── tier 2: what a secret is called, and what one looks like ────────────────
$Label = '(--?)?(pass|passwd|password|pass-phrase|passphrase|token|secret|' +
         'api[-_]?key|apikey|auth[-_]?token|access[-_]?key|' +
         'client[-_]?secret|private[-_]?key|credential|authorization|' +
         # SQL says it in two words: CREATE USER … IDENTIFIED BY '…', the same
         # spelling in Oracle, MySQL and MariaDB. `bin/safe-env` has carried
         # this rule since the first commit and the redactor did not — the
         # shape of drift two implementations of one policy produce in silence.
         'identified[ \t]+by|' +
         # Cloud keys with no distinctive prefix. AWS is covered by tier 1
         # (AKIA…), Huawei and OpenStack are not: their access key is 20
         # characters of uppercase and digits, the secret 40 of base62 — shapes
         # that also describe a git SHA and half the identifiers in ordinary
         # output. The variable name is the only reliable signal.
         'hw[-_]?(access|secret)([-_]?key)?|huaweicloud?[-_]?[a-z_]*key|' +
         'os[-_](access|secret)[-_]?key)s?'
# 16 is the floor: an md5 is 32 and a git SHA is 40, so length alone can never
# decide this — only the label can.
$Value = '[A-Za-z0-9+/=_.~-]{16,}'
# A password is the one string that carries punctuation — `S3cr3t!Pass#2026`
# stops at the first `!` in the class above, six characters short of the floor,
# and went through untouched. Inside quotes the writer has already said where
# the value ends, so the quotes are the boundary. 8 is the floor there: a quoted
# run is far less ambiguous than a bare one.
$Quoted = '"[^"\n]{8,}"|''[^''\n]{8,}'''
# Below the floor, and unquoted. The floor of 16 held until 2026-09-21, when a
# 10-character password in a docker-compose comment went through a hook that was
# installed, wired and working. A short value is admitted here and decided by
# composition in Test-KeepBare: lower case, upper case and a digit together is
# what a generated credential looks like and what prose does not.
$Short  = '[A-Za-z0-9._~+/-]{8,15}'
$AnyVal = '(?:' + $Quoted + '|' + $Value + '|' + $Short + ')'

# The label is matched without regard to case. `TOKEN: 6310…` is how a token
# appears in most output there is — an env dump, a config echo, a CI log — and
# the POSIX version missed all of it until 2026-09-14 because awk matches case
# sensitively and the list is written in lower case.
# Named groups, not numbered: $Label carries five parenthesised alternations of
# its own, so the value would land at group 7 and move again the next time a
# cloud vendor is added to the list.
# `"?` in front of the separator: the JSON spelling puts a closing quote between
# the label and the colon — {"password": "…"} — and neither pattern admitted it.
# `(bearer|basic|token) ` after it: an HTTP header puts the scheme between the
# label and the value, and the scheme stays readable for the same reason the
# label does.
$Scheme = '(?:(?:bearer|basic|token)[^\S\n]+)?'
# Both spellings in one pattern rather than two Replace passes over the text:
# `password=X`, `TOKEN: X`, `{"password": X}` and `--pass X`. The POSIX version
# folds them for a different reason — there two dynamic regexes miss gawk's
# compile cache — and here it simply halves the work.
$Separator = '"?(?:[^\S\n]*[=:][^\S\n]*|[^\S\n]+)'
#
# Deliberately not RegexOptions.Compiled. Measured 2026-09-16, ten runs each:
# compiling costs 0.107 s per invocation and saves 0.32 s on a 1.1 MB payload,
# so it pays for itself only above roughly 340 KB. This runs once per tool call,
# and a tool result is usually kilobytes — the common case would pay the
# start-up and never see the saving.
$Labelled  = [regex]::new(
    '(?<head>' + $Label + $Separator + $Scheme + ')(?<val>' + $AnyVal + ')',
    'IgnoreCase')

# Tier 2 fires on a label followed by any long-enough run of token characters,
# and that description also fits a name. Measured 2026-09-14 over 69 Codex
# transcripts: of 51 flagged lines, about 35 were an identifier in source code,
# a metavar in --help output, a Terraform reference or a Kubernetes object name.
# Reading a file with `outputTokens: usage.outputTokens` handed the model
# `<REDACTED:18>` where the name should be.
#
# A credential rarely looks like a name. Each rule is narrow on purpose: the
# metavar rule demands an underscore rather than matching upper case alone,
# because a Huawei access key is 20 characters of uppercase and digits.
$NameShapes = @(
    '^\$'                                  # $VAR, ${VAR}
    '^(var|data|local|module|each|self)\.'  # Terraform reference
    '^[~.]?/'                               # /path ./path ~/path
    '^[A-Za-z_][A-Za-z_.]*\.[A-Za-z_.]*$'   # pkg.field.name
    '^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$'         # ANTHROPIC_API_KEY
    '^[a-z]+(-[a-z]+)+$'                    # prometheus-operator
    '^[a-z]+(_[a-z]+)+$'                    # aws_secrets_manager
)

function Test-Name([string]$Value) {
    foreach ($p in $NameShapes) { if ($Value -cmatch $p) { return $true } }
    return $false
}

# The unquoted branch of tier 2. A quoted value is not decided here: the writer
# has already said where it begins and ends, so its floor stays 8 and its
# composition is not examined.
function Test-KeepBare([string]$Value) {
    if (Test-Name $Value)     { return $true }
    if ($Value.Length -ge 16) { return $false }   # the old floor, unchanged
    # Short and unquoted: mask only what reads as generated. `Tr0ub4dor` is a
    # password by this rule and was deliberately left alone before 0.9.0 -- the
    # gap that cost a real credential. `deploy_v2`, `main-2026` and `utf8mb4`
    # are not, because each is missing one of the three classes.
    return -not ($Value -cmatch '[a-z]' -and $Value -cmatch '[A-Z]' -and $Value -cmatch '[0-9]')
}

$script:Hits = 0

function Get-Mask([string]$Value) { "<REDACTED:$($Value.Length)>" }

# A credential glued to its flag, or after a colon in a user:password pair.
# The labelled rule above needs a separator; these four client idioms have none,
# and each is gated on the command that owns it because -p, -a and -u mean other
# things elsewhere (ls -p, grep -a, sort -u). The POSIX file carries the same
# four, gated the same way.
$GluedRules = @(
    @{ Cmd = [regex]::new('(^|[^\S\n])(mysql|mariadb|mysqldump|mysqladmin)([^\S\n]|$)', 'IgnoreCase')
       Pat = [regex]::new('(?<head>(^|[^\S\n])-p)(?<val>[^\s]{8,})', 'IgnoreCase') }
    @{ Cmd = [regex]::new('(^|[^\S\n])redis-cli([^\S\n]|$)', 'IgnoreCase')
       Pat = [regex]::new('(?<head>(^|[^\S\n])-a[^\S\n]+)(?<val>[^\s]{8,})', 'IgnoreCase') }
    @{ Cmd = [regex]::new('(^|[^\S\n])smbclient([^\S\n]|$)', 'IgnoreCase')
       Pat = [regex]::new('(?<head>(^|[^\S\n])-U[^\S\n]*[A-Za-z0-9_.@-]+%)(?<val>[^\s]{8,})', 'IgnoreCase') }
    @{ Cmd = [regex]::new('(^|[^\S\n])(curl|wget|http)([^\S\n]|$)|--user[^\S\n]', 'IgnoreCase')
       Pat = [regex]::new('(?<head>(^|[^\S\n])(-u|--user)[^\S\n]+[A-Za-z0-9_.@-]+:)(?<val>[^\s]{8,})', 'IgnoreCase') }
)

function Edit-Glued([string]$Line) {
    foreach ($rule in $GluedRules) {
        if (-not $rule.Cmd.IsMatch($Line)) { continue }
        $Line = $rule.Pat.Replace($Line, {
            param($m)
            $script:Hits++
            $m.Groups['head'].Value + (Get-Mask $m.Groups['val'].Value)
        })
    }
    return $Line
}

function Edit-Line([string]$Line) {
    if ($Line -eq '') { return $Line }
    $out = $patternsRe.Replace($Line, {
        param($m) $script:Hits++; Get-Mask $m.Value
    })
    # The label itself stays readable: `--pass 6310…` must come back as
    # `--pass <REDACTED:32>`, or the model cannot tell what was removed.
    $out = $Labelled.Replace($out, {
            param($m)
            $v = $m.Groups['val'].Value
            # A quoted value keeps its quotes: they belong to the line, not to
            # the secret, and `password="<REDACTED:20>"` still reads as a
            # quoted field.
            $q = ''
            if ($v.Length -ge 2 -and ($v[0] -eq '"' -or $v[0] -eq "'") -and $v[-1] -eq $v[0]) {
                $q = [string]$v[0]
                $v = $v.Substring(1, $v.Length - 2)
            }
            # A quoted value only has to clear Test-Name; an unquoted one is
            # also judged on length and composition.
            $keep = if ($q) { Test-Name $v } else { Test-KeepBare $v }
            if ($keep) { return $m.Value }            # a name, not a value
            $script:Hits++
            $m.Groups['head'].Value + $q + (Get-Mask $v) + $q
    })
    $out = Edit-Glued $out
    return $out
}

# .NET matches over the whole text in one pass, and that is the only reason
# this port is usable: calling Edit-Line per line costs 143 s per megabyte
# against 2.3 s for a single pass — measured 2026-09-16 on 25 857 lines, where
# the per-line version spends everything on 25 857 function calls and two
# script-block callbacks each.
#
# One pass over the whole text means the patterns have to be line-local by
# construction, since `\s` and `[^"]` both match a newline. Hence `[^\S\n]`
# for the separators above and `[^"\n]` inside the quoted value: a label on one
# line must not reach a value on the next.
#
# A private key is the exception that genuinely spans lines, so it is taken
# first, with a variable-length lookbehind (.NET has them) anchored to the
# header line. Tier 1 matches the BEGIN text and nothing else, so before this
# the result came back with `-----<REDACTED:25>-----` on top and the key itself
# intact underneath — which reads as handled and is not. The body is replaced
# line for line, so a diff of the result against the file still lines up.
$KeyBody = [regex]::new(
    '(?<=^-+BEGIN [A-Z0-9 ]*PRIVATE KEY-+\r?$\n)(?s:.*?)(?=^-+END [A-Z0-9 ]*PRIVATE KEY)',
    'Multiline')

function Edit-Text([string]$Text) {
    if ($Text -eq '') { return $Text }
    $out = $KeyBody.Replace($Text, {
        param($m)
        ($m.Value.Split([char]10) | ForEach-Object {
            if ($_ -eq '') { $_ } else { $script:Hits++; Get-Mask $_ }
        }) -join "`n"
    })
    return (Edit-Line $out)
}

function Read-Stdin { $input_ = [Console]::In.ReadToEnd(); return $input_ }

# ── the journal ─────────────────────────────────────────────────────────────
# One line per invocation, never a value. It exists because of 2026-09-21: from
# outside the process, "the hook was never called", "it was called and matched
# nothing" and "it was called and the host ignored the replacement" all look
# identical — like nothing at all. The POSIX side writes the same format to the
# same file, so one reader answers for both.
$script:LogPath = if ($env:ENV2HELL_LOG) { $env:ENV2HELL_LOG }
                  elseif ($env:XDG_STATE_HOME) { Join-Path $env:XDG_STATE_HOME 'env2hell/redact.log' }
                  elseif ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'env2hell\redact.log' }
                  else { Join-Path $HOME '.local/state/env2hell/redact.log' }
function Write-Journal([string]$Mode, [string]$Tool, $Bytes) {
    if ($script:LogPath -eq 'off') { return }
    try {
        $dir = Split-Path -Parent $script:LogPath
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $max = if ($env:ENV2HELL_LOG_MAX) { [int]$env:ENV2HELL_LOG_MAX } else { 1048576 }
        if ((Test-Path $script:LogPath) -and (Get-Item $script:LogPath).Length -gt $max) {
            Move-Item -Force $script:LogPath "$($script:LogPath).1"
        }
        $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $masked = if ($script:Hits -gt 0) { 'yes' } else { 'no' }
        Add-Content -Path $script:LogPath -Value "$stamp mode=$Mode tool=$Tool bytes=$Bytes masked=$masked"
    } catch { }      # a read-only log directory must never break masking
}

$mode = if ($args.Count -gt 0) { [string]$args[0] } else { '' }

# ── self-test ───────────────────────────────────────────────────────────────
if ($mode -eq '--self-test') {
    $sample = @(
        'croc --relay h:9009 --pass 00112233445566778899aabbccddeeff code-word'
        'md5sum: deadbeefdeadbeefdeadbeefdeadbeef  big.bin'
        'export GH=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB'
    ) -join "`n"
    Edit-Text $sample
    exit 0
}

# ── --filter: plain text in, masked text out ────────────────────────────────
# What the Opencode plugin calls, and what is usable by hand in a pipe. Exit 0
# means something was masked, 1 means the text came through unchanged, so a
# caller can skip the assignment rather than rewrite a string with itself.
if ($mode -eq '--filter') {
    $text = Read-Stdin
    [Console]::Out.Write((Edit-Text $text))
    Write-Journal 'filter' '-' $text.Length
    exit $(if ($script:Hits -gt 0) { 0 } else { 1 })
}

# ── hook mode ───────────────────────────────────────────────────────────────
$raw = Read-Stdin
if ([string]::IsNullOrEmpty($raw)) { exit 0 }

try { $payload = $raw | ConvertFrom-Json } catch { exit 0 }   # fail open
if ($null -eq $payload) { exit 0 }

# Named before anything can bail out, and written by a trap-equivalent at the
# end of every path below: a call that produced no line is a call that never
# reached the hook, which is exactly the distinction that was missing.
$script:LogMode = if ($mode -eq '--warn-only') { 'warn' } else { 'hook' }
$script:LogTool = try { if ($payload.tool_name) { [string]$payload.tool_name } else { '-' } } catch { '-' }
$script:LogBytes = $raw.Length
# An explicit call rather than a trap or an exiting-event handler: `exit` is not
# a terminating error, so a trap never runs, and the engine-exiting event does
# not fire when the script is dot-sourced into a host -- which is how the test
# suites call it. Every path out of hook mode goes through this.
function Exit-Hook([int]$Code = 0) {
    Write-Journal $script:LogMode $script:LogTool $script:LogBytes
    exit $Code
}

$resp = $null
try { $resp = $payload.tool_response } catch { $resp = $null }

# A failed command carries no tool_response at all: Claude Code routes it to
# PostToolUseFailure, whose output lives in a top-level `error` string. Only
# --warn-only can do anything with that, and only because the failure event has
# no field that would replace a result.
$errText = $null
try { $errText = $payload.error } catch { $errText = $null }
if ($null -eq $resp -and $errText -isnot [string]) { Exit-Hook 0 }

$ctx = '[secrets-redact] A secret-shaped value in this output was replaced ' +
       'with <REDACTED:length>. Do not try to recover it, and do not print ' +
       'the command that produced it.'

function Get-Field($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -isnot [psobject]) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# ── warn-only, where a result cannot be replaced ────────────────────────────
# Two events land here, and neither can be rewritten. Codex's
# PostToolUseOutcome carries should_block, additional_contexts and
# feedback_message, and nothing that replaces output. Claude Code's
# PostToolUseFailure — the event a non-zero exit fires instead of PostToolUse —
# documents `additionalContext` and nothing else.
#
# So for a failed command there is no masking to be had, and a failing command
# is exactly when a credential surfaces. What is left is to say so: the model
# learns a credential is now in the transcript, which is what turns a silent
# leak into a rotation. The message never repeats the value and never says
# which command produced it — both would put a second copy in the very
# transcript being warned about.
if ($mode -eq '--warn-only') {
    # Every string anywhere in the result, plus the failure event's top-level
    # `error`. Detection can afford a recursive walk where replacement cannot:
    # nothing is rebuilt here, so an unfamiliar schema costs a false positive at
    # worst, never a mangled result. An Edit result carries the file in four
    # places and an MCP result is an array of content blocks whose schema
    # belongs to the server — enumerating those fields would miss the next one.
    function Get-Strings($Node) {
        if ($Node -is [string]) { return @($Node) }
        $out = @()
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($item in $Node) { $out += Get-Strings $item }
            return $out
        }
        if ($Node -is [psobject]) {
            foreach ($prop in $Node.PSObject.Properties) { $out += Get-Strings $prop.Value }
        }
        return $out
    }

    # Except `originalFile`: Claude Code hands the hook the whole file there and
    # keeps none of it — the transcript stores the field empty, beside
    # `contentNotInModelContext`. Counting it warned about credentials that
    # never reached the session. The edited region is still read through
    # oldString, newString and structuredPatch.
    if ($resp -is [psobject] -and $resp.PSObject.Properties['originalFile']) {
        $resp = $resp | Select-Object -Property * -ExcludeProperty originalFile
    }

    $parts = @()
    if ($errText -is [string]) { $parts += $errText }
    if ($null -ne $resp)       { $parts += Get-Strings $resp }
    $text = ($parts -join "`n")
    if ($text -eq '') { Exit-Hook 0 }
    $null = Edit-Text $text
    if ($script:Hits -le 0) { Exit-Hook 0 }
    # Named back exactly as it arrived: a hook wired to PostToolUseFailure that
    # answers "PostToolUse" is answering a question nobody asked, and the reply
    # is dropped.
    $eventName = 'PostToolUse'
    $en = Get-Field $payload 'hook_event_name'
    if ($en -is [string] -and $en -ne '') { $eventName = $en }
    @{
        hookSpecificOutput = @{
            hookEventName     = $eventName
            additionalContext = "[secrets-redact] This output contains $($script:Hits) " +
                'credential-shaped value(s). It cannot be removed here, so it is already ' +
                'in the transcript. Do not repeat it, do not echo the command that ' +
                'produced it, and tell the user the value has to be rotated.'
        }
    } | ConvertTo-Json -Depth 20 -Compress
    Exit-Hook 0
}

# A result arrives in one of four shapes, and they are not interchangeable —
# replacing an output with the wrong schema is worse than not replacing it:
#
#   streams   {"stdout": …, "stderr": …}      a shell call that succeeded
#   file      {"file": {"content": …}, …}     what the Read tool returns
#   content   {"content": "…"}                one blob; Grep returns this
#   string    "…"                             a result handed over whole
#
# The string branch is defensive, not a path any assistant here is known to
# take. A non-zero exit reaches Claude Code's PostToolUseFailure instead, where
# the output is a top-level `error` string and nothing can replace it — see the
# --warn-only branch above.
$stdout = Get-Field $resp 'stdout'
$stderr = Get-Field $resp 'stderr'
$file   = Get-Field $resp 'file'
$fileC  = Get-Field $file 'content'
$content = Get-Field $resp 'content'

$shape =
    if ($resp -is [string])                            { 'string'  }
    elseif ($stdout -is [string] -or $stderr -is [string]) { 'streams' }
    elseif ($fileC -is [string])                       { 'file'    }
    elseif ($content -is [string])                     { 'content' }
    else                                               { 'other'   }

if ($shape -eq 'other' -or $null -eq $resp) { Exit-Hook 0 }

try {
    switch ($shape) {
        'string' {
            $new = Edit-Text $resp
            if ($script:Hits -le 0) { Exit-Hook 0 }
            $updated = $new
        }
        'streams' {
            $o = if ($stdout -is [string]) { $stdout } else { '' }
            $e = if ($stderr -is [string]) { $stderr } else { '' }
            $no = Edit-Text $o
            $ne = Edit-Text $e
            if ($script:Hits -le 0) { Exit-Hook 0 }
            # Rebuild from the original tool_response so fields this hook knows
            # nothing about survive intact.
            $resp.stdout = $no
            $resp.stderr = $ne
            $updated = $resp
        }
        'file' {
            $nf = Edit-Text $fileC
            if ($script:Hits -le 0) { Exit-Hook 0 }
            $file.content = $nf
            $updated = $resp
        }
        'content' {
            $nc = Edit-Text $content
            if ($script:Hits -le 0) { Exit-Hook 0 }
            $resp.content = $nc
            $updated = $resp
        }
    }

    @{
        hookSpecificOutput = @{
            hookEventName     = 'PostToolUse'
            updatedToolOutput = $updated
            additionalContext = $ctx
        }
    } | ConvertTo-Json -Depth 20 -Compress
} catch {
    Exit-Hook 0            # fail open, never break the session
}

Exit-Hook 0
