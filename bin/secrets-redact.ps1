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

      tier 1  provider-shaped tokens (ghp_, glpat-, AKIA, JWT, private key
              blocks, credentials inside a URL). Unambiguous — masked anywhere.

      tier 2  a high-entropy run only when a label on the same line says it is
              a secret: --pass, --token, password=, Authorization: Bearer, or
              an assignment whose NAME reads like a credential. Tier 1 cannot
              catch an unprefixed hex password, and matching bare hex
              everywhere would redact every md5sum and git SHA the model needs.
              The label is what separates the two.

    Fails open: unparsable input or nothing to mask means exit 0 with no
    output, which leaves the tool result exactly as it was. A hook that breaks
    the session is worse than a hook that misses one secret.

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
    'sk-(or-v1-|proj-|ant-)?[A-Za-z0-9-]{20,}'
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
         'client[-_]?secret|private[-_]?key|credential|' +
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

# The label is matched without regard to case. `TOKEN: 6310…` is how a token
# appears in most output there is — an env dump, a config echo, a CI log — and
# the POSIX version missed all of it until 2026-09-14 because awk matches case
# sensitively and the list is written in lower case.
# Named groups, not numbered: $Label carries five parenthesised alternations of
# its own, so the value would land at group 7 and move again the next time a
# cloud vendor is added to the list.
$Labelled = @(
    [regex]::new('(?<head>' + $Label + '\s*[=:]\s*"?)(?<val>' + $Value + ')', 'IgnoreCase')  # password=X, TOKEN: X
    [regex]::new('(?<head>' + $Label + '\s+"?)(?<val>'       + $Value + ')', 'IgnoreCase')   # --pass X, --token X
)

$script:Hits = 0

function Get-Mask([string]$Value) { "<REDACTED:$($Value.Length)>" }

function Edit-Line([string]$Line) {
    if ($Line -eq '') { return $Line }
    $out = $patternsRe.Replace($Line, {
        param($m) $script:Hits++; Get-Mask $m.Value
    })
    # The label itself stays readable: `--pass 6310…` must come back as
    # `--pass <REDACTED:32>`, or the model cannot tell what was removed.
    foreach ($re in $Labelled) {
        $out = $re.Replace($out, {
            param($m) $script:Hits++; $m.Groups['head'].Value + (Get-Mask $m.Groups['val'].Value)
        })
    }
    return $out
}

# Splitting on "`n" with -1 keeps the trailing empty element, so joining puts
# the text back byte for byte — including whether it ended in a newline, and
# including a \r that a CRLF stream carries. This masks; it does not reformat.
function Edit-Text([string]$Text) {
    if ($Text -eq '') { return $Text }
    $lines = $Text -split "`n", -1
    for ($i = 0; $i -lt $lines.Count; $i++) { $lines[$i] = Edit-Line $lines[$i] }
    return ($lines -join "`n")
}

function Read-Stdin { $input_ = [Console]::In.ReadToEnd(); return $input_ }

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
    exit $(if ($script:Hits -gt 0) { 0 } else { 1 })
}

# ── hook mode ───────────────────────────────────────────────────────────────
$raw = Read-Stdin
if ([string]::IsNullOrEmpty($raw)) { exit 0 }

try { $payload = $raw | ConvertFrom-Json } catch { exit 0 }   # fail open
if ($null -eq $payload) { exit 0 }

$resp = $null
try { $resp = $payload.tool_response } catch { $resp = $null }

# A failed command carries no tool_response at all: Claude Code routes it to
# PostToolUseFailure, whose output lives in a top-level `error` string. Only
# --warn-only can do anything with that, and only because the failure event has
# no field that would replace a result.
$errText = $null
try { $errText = $payload.error } catch { $errText = $null }
if ($null -eq $resp -and $errText -isnot [string]) { exit 0 }

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

    $parts = @()
    if ($errText -is [string]) { $parts += $errText }
    if ($null -ne $resp)       { $parts += Get-Strings $resp }
    $text = ($parts -join "`n")
    if ($text -eq '') { exit 0 }
    $null = Edit-Text $text
    if ($script:Hits -le 0) { exit 0 }
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
    exit 0
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

if ($shape -eq 'other' -or $null -eq $resp) { exit 0 }

try {
    switch ($shape) {
        'string' {
            $new = Edit-Text $resp
            if ($script:Hits -le 0) { exit 0 }
            $updated = $new
        }
        'streams' {
            $o = if ($stdout -is [string]) { $stdout } else { '' }
            $e = if ($stderr -is [string]) { $stderr } else { '' }
            $no = Edit-Text $o
            $ne = Edit-Text $e
            if ($script:Hits -le 0) { exit 0 }
            # Rebuild from the original tool_response so fields this hook knows
            # nothing about survive intact.
            $resp.stdout = $no
            $resp.stderr = $ne
            $updated = $resp
        }
        'file' {
            $nf = Edit-Text $fileC
            if ($script:Hits -le 0) { exit 0 }
            $file.content = $nf
            $updated = $resp
        }
        'content' {
            $nc = Edit-Text $content
            if ($script:Hits -le 0) { exit 0 }
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
    exit 0            # fail open, never break the session
}

exit 0
