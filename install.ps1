<#
.SYNOPSIS
    Install env2hell on Windows. Needs neither Python nor Git Bash.

.DESCRIPTION
    Copies the two PowerShell commands into a directory of your choosing
    (%LOCALAPPDATA%\Programs\env2hell by default), then wires every assistant
    it finds to call the guard before each shell command.

    Claude Code and Codex take a PreToolUse hook; the hook is registered with
    "shell": "powershell" so it runs without a POSIX shell present. Opencode
    takes a plugin plus a set of permission rules.

    Idempotent: a configuration file about to change is copied to
    <file>.bak.<timestamp> first, and re-running rewrites only what differs.

    Run one installer at a time. Each configuration is written in place, not
    through a temporary file, so two installers running together can leave one
    half-written. The POSIX installer renames a temporary file into place and
    only ever loses the slower run's change.

.PARAMETER DryRun
    Print what would happen and change nothing.

.PARAMETER Ide
    Install into one assistant only: claude, opencode or codex.

.PARAMETER BinDir
    Where the two commands go.

.PARAMETER NoRule
    Wire the guard, but do not install the documentation rule.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -DryRun
    .\install.ps1 -Ide claude
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [ValidateSet('claude', 'opencode', 'codex')][string]$Ide,
    [string]$BinDir = "$env:LOCALAPPDATA\Programs\env2hell",
    [switch]$NoRule
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Src   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Home_ = $env:USERPROFILE
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function Say  ($m) { Write-Host $m }
function Ok   ($m) { Write-Host $m -ForegroundColor Green }
function Warn ($m) { Write-Host $m -ForegroundColor Yellow }
function Bad  ($m) { Write-Host $m -ForegroundColor Red }

# ConvertTo-Json stops at depth 2 unless told otherwise, which silently turns
# nested configuration into the string "System.Object[]". Always pass -Depth.
function Read-Json ($Path)          { Get-Content -Raw -Encoding UTF8 $Path | ConvertFrom-Json }
function Write-Json ($Path, $Data) {
    if ($DryRun) { return }
    Copy-Item $Path "$Path.bak.$Stamp" -Force
    ($Data | ConvertTo-Json -Depth 100) | Set-Content -Encoding UTF8 $Path
}

function Install-File ($Source, $Target) {
    if ((Test-Path $Target) -and
        ((Get-FileHash $Source).Hash -eq (Get-FileHash $Target).Hash)) {
        Say "    = $Target"; return
    }
    if ($DryRun) { Say "    would write $Target"; return }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Target) | Out-Null
    if (Test-Path $Target) {
        Copy-Item $Target "$Target.bak.$Stamp" -Force
        Say "    ~ $Target  (backup .bak.$Stamp)"
    } else {
        Say "    + $Target"
    }
    Copy-Item $Source $Target -Force
}

# Only assistants that are already installed are written to.
function Get-Ides {
    if ($Ide) { return @($Ide) }
    $found = @()
    if (Test-Path "$Home_\.claude")          { $found += 'claude' }
    if (Test-Path "$Home_\.config\opencode") { $found += 'opencode' }
    if (Test-Path "$Home_\.codex")           { $found += 'codex' }
    return $found
}

function Get-ConfigPath ($Name) {
    switch ($Name) {
        'claude'   { "$Home_\.claude\settings.json" }
        'codex'    { "$Home_\.codex\hooks.json" }
        'opencode' { "$Home_\.config\opencode\opencode.json" }
    }
}

function Get-RuleTarget ($Name) {
    switch ($Name) {
        'claude'   { "$Home_\.claude\rules\secrets-hygiene.md" }
        'opencode' { "$Home_\.config\opencode\instructions\secrets-hygiene.md" }
        'codex'    { "$Home_\.codex\memories\secrets-hygiene.md" }
    }
}

# Same rule set as the POSIX installer — see lib/patch_config.py.
$DumpRules = [ordered]@{
    'env' = 'deny'; 'printenv' = 'deny'; 'printenv *' = 'ask'
    'export -p*' = 'deny'; 'set' = 'deny'; 'declare' = 'deny'
    'typeset' = 'deny'; 'history' = 'deny'
    'safe-env' = 'allow'; 'safe-env *' = 'allow'
}
# See lib/patch_config.py (REDACT_TIMEOUT) for why this is 60 and not 10.
$RedactTimeout = 60

# The same three matchers lib/patch_config.py writes, named here for the same
# reason: three functions below have to agree with it and with each other, and
# a comment saying "keep these in step" is what failed last time. The port went
# without the notice entry from 2026-09-14 until 2026-09-16, so a Windows user
# editing a .env got no warning at all.
$RedactMatcher  = 'Bash|Read|Grep'
$NoticeMatcher  = 'Edit|Write|mcp__.*'
$FailureMatcher = 'Bash|Read|Grep|Edit|Write|mcp__.*'

$Readers = @('cat','head','tail','less','more','strings','xxd','od','nl','tac','bat','batcat')
$SecretFiles = @('*.env','*.env.*','*/.env','*.pem','*.key','*.p12','*.pfx',
                 '*id_rsa*','*id_ed25519*','*id_ecdsa*','*/.bashrc*','*/.zshrc*',
                 '*/.profile*','*/.bash_profile*','*/.zshenv*','*/.netrc*','*_netrc*',
                 '~/.bashrc*','~/.zshrc*','~/.profile*',
                 '*.git-credentials*','*.npmrc*','*.pypirc*','*.pgpass*','*.my.cnf*',
                 '*.azure/*','*.kube/config*','*.docker/config.json*',
                 '*Microsoft.PowerShell_profile.ps1*',
                 '/proc/*/environ*','*credentials*','*secrets*')

# Ownership is the program a hook entry runs, never a substring of the line.
# A user's own wrapper — `& "C:\me\bin\wrap-secrets-guard" -Audit` — matched
# 'secrets-guard' and was repointed at this installation without a word; an
# audit hook named after the redactor was removed by -Remove. The entries this
# installer writes are of the form `& "<path>"`, so argv[0] is what to read.
function Test-OurCommand ($Command, $Tool) {
    $text = "$Command".Trim()
    if ($text -match '^&\s*"([^"]+)"' -or $text -match "^&\s*'([^']+)'") {
        $program = $Matches[1]
    } else {
        $program = ($text -split '\s+', 2)[0].Trim('"', "'")
    }
    # Split on both separators by hand. [System.IO.Path] uses the separator of
    # the machine it runs on, so on the Linux pwsh the tests use it reads a
    # whole Windows path as one filename and nothing ever matches.
    $leaf = ($program -split '[\\/]')[-1]
    return ($leaf -replace '\.[^.]*$', '') -eq $Tool
}

# `$o.PSObject.Properties.Name` throws under Set-StrictMode when the object has
# no properties at all — member enumeration over an empty collection is an error
# there, not an empty result. A freshly created settings.json holding `{}` is
# exactly that object, so the installer died on the first assistant it touched
# with: "The property 'Name' cannot be found on this object." Found 2026-09-16,
# the first time install.ps1 was run end to end rather than parsed.
function Test-Property ($Object, [string]$Name) {
    foreach ($p in $Object.PSObject.Properties) {
        if ($p.Name -eq $Name) { return $true }
    }
    return $false
}

function Set-Property ($Object, $Name, $Value) {
    if (Test-Property $Object $Name) { $Object.$Name = $Value }
    else { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

function Update-HookConfig ($Name, $Path, $GuardPath) {
    $data = Read-Json $Path
    if (-not (Test-Property $data 'hooks')) {
        Set-Property $data 'hooks' ([pscustomobject]@{})
    }
    if (-not (Test-Property $data.hooks 'PreToolUse')) {
        Set-Property $data.hooks 'PreToolUse' @()
    }

    $matcher = if ($Name -eq 'codex') { '^Bash$' } else { 'Bash' }
    $entries = @($data.hooks.PreToolUse)
    $already = $entries | Where-Object {
        $_.hooks | Where-Object { Test-OurCommand $_.command 'secrets-guard' }
    }
    if ($already) { Say '    = already wired'; return }

    $entry = [pscustomobject]@{
        matcher = $matcher
        hooks   = @([pscustomobject]@{
            type          = 'command'
            shell         = 'powershell'
            command       = "& `"$GuardPath`""
            timeout       = 5
            statusMessage = 'secrets-guard...'
        })
    }
    $data.hooks.PreToolUse = @($entries + $entry)
    Write-Json $Path $data
    Say $(if ($DryRun) { '    would add hook' } else { '    hook added' })
}

# The guard denies a command before it runs; the redactor masks what a command
# already printed. Until 2026-09-14 the Windows installer wired only the first,
# so a Windows install had a gate and no net: every value a program echoed back
# — a password handed to croc, a token inside a URL, an auth error quoting the
# key — reached the model and the transcript untouched.
#
# The two matchers differ on purpose. The guard reads a command line, which has
# no meaning for a tool that runs no shell. The redactor reads a result, and a
# result carrying a credential need not have come from a shell: `Read` on a
# .env or a kubeconfig hands the file over verbatim, and `Grep` returns the
# matching lines.
function Update-RedactConfig ($Name, $Path, $RedactPath) {
    $data = Read-Json $Path
    if (-not (Test-Property $data 'hooks')) {
        Set-Property $data 'hooks' ([pscustomobject]@{})
    }
    if (-not (Test-Property $data.hooks 'PostToolUse')) {
        Set-Property $data.hooks 'PostToolUse' @()
    }

    # Codex cannot replace a tool result — its PostToolUseOutcome carries
    # should_block, additional_contexts and feedback_message and nothing that
    # rewrites output — so there the hook warns instead, which is what turns a
    # silent leak into a rotation.
    $matcher  = if ($Name -eq 'codex') { '^Bash$' } else { $RedactMatcher }
    $argument = if ($Name -eq 'codex') { ' --warn-only' } else { '' }

    # The notice entry below is also a secrets-redact command on PostToolUse and
    # it is not this one: it warns rather than replaces, and carries its own
    # matcher. Telling them apart by the flag keeps each idempotent — on Codex
    # the redactor's own command *is* the warn-only one, so there the flag says
    # nothing and every entry of ours is this one.
    $entries = @($data.hooks.PostToolUse)
    $already = @($entries | Where-Object {
        $e = $_
        $mine = @($e.hooks | Where-Object { Test-OurCommand $_.command 'secrets-redact' })
        if ($mine.Count -eq 0) { return $false }
        if ($Name -ne 'claude') { return $true }
        @($mine | Where-Object { "$($_.command)" -notmatch '--warn-only\s*$' }).Count -gt 0
    })
    if ($already.Count -gt 0) {
        # An install made before the matcher widened is still wired for Bash
        # alone, and re-running the installer is the only thing that will ever
        # look at it again.
        $fixed = 0
        foreach ($e in $already) {
            if ("$($e.matcher)" -ne $matcher) { $e.matcher = $matcher; $fixed++ }
        }
        if ($fixed -eq 0) { Say '    = redactor already wired'; return }
        Write-Json $Path $data
        Say $(if ($DryRun) { "    would set redactor matcher to $matcher" }
              else         { "    redactor matcher set to $matcher" })
        return
    }

    $entry = [pscustomobject]@{
        matcher = $matcher
        hooks   = @([pscustomobject]@{
            type          = 'command'
            shell         = 'powershell'
            command       = "& `"$RedactPath`"$argument"
            timeout       = $RedactTimeout
            statusMessage = 'secrets-redact...'
        })
    }
    $data.hooks.PostToolUse = @($entries + $entry)
    Write-Json $Path $data
    Say $(if ($DryRun) { '    would add redactor hook' } else { '    redactor hook added' })
}

# Claude Code's PostToolUseFailure: the event a non-zero exit fires instead of
# PostToolUse. A failed command never reaches the redactor otherwise, which is
# how a GitLab token reached a transcript in full on 2026-09-14.
#
# Wiring it does not mask that output — the event documents `additionalContext`
# and no field that replaces a result, so the value is in the transcript before
# any hook sees it. What it buys is that the model is told, in the same turn,
# that a credential just landed there and has to be rotated. Hence --warn-only,
# whatever the success path does on this assistant.
function Update-FailureConfig ($Name, $Path, $RedactPath) {
    if ($Name -ne 'claude') { return }        # the event is Claude Code's

    $data = Read-Json $Path
    if (-not (Test-Property $data 'hooks')) {
        Set-Property $data 'hooks' ([pscustomobject]@{})
    }
    if (-not (Test-Property $data.hooks 'PostToolUseFailure')) {
        Set-Property $data.hooks 'PostToolUseFailure' @()
    }

    $entries = @($data.hooks.PostToolUseFailure)
    $already = @($entries | Where-Object {
        $_.hooks | Where-Object { Test-OurCommand $_.command 'secrets-redact' }
    })
    if ($already.Count -gt 0) { Say '    = failure hook already wired'; return }

    $entry = [pscustomobject]@{
        matcher = $FailureMatcher
        hooks   = @([pscustomobject]@{
            type          = 'command'
            shell         = 'powershell'
            command       = "& `"$RedactPath`" --warn-only"
            timeout       = $RedactTimeout
            statusMessage = 'secrets-redact...'
        })
    }
    $data.hooks.PostToolUseFailure = @($entries + $entry)
    Write-Json $Path $data
    Say $(if ($DryRun) { '    would add failure hook' } else { '    failure hook added' })
}

# Tools whose result carries a secret in a shape not worth rewriting.
#
# `Read` and `Grep` hand over one string and the hook replaces it. `Edit` does
# not: its result carries the file in four places — originalFile, oldString,
# newString and every line of structuredPatch[].lines — and `Write` adds
# content beside originalFile. An MCP result is an array of content blocks
# whose schema belongs to the server.
#
# Masking one of those fields and leaving the next would read as coverage while
# the same secret sits one key along, and rebuilding all of them means guessing
# at schemas this hook does not own. A mangled tool result is worse than an
# unmasked one — it is wrong in a way nothing downstream can detect. So this
# entry only warns. Editing a .env is ordinary work, and it is the case this
# covers.
function Update-NoticeConfig ($Name, $Path, $RedactPath) {
    if ($Name -ne 'claude') { return }        # the other assistants warn anyway

    $data = Read-Json $Path
    if (-not (Test-Property $data 'hooks')) {
        Set-Property $data 'hooks' ([pscustomobject]@{})
    }
    if (-not (Test-Property $data.hooks 'PostToolUse')) {
        Set-Property $data.hooks 'PostToolUse' @()
    }

    $wanted  = "& `"$RedactPath`" --warn-only"
    $entries = @($data.hooks.PostToolUse)
    $already = @($entries | Where-Object {
        @($_.hooks | Where-Object {
            (Test-OurCommand $_.command 'secrets-redact') -and
            "$($_.command)" -match '--warn-only\s*$'
        }).Count -gt 0
    })
    if ($already.Count -gt 0) {
        $fixed = 0
        foreach ($e in $already) {
            if ("$($e.matcher)" -ne $NoticeMatcher) { $e.matcher = $NoticeMatcher; $fixed++ }
        }
        if ($fixed -eq 0) { Say '    = notice hook already wired'; return }
        Write-Json $Path $data
        Say $(if ($DryRun) { "    would set notice matcher to $NoticeMatcher" }
              else         { "    notice matcher set to $NoticeMatcher" })
        return
    }

    $entry = [pscustomobject]@{
        matcher = $NoticeMatcher
        hooks   = @([pscustomobject]@{
            type          = 'command'
            shell         = 'powershell'
            command       = $wanted
            timeout       = $RedactTimeout
            statusMessage = 'secrets-redact...'
        })
    }
    $data.hooks.PostToolUse = @($entries + $entry)
    Write-Json $Path $data
    Say $(if ($DryRun) { '    would add notice hook' } else { '    notice hook added' })
}

function Update-OpencodeConfig ($Path, $WithRule) {
    $data = Read-Json $Path
    $changed = 0

    # Opencode reads an instruction file only when it is listed here; dropping
    # it into instructions/ is not enough.
    $ruleEntry = '~/.config/opencode/instructions/secrets-hygiene.md'
    if ($WithRule) {
        if (-not (Test-Property $data 'instructions')) {
            Set-Property $data 'instructions' @()
        }
        if (@($data.instructions) -notcontains $ruleEntry) {
            $data.instructions = @(@($data.instructions) + $ruleEntry)
            $changed++
        }
    }

    if (-not (Test-Property $data 'plugin')) { Set-Property $data 'plugin' @() }
    if (@($data.plugin) -notcontains './plugins/secrets-guard.ts') {
        $data.plugin = @(@($data.plugin) + './plugins/secrets-guard.ts')
        $changed++
    }

    if (-not (Test-Property $data 'permission')) {
        Set-Property $data 'permission' ([pscustomobject]@{})
    }
    if (-not (Test-Property $data.permission 'bash')) {
        Set-Property $data.permission 'bash' ([pscustomobject]@{})
    }
    $bash = $data.permission.bash

    $wanted = [ordered]@{}
    foreach ($k in $DumpRules.Keys) { $wanted[$k] = $DumpRules[$k] }
    foreach ($r in $Readers) { foreach ($f in $SecretFiles) { $wanted["$r $f"] = 'deny' } }

    foreach ($k in $wanted.Keys) {
        $current = if (Test-Property $bash $k) { $bash.$k } else { $null }
        if ($current -ne $wanted[$k]) { Set-Property $bash $k $wanted[$k]; $changed++ }
    }

    if ($changed -eq 0) { Say '    = already current'; return }
    Write-Json $Path $data
    Say $(if ($DryRun) { "    would write $changed entries" } else { "    $changed entries written" })
}

# ── commands ────────────────────────────────────────────────────────────────
Say '-- commands --'
$guard  = "$BinDir\secrets-guard.ps1"
$redact = "$BinDir\secrets-redact.ps1"
Install-File "$Src\bin\secrets-guard.ps1"  $guard
Install-File "$Src\bin\secrets-redact.ps1" $redact
Install-File "$Src\bin\safe-env.ps1"       "$BinDir\safe-env.ps1"

if (($env:PATH -split ';') -notcontains $BinDir) {
    Warn "    $BinDir is not on PATH. Add it for the current user:"
    Say  "        [Environment]::SetEnvironmentVariable('PATH', `"`$env:PATH;$BinDir`", 'User')"
}

# ── assistants ──────────────────────────────────────────────────────────────
$ides = Get-Ides
if ($ides.Count -eq 0) {
    Bad  '  No assistant found.'
    Warn "    Looked for $Home_\.claude, $Home_\.config\opencode, $Home_\.codex"
    Warn '    Pass -Ide <claude|opencode|codex> to install anyway.'
    exit 1
}

foreach ($name in $ides) {
    Say "-- $name --"
    $config = Get-ConfigPath $name
    if (-not (Test-Path $config)) { Warn "    config not found: $config"; continue }

    if ($name -eq 'opencode') {
        Install-File "$Src\plugins\opencode\secrets-guard.ts" `
                     "$Home_\.config\opencode\plugins\secrets-guard.ts"
        Update-OpencodeConfig $config (-not $NoRule)
    } else {
        Update-HookConfig    $name $config $guard
        Update-RedactConfig  $name $config $redact
        Update-FailureConfig $name $config $redact
        Update-NoticeConfig  $name $config $redact
    }

    if (-not $NoRule) {
        Install-File "$Src\rules\secrets-hygiene.md" (Get-RuleTarget $name)
    }
}

# ── verify ──────────────────────────────────────────────────────────────────
Say '-- verify --'
if ($DryRun) { Warn '  dry run — nothing was installed'; exit 0 }

function Test-Guard ($Command) {
    $payload = @{ tool_input = @{ command = $Command } } | ConvertTo-Json -Depth 5 -Compress
    $payload | & powershell -NoProfile -File $guard 2>$null | Out-Null
    return $LASTEXITCODE
}

$blocked = Test-Guard 'env'
$allowed = Test-Guard 'echo hi'

if ($blocked -eq 2 -and $allowed -eq 0) {
    Ok '  ok — the guard blocks a bare env and allows an ordinary command'
    Say ''
    Say '  Restart your assistant: hooks and plugins are read at start-up.'
    Say '  Then, in a shell it runs: safe-env      (values masked)'
    Say '                            $env:NAME     (one variable)'
} else {
    Bad '  Installed, but the guard did not behave as expected.'
    Say "    bare env → exit $blocked (expected 2)"
    Say "    echo hi  → exit $allowed (expected 0)"
    exit 1
}
