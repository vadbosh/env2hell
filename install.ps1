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
$Readers = @('cat','head','tail','less','more','strings','xxd','od','nl','tac','bat','batcat')
$SecretFiles = @('*.env','*.env.*','*/.env','*.pem','*.key','*.p12','*.pfx',
                 '*id_rsa*','*id_ed25519*','*id_ecdsa*','*/.bashrc*','*/.zshrc*',
                 '*/.profile*','*/.bash_profile*','*/.zshenv*','*/.netrc*','*_netrc*',
                 '~/.bashrc*','~/.zshrc*','~/.profile*',
                 '*.git-credentials*','*.npmrc*','*.pypirc*','*.pgpass*','*.my.cnf*',
                 '*.azure/*','*.kube/config*','*.docker/config.json*',
                 '*Microsoft.PowerShell_profile.ps1*',
                 '/proc/*/environ*','*credentials*','*secrets*')

function Set-Property ($Object, $Name, $Value) {
    if ($Object.PSObject.Properties.Name -contains $Name) { $Object.$Name = $Value }
    else { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

function Update-HookConfig ($Name, $Path, $GuardPath) {
    $data = Read-Json $Path
    if ($data.PSObject.Properties.Name -notcontains 'hooks') {
        Set-Property $data 'hooks' ([pscustomobject]@{})
    }
    if ($data.hooks.PSObject.Properties.Name -notcontains 'PreToolUse') {
        Set-Property $data.hooks 'PreToolUse' @()
    }

    $matcher = if ($Name -eq 'codex') { '^Bash$' } else { 'Bash' }
    $entries = @($data.hooks.PreToolUse)
    $already = $entries | Where-Object {
        $_.hooks | Where-Object { "$($_.command)" -match 'secrets-guard' }
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

function Update-OpencodeConfig ($Path) {
    $data = Read-Json $Path
    $changed = 0

    if ($data.PSObject.Properties.Name -notcontains 'plugin') { Set-Property $data 'plugin' @() }
    if (@($data.plugin) -notcontains './plugins/secrets-guard.ts') {
        $data.plugin = @(@($data.plugin) + './plugins/secrets-guard.ts')
        $changed++
    }

    if ($data.PSObject.Properties.Name -notcontains 'permission') {
        Set-Property $data 'permission' ([pscustomobject]@{})
    }
    if ($data.permission.PSObject.Properties.Name -notcontains 'bash') {
        Set-Property $data.permission 'bash' ([pscustomobject]@{})
    }
    $bash = $data.permission.bash

    $wanted = [ordered]@{}
    foreach ($k in $DumpRules.Keys) { $wanted[$k] = $DumpRules[$k] }
    foreach ($r in $Readers) { foreach ($f in $SecretFiles) { $wanted["$r $f"] = 'deny' } }

    foreach ($k in $wanted.Keys) {
        $current = if ($bash.PSObject.Properties.Name -contains $k) { $bash.$k } else { $null }
        if ($current -ne $wanted[$k]) { Set-Property $bash $k $wanted[$k]; $changed++ }
    }

    if ($changed -eq 0) { Say '    = already current'; return }
    Write-Json $Path $data
    Say $(if ($DryRun) { "    would write $changed entries" } else { "    $changed entries written" })
}

# ── commands ────────────────────────────────────────────────────────────────
Say '-- commands --'
$guard = "$BinDir\secrets-guard.ps1"
Install-File "$Src\bin\secrets-guard.ps1" $guard
Install-File "$Src\bin\safe-env.ps1"      "$BinDir\safe-env.ps1"

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
        Update-OpencodeConfig $config
    } else {
        Update-HookConfig $name $config $guard
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
