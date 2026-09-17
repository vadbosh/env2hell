<#
.SYNOPSIS
    Run a PowerShell hook against many payloads in ONE process.

.DESCRIPTION
    pwsh -File costs about a second of startup, so a harness that spawns it per
    case pays six minutes for four hundred cases. This runs the hook in-process
    instead: [Console]::SetIn is redirected to each payload in turn and the
    script is invoked with `&`, so its `exit N` ends the script rather than the
    host and lands in $LASTEXITCODE.

    Verified on this machine before the harnesses were changed to use it: five
    known cases through both routes gave identical exit codes and the host
    survived all five. Do not take that on trust after a PowerShell upgrade —
    a harness that lies about verdicts is the exact failure class these tests
    exist to catch. tests/test_parity_guard.sh re-checks it on every run.

    Usage:  pwsh -NoProfile -File tests/pwsh_batch.ps1 <hook.ps1> <payloads.txt>

    <payloads.txt> holds one single-line JSON payload per line; json.dumps
    escapes newlines, so a multi-line command is still one line here. One exit
    code is printed per payload, in order.

    98 = the hook threw. 99 = it returned without setting an exit code. Neither
    can be confused with 0 or 2, which is the point.
#>
param(
    [Parameter(Mandatory = $true)][string]$Hook,
    [Parameter(Mandatory = $true)][string]$Payloads
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The hook denies by writing to [Console]::Error directly, which is the console
# handle and not PowerShell's error stream — `*> $null` does not touch it, and
# the message lands in the middle of the exit codes. The handle has to be
# redirected too, and put back afterwards.
$savedIn  = [Console]::In
$savedErr = [Console]::Error
try {
    [Console]::SetError([System.IO.TextWriter]::Null)
    foreach ($line in [System.IO.File]::ReadLines($Payloads)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        [Console]::SetIn([System.IO.StringReader]::new($line))
        $global:LASTEXITCODE = 99
        try {
            & $Hook *> $null
            $rc = $LASTEXITCODE
        } catch {
            $rc = 98
        }
        $rc
    }
} finally {
    [Console]::SetIn($savedIn)
    [Console]::SetError($savedErr)
}
