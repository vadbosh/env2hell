<#
.SYNOPSIS
    Answer PreToolUse payloads from stdin, one exit code per line, forever.

.DESCRIPTION
    The batch form (tests/pwsh_batch.ps1) needs the whole corpus up front. A
    case-by-case suite does not have that: it prints each result as it goes,
    with its group heading around it. This is the same trick kept open as a
    co-process — read one payload per line from the real stdin, run the hook
    against it in-process, write back one exit code.

    The hook reads [Console]::In.ReadToEnd(), so Console.In is swapped for a
    StringReader per request and the request stream is the ORIGINAL stdin,
    captured before the first swap. The hook denies by writing to
    [Console]::Error directly, which `*> $null` does not touch, so that handle
    is redirected too — otherwise a denial message lands in the middle of the
    exit codes and the caller reads it as one.

    Output is flushed per line, or the caller blocks forever waiting for an
    answer that is sitting in a buffer.

    Usage:  coproc PW { pwsh -NoProfile -File tests/pwsh_serve.ps1 <hook.ps1>; }
            printf '%s\n' "$payload" >&"${PW[1]}"
            read -r rc <&"${PW[0]}"

    98 = the hook threw. 99 = it returned without setting an exit code.
#>
param([Parameter(Mandatory = $true)][string]$Hook)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requests = [Console]::In
$out      = [Console]::Out
$savedErr = [Console]::Error
[Console]::SetError([System.IO.TextWriter]::Null)

while ($null -ne ($line = $requests.ReadLine())) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    [Console]::SetIn([System.IO.StringReader]::new($line))
    $global:LASTEXITCODE = 99
    try {
        & $Hook *> $null
        $rc = $LASTEXITCODE
    } catch {
        $rc = 98
    }
    $out.WriteLine($rc)
    $out.Flush()
}

[Console]::SetError($savedErr)
