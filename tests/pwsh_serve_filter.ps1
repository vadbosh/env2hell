<#
.SYNOPSIS
    Answer secrets-redact requests from stdin, one JSON line each, forever.

.DESCRIPTION
    The same in-process trick as tests/pwsh_serve.ps1, for a tool that takes
    flags and produces text rather than one exit code. `pwsh -File` costs about
    a second of startup and tests/test_redact.sh calls the tool two dozen times,
    so the port's run was 72 seconds of starting PowerShell.

    Request:  {"args":["--filter"],"stdin":"text\n"}
    Response: {"rc":0,"out":"masked text\n"}

    Console.In and Console.Out are both swapped per request, because the tool
    reads with [Console]::In.ReadToEnd() and writes with [Console]::Out.Write.
    The request stream is the ORIGINAL stdin, captured before the first swap,
    and the response goes to the ORIGINAL stdout — otherwise the answer lands in
    the buffer meant for the tool.

    -Depth 100 on ConvertTo-Json: the default of 2 silently truncates, and a
    truncated response is a test that lies rather than fails.

    98 = the tool threw. 99 = it returned without setting an exit code.

    Usage:  coproc RT { pwsh -NoProfile -File tests/pwsh_serve_filter.ps1 <tool>; }
#>
param([Parameter(Mandatory = $true)][string]$Tool)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requests = [Console]::In
$replies  = [Console]::Out
$savedErr = [Console]::Error
[Console]::SetError([System.IO.TextWriter]::Null)

while ($null -ne ($line = $requests.ReadLine())) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $req = $line | ConvertFrom-Json

    $out = New-Object System.IO.StringWriter
    [Console]::SetIn([System.IO.StringReader]::new([string]$req.stdin))
    [Console]::SetOut($out)
    $global:LASTEXITCODE = 99
    try {
        # The tool writes in two ways and both have to be caught. `--filter`
        # goes to [Console]::Out, which the StringWriter above takes; the hook
        # mode emits its JSON down the PowerShell pipeline, which an `| Out-Null`
        # discarded — every hook-mode case then read as "the hook issued no
        # replacement at all", in two seconds, with nothing having run.
        $piped = if ($req.args.Count -gt 0) { & $Tool @($req.args) } else { & $Tool }
        $rc = $LASTEXITCODE
    } catch {
        $piped = @()
        $rc = 98
    }
    [Console]::SetOut($replies)

    $text = $out.ToString()
    if ($null -ne $piped) {
        $text += (@($piped) | ForEach-Object { [string]$_ }) -join "`n"
    }

    $replies.WriteLine((@{ rc = $rc; out = $text } | ConvertTo-Json -Compress -Depth 100))
    $replies.Flush()
}

[Console]::SetError($savedErr)
