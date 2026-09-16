# tests/test_ownership.ps1 — whose hook entry is it?
#
#   pwsh -NoProfile -File tests/test_ownership.ps1
#   (tests/test_install.sh runs this too, when pwsh is present)
#
# install.ps1 used to decide ownership with -match 'secrets-guard', so a user's
# own wrapper was repointed at this installation and their audit hook was
# deleted by -Remove. The function is lifted out of install.ps1 by name rather
# than copied here: a copy would drift, and the point is to test what ships.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installer = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1'
$src = Get-Content -Raw $installer
if ($src -notmatch '(?s)(function Test-OurCommand \(\$Command, \$Tool\) \{.*?\n\})') {
    Write-Host "Test-OurCommand not found in $installer"; exit 2
}
Invoke-Expression $Matches[1]

$cases = @(
    @{ cmd = '& "C:\Programs\env2hell\secrets-guard.ps1"';             tool = 'secrets-guard';  want = $true  },
    @{ cmd = '& "C:\Programs\env2hell\secrets-redact.ps1" --warn-only'; tool = 'secrets-redact'; want = $true  },
    @{ cmd = '& "C:\Program Files\env2hell\secrets-guard.ps1"';        tool = 'secrets-guard';  want = $true  },
    @{ cmd = 'C:\Programs\env2hell\secrets-guard.ps1';                 tool = 'secrets-guard';  want = $true  },
    @{ cmd = '& "C:\me\bin\wrap-secrets-guard.ps1" -Audit';            tool = 'secrets-guard';  want = $false },
    @{ cmd = '& "C:\me\bin\secrets-redact-audit.ps1"';                 tool = 'secrets-redact'; want = $false },
    @{ cmd = '& "C:\me\bin\my-logger.ps1"';                            tool = 'secrets-redact'; want = $false },
    @{ cmd = '';                                                       tool = 'secrets-guard';  want = $false }
)

$pass = 0; $fail = 0
foreach ($c in $cases) {
    $got = Test-OurCommand $c.cmd $c.tool
    if ($got -eq $c.want) {
        $pass++
        Write-Host ('  ok    {0}' -f $c.cmd)
    } else {
        $fail++
        Write-Host ('  FAIL  {0} — wanted {1}, got {2}' -f $c.cmd, $c.want, $got)
    }
}
Write-Host ''
Write-Host "passed $pass, failed $fail"
if ($fail -gt 0) { exit 1 }
