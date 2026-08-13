<#
.SYNOPSIS
    safe-env — print the environment with secret-looking values masked.

.DESCRIPTION
    The sanctioned replacement for `Get-ChildItem Env:` under secrets-guard.
    Variable names and harmless values stay readable; anything shaped like a
    credential is replaced by <REDACTED:length>.

    The length is kept because it is useful (it tells two different keys apart)
    and harmless (it reveals nothing usable).

.EXAMPLE
    safe-env
    safe-env | Select-String MODEL
#>

Set-StrictMode -Version Latest

# Explicit provider formats first, then generic high-entropy fallbacks for the
# tokens that carry no recognisable prefix.
$patterns = @(
    'AKIA[0-9A-Z]{16}'                                  # AWS access key
    '(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,}'            # GitHub token
    'github_pat_[A-Za-z0-9_]{22,}'                      # GitHub fine-grained
    'glpat-[A-Za-z0-9_-]{20,}'                          # GitLab
    'xox[baprs]-[A-Za-z0-9-]{10,}'                      # Slack
    'tvly-[A-Za-z0-9-]{10,}'                            # Tavily
    'AIza[A-Za-z0-9_-]{35}'                             # Google
    '(sk|rk)_live_[A-Za-z0-9]{20,}'                     # Stripe
    'sk-(or-v1-|proj-|ant-)?[A-Za-z0-9-]{20,}'          # OpenAI family
    'at-[A-Za-z0-9]{30,}'                               # Atlassian
    'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.'    # JWT
    '://[^/:@\s]+:[^/:@\s]{3,}@'                        # password inside a URL
    'BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY'        # private key block
    '(?i)IDENTIFIED\s+BY\s+[''"][^''"]{6,}'             # SQL password
)

$fallbacks = @(
    '^[A-Fa-f0-9]{32,}$'                                # long hex
    '^[A-Za-z0-9]{20,}\.[A-Za-z0-9_-]{8,}$'             # key.signature (z.ai shape)
    '^[A-Za-z0-9_-]{40,}$'                              # long opaque run
)

function Test-Secret([string]$Value) {
    foreach ($p in $patterns)  { if ($Value -match $p) { return $true } }
    foreach ($p in $fallbacks) { if ($Value -match $p) { return $true } }
    # A dotted token whose halves are both long: caught by neither list above.
    if ($Value -match '[A-Za-z0-9_-]{40,}' -and $Value -match '[A-Za-z0-9_-]\.[A-Za-z0-9_-]') {
        return $true
    }
    return $false
}

Get-ChildItem Env: | Sort-Object Name | ForEach-Object {
    $value = [string]$_.Value
    if ([string]::IsNullOrEmpty($value)) {
        "$($_.Name)="
    } elseif (Test-Secret $value) {
        "$($_.Name)=<REDACTED:$($value.Length)>"
    } else {
        "$($_.Name)=$value"
    }
}
