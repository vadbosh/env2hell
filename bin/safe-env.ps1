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
    'ATATT[A-Za-z0-9_=.-]{20,}'                         # Atlassian API token
    'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.'    # JWT
    '://[^/:@\s]+:[^/:@\s]{3,}@'                        # password inside a URL
    'BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY'        # private key block
)

# Kept out of $patterns on purpose, and the POSIX pair does the same: this list
# is compared character for character against bin/secrets-redact.ps1 by
# tests/test_redact.sh, and the redactor has no SQL rule. A pattern that lives
# in one file and not the other belongs beside the list, not inside it.
$sqlPassword = '(?i)IDENTIFIED\s+BY\s+[''"][^''"]{6,}'

$fallbacks = @(
    '^[A-Fa-f0-9]{32,}$'                                # long hex
    '^[A-Za-z0-9]{20,}\.[A-Za-z0-9_-]{8,}$'             # key.signature (z.ai shape)
    '^[A-Za-z0-9_-]{40,}$'                              # long opaque run
)

# Standard base64 — the commonest encoding for a random secret, and the one
# shape the list above could not take: `+`, `/` and `=` are outside
# [A-Za-z0-9_-], so any one of them broke every run long enough to match.
# A path is the false positive to avoid, because `/` is in the alphabet, so a
# value starting with `/`, `~`, `.` or a drive letter is excluded.
$base64  = '^[A-Za-z0-9+/=]{40,}$'
$notPath = '^([\\/~.]|[A-Za-z]:[\\/])'

function Test-Secret([string]$Value) {
    foreach ($p in $patterns)  { if ($Value -match $p) { return $true } }
    if ($Value -match $sqlPassword) { return $true }
    foreach ($p in $fallbacks) { if ($Value -match $p) { return $true } }
    # A dotted token whose halves are both long: caught by neither list above.
    if ($Value -match '[A-Za-z0-9_-]{40,}' -and $Value -match '[A-Za-z0-9_-]\.[A-Za-z0-9_-]') {
        return $true
    }
    if ($Value -match $base64 -and $Value -notmatch $notPath) { return $true }
    return $false
}

# What the NAME says, for the values whose shape says nothing. A classic
# Atlassian API token is 24 characters of letters and digits — the shape of a
# build id or a short hash — so no pattern can take it without masking half an
# ordinary environment. A path stays visible because it is configuration, so
# does a flag, and nothing under eight characters is worth hiding.
$credName = '(PASSWD|PASSWORD|PASSPHRASE|TOKEN|SECRET|API_?KEY|APIKEY' +
            '|AUTH_?TOKEN|ACCESS_?KEY|SECRET_?KEY|CLIENT_?SECRET' +
            '|PRIVATE_?KEY|CREDENTIAL)'

# The name has to be a WHOLE underscore-separated component, not a substring of
# one. Matched as a substring, PASS masked BYPASS_CACHE and PASSENGER_ROOT —
# configuration silently deleted from the output. PASS needs a neighbour:
# DB_PASS is a password, a lone PASS is as likely to be a counter. PASSWORD,
# PASSWD and PASSPHRASE say it on their own. bin/secrets-guard.ps1 carries the
# same list; tests/test_policy.sh asks both the same names.
$credVar = '^([A-Za-z0-9]+_)*' + $credName + '(_[A-Za-z0-9]+)*$' +
           '|^(([A-Za-z0-9]+_)+PASS(_[A-Za-z0-9]+)*' +
           '|PASS(_[A-Za-z0-9]+)+)$'

function Test-NamedCredential([string]$Name, [string]$Value) {
    if ($Name.ToUpper() -notmatch $credVar)           { return $false }
    if ($Value.Length -lt 8)                          { return $false }
    if ($Value -match '^[~.]?[\\/]')                  { return $false }
    if ($Value -match '^[A-Za-z]:[\\/]')              { return $false }
    if ($Value -match '^(?i)(true|false|yes|no|on|off|\d+)$') { return $false }
    return $true
}

Get-ChildItem Env: | Sort-Object Name | ForEach-Object {
    $value = [string]$_.Value
    if ([string]::IsNullOrEmpty($value)) {
        "$($_.Name)="
    } elseif ((Test-Secret $value) -or (Test-NamedCredential $_.Name $value)) {
        "$($_.Name)=<REDACTED:$($value.Length)>"
    } else {
        "$($_.Name)=$value"
    }
}
