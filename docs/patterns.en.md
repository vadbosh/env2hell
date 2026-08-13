# What counts as a secret

`safe-env` decides, per variable, whether the value looks like a credential. A
match is replaced by `<REDACTED:length>`; everything else prints normally, so
the output stays useful:

```
ANTHROPIC_MODEL=glm-5.2
PATH=/usr/local/bin:/usr/bin:/bin
TAVILY_API_KEY=<REDACTED:57>
```

The length is kept deliberately. It distinguishes two different keys in the
same output and reveals nothing that helps an attacker.

## Recognised formats

| Provider | Pattern |
|---|---|
| AWS access key | `AKIA` + 16 upper-case alphanumerics |
| GitHub, classic | `ghp_` / `gho_` / `ghs_` / `ghu_` / `ghr_` + 36 or more |
| GitHub, fine-grained | `github_pat_` + 22 or more |
| GitLab | `glpat-` + 20 or more |
| Slack | `xox` + `b`/`a`/`p`/`r`/`s` + `-` + 10 or more |
| Tavily | `tvly-` + 10 or more |
| Google | `AIza` + 35 |
| Stripe, live | `sk_live_` / `rk_live_` + 20 or more |
| OpenAI family | `sk-`, optionally `sk-or-v1-`, `sk-proj-`, `sk-ant-` + 20 or more |
| Atlassian | `at-` + 30 or more |
| JWT | `eyJ…` `.` `eyJ…` `.` |
| Private key | a `BEGIN … PRIVATE KEY` line |
| Password in a URL | `://user:password@` |
| SQL password | `IDENTIFIED BY '…'` |

## The generic fallbacks

Named formats cover the providers you have heard of. The ones you have not are
caught by shape:

| Shape | Catches |
|---|---|
| 32 or more hex characters | hash-like keys with no prefix |
| 20+ alphanumerics, a dot, 8+ more | `key.signature` tokens |
| 40 or more opaque characters | long random strings |
| a 40+ run containing a dot | compound tokens |

The third row exists because of a real miss. A token of the form

```
<32 hex characters>.<16 characters>
```

was printed in full by an early version: the dot broke every run long enough to
trigger the other rules, so none of them fired. The `key.signature` row was
added for exactly that shape, and it is why an unfamiliar token format is worth
testing rather than assuming.

## Testing a format

Never paste a live key to check. Construct one of the same shape:

```bash
env -i PATH="$PATH" \
    SAMPLE='glpat-EXAMPLEEXAMPLEEXAMPLE1234' \
    safe-env | grep SAMPLE
```

Masked output means the pattern holds:

```
SAMPLE=<REDACTED:31>
```

The same check in PowerShell:

```powershell
$env:SAMPLE = 'glpat-EXAMPLEEXAMPLEEXAMPLE1234'
.\bin\safe-env.ps1 | Select-String SAMPLE
```

## Adding a format

Two files, and they must stay in step:

- `bin/safe-env` — the `RE` string in the `BEGIN` block of the awk program
- `bin/safe-env.ps1` — the `$patterns` array

Add the same expression to both, then test with a constructed sample as above.
A format present in one file and missing from the other is worse than absent
from both: it produces a machine where the behaviour depends on the operating
system, and nobody expects that.

## What the guard blocks, by contrast

`safe-env` masks values. `secrets-guard` denies commands — a different list,
kept in `lib/patch_config.py` (`DUMP_RULES`, `READERS`, `SECRET_FILES`) so that
the installer and the documentation cannot disagree.

The files treated as secret stores:

```
*.env  *.pem  *.key  *.p12  *.pfx  *id_rsa*  *id_ed25519*
~/.bashrc  ~/.zshrc  ~/.profile  ~/.bash_profile  ~/.zshenv  ~/.netrc
/proc/*/environ  *credentials*  *secrets*
.aws/credentials  .docker/config.json  .kube/config
```

Reading one of these with `cat`, `head`, `tail`, `less`, `strings` and the like
is denied. Listing them, moving them or checking that they exist is not — the
guard is about printing content, not about the files themselves.

## When a key does leak anyway

Rotate it. Do not reason about who might have seen it: the transcript is on
disk and may already be inside an overnight digest.

Searching your memory stores for the prefix tells you the blast radius, which
is worth knowing. It does not change the decision — rotate regardless of what
the search returns.
