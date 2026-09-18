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
| Atlassian API token | `ATATT` + 20 or more |
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
| 40 or more of `A-Za-z0-9_-` | long random strings |
| a 40+ run containing a dot | compound tokens |
| 40 or more of `A-Za-z0-9+/=`, unless the value reads as a path | standard base64 |

The alphabets are spelled out because they are the whole point. The last row
was added on 2026-09-17 for the same reason the `key.signature` row was: a
32-byte secret encoded as standard base64 is 44 characters and, with
probability near one, carries a `+`, a `/` or an `=` — and any one of them
broke every run long enough to trigger the rows above it. `/` is in that
alphabet too, so a value starting with `/`, `~`, `.` or a drive letter is
excluded: a long enough absolute path is letters, digits and slashes and
nothing else.

The third row exists because of a real miss. A token of the form

```
<32 hex characters>.<16 characters>
```

was printed in full by an early version: the dot broke every run long enough to
trigger the other rules, so none of them fired. The `key.signature` row was
added for exactly that shape, and it is why an unfamiliar token format is worth
testing rather than assuming.

## When the name decides, not the shape of the value

The two tiers above look at the value. A third looks at the name: a classic
Atlassian API token is 24 characters of letters and digits — the same shape as a
build id, a short hash or a bucket name. Shape decides nothing there; the name
does.

A value is masked when its variable name contains one of these as a whole
component:

```
PASSWD  PASSWORD  PASSPHRASE  TOKEN  SECRET  API_KEY  APIKEY
AUTH_TOKEN  ACCESS_KEY  SECRET_KEY  CLIENT_SECRET  PRIVATE_KEY  CREDENTIAL
```

A whole component between `_` separators, not a substring: matched as a
substring, `PASS` masked `BYPASS_CACHE` and `PASSENGER_ROOT`. Three exemptions
keep the tier from eating half the environment:

- a value shorter than eight characters — which is what keeps
  `TOKENIZERS_PARALLELISM=false` readable;
- a value that looks like a path (`/x`, `./x`, `~/x`, `C:\x`) — a path is
  configuration, not a secret;
- `true`, `false`, `yes`, `no`, `on`, `off`, or a number;
- a **version-control identifier**: the name carries `COMMIT`, `SHA`,
  `REVISION`, `DIGEST`, `CHECKSUM` or `HASH`, and the value is hex of 7, 8, 40
  or 64 characters, with or without a `sha256:` prefix. A commit SHA is exactly
  the shape the "32 or more hex" rule was written for, and every CI system
  exports one;
- a **network address**: the name ends in `_HOST`, `_HOSTNAME`, `_SERVER`,
  `_ENDPOINT`, `_ADDR`, `_ADDRESS`, `_URI` or `_URL`, and the value is a bare
  hostname or `http(s)://…`. Credentials inside a URL are caught by tier 1
  first, so `DB_URL=postgres://user:password@host` stays masked.

Both exemptions are checked from both sides — the name **and** the shape of the
value. `COMMIT_TOKEN` holding forty non-hex characters is still masked.

Two variables with the **same** value show it:

```
HW_SECRET_KEY=<masked>             BUILD_ID=abc123XYZ456def7
```

The tier lives in `bin/safe-env` (`CRED` and the `named_credential` function)
and in `bin/safe-env.ps1`. For `secrets-redact` the label on the line plays the
part the name plays here — that is the next section.

## The same shapes in command output

`safe-env` reads `NAME=value` pairs, so a shape can be tested against the value
alone. `secrets-redact` reads whatever a command printed, where there is no such
frame — and that changes which rules are safe.

The named formats above carry over unchanged: `ghp_…` is a GitHub token wherever
it appears. The generic fallbacks do not. "32 or more hex characters" is a fine
rule for the right-hand side of `GITHUB_TOKEN=`; applied to free text it matches
every md5sum, every git SHA, every content hash in the session.

So in output the frame is rebuilt from a label on the same line:

| Label | Example |
|---|---|
| `--pass`, `--password`, `--passphrase` | `croc --relay h:9009 --pass <REDACTED:32>` |
| `--token`, `--secret`, `--api-key` | `deploy --token <REDACTED:40>` |
| `password=`, `secret=`, `api_key=` | `DB_URL=…?password=<REDACTED:24>` |
| `TOKEN:`, `Authorization: Bearer` | `Authorization: Bearer <REDACTED:180>` |
| plurals and `-`/`_` spellings | `access_key`, `client-secret`, `credentials` |
| a value glued to its flag, or after a colon | `mysql -p<REDACTED:16>`, `redis-cli -a <REDACTED:16>`, `-U admin%<REDACTED:16>`, `curl -u admin:<REDACTED:16>` |

The last row is four client idioms with no separator at all between the flag and
the value. Each rule fires only next to the command that owns it — `mysql`,
`mariadb`, `mysqldump`, `redis-cli`, `smbclient`, `curl` — because the same flag
letters mean other things elsewhere, and `ls -p`, `grep -a` and `sort -u` stay
untouched. Only the value is replaced: the flag and the user name in `admin:`
stay readable.

The value itself must still look like a secret: 16 or more characters from
`A-Za-z0-9+/=_.~-`. Sixteen, not thirty-two, because the label has already done
most of the work — an md5 is 32 and a git SHA is 40, so length on its own can
never decide this question.

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

Four places, and which one is yours depends on the kind of rule:

- **a provider prefix** (`ghp_`, `glpat-`) — the `RE` string in the `BEGIN`
  block of the awk program in `bin/safe-env`, and the `$patterns` array in
  `bin/safe-env.ps1`;
- **a shape with no prefix** — the `if (val ~ …)` ladder in `bin/safe-env` and
  the `$fallbacks` array in the port;
- **a variable name** — `CRED` in `bin/safe-env` and its counterpart in the port;
- **a rule the redactor must not have** — beside the list rather than inside it,
  which is where `$sqlPassword` sits, because `tests/test_redact.sh` compares the
  two implementations' lists character for character.

Plus a row in the table in `tests/test_parity_safe_env.sh`: that is where a new
rule proves both implementations answer the same.

Add the same expression to both files of your tier, then test with a constructed
sample as above.
A format present in one file and missing from the other is worse than absent
from both: it produces a machine where the behaviour depends on the operating
system, and nobody expects that.

## What the guard blocks, next to what the redactor masks

`safe-env` masks values. `secrets-guard` denies commands — a different list,
and it lives in more than one place because the consumers differ. The two hooks
carry regular expressions; `lib/patch_config.py` and `install.ps1` carry globs,
which is what Opencode's `permission.bash` takes. They cannot be diffed as text,
so `tests/test_policy.sh` asks all four the same question instead: a list of
paths that must be denied and a few that must not.

The files treated as secret stores:

```
.env   *.pem  *.key  *.p12  *.pfx  *id_rsa*  *id_ed25519*  *id_ecdsa*
.aws/credentials  .docker/config.json  .kube/config  .azure/
.git-credentials  .npmrc  .pypirc  .pgpass  .my.cnf
~/.bashrc  ~/.zshrc  ~/.profile  ~/.bash_profile  ~/.zshenv  ~/.netrc
_netrc  Microsoft.PowerShell_profile.ps1          ← the Windows spellings
/proc/*/environ  *credentials*  *secrets*
gh/hosts.yml  .terraformrc  credentials.tfrc.json  .cargo/credentials
.gem/credentials  .m2/settings.xml  .m2/settings-security.xml  rclone.conf
gcloud/credentials.db  gcloud/application_default_credentials.json
.vault-token  .databrickscfg  .snowflake/config  containers/auth.json
helm/registry/config.json
```

Either path separator is accepted, so the Windows form of the same store —
`C:\Users\you\.aws\credentials` — is matched as readily as the Unix one.

**`.env` on the first row is not a glob, unlike every one of its neighbours.**
The hooks need a boundary on its left — a space, a quote, a slash or an `=`. So
`cat .env`, `cat /srv/app/.env`, `cat .env.local` are denied, and since 0.7.0 so
are `cat prod.env` and `head config/production.env`: a filename ending in `.env`
counts as a store when the component before `.env` holds no dot. That condition
is what separates a filename from a config key — in
`jq -r '.permission.bash.env' opencode.json | head` the character before `bash`
is a dot, and the command passes (`docs/design.en.md`).

Before 0.7.0 the implementations disagreed here: Opencode's `SECRET_FILES`
carried a real `*.env` glob while both hooks required the left boundary, so
Opencode denied `cat prod.env` and the hooks allowed it. All four deny it now,
and `tests/test_policy.sh` holds them to it.

Two rows are enforced by Opencode alone. `*credentials*` and `*secrets*` are
broad enough to be useful as a prompt and wrong as a hard deny: in the hooks
they would refuse `cat credentials-design.md` and `cat notes-about-secrets.md`.
Everything else on the list is denied by all four.

Two absences are decisions rather than gaps. `~/.ssh/config` is not on the list:
it holds hostnames and `IdentityFile` paths, not keys, and denying it would cost
ordinary work for nothing. And `.env.example`, `.env.sample`, `.env.template`,
`.env.dist` and `.env.defaults` are exempt from the `.env` rule — they are
committed precisely because they hold no values, and reading one is the first
thing anybody does in an unfamiliar repository. Both are pinned by
`tests/test_policy.sh`, which asks all four implementations the same question,
so neither can be added back by tidiness.

Reading one of these is denied — with a pager that prints the whole file (`cat`,
`bat`, `tac`, `nl`, `head`, `tail`, `less`, `more`, `view`, `od`, `xxd`,
`strings`, `type`, `gc`) and with an extractor that takes a part (`grep`, `rg`,
`sed`, `awk`, `sort`, `uniq`, `cut`, `rev`, `jq`, `yq` and their relatives). An
in-place edit is not a read — for `sed`, `perl` and `awk`, where `-i` really means in-place; for `grep`, `rg` and `sort` it is a different flag, and the first quoted argument of a
grep-like command is the search pattern rather than a path. Listing them, moving them or checking
that they exist is not — the guard is about printing content, not about the
files themselves.

## When a key does leak anyway

Rotate it. Do not reason about who might have seen it: the transcript is on
disk and may already be inside an overnight digest.

Searching your memory stores for the prefix tells you the blast radius, which
is worth knowing. It does not change the decision — rotate regardless of what
the search returns.
