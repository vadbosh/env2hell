# Review of bin/safe-env — a task for whoever fixes it

<!-- filename: review-2026-09-17-safe-env.md — one review per object -->

Date: 2026-09-17. Object: `bin/safe-env`, 77 lines, bash driving one awk
program. Its PowerShell port `bin/safe-env.ps1` (89 lines) is not the object,
but it is read here in one place, because it answers a question the POSIX
version gets wrong — see A1.

Line numbers are as of commit `50d769d`. They will rot; anchor by name:
`rg -n 'BEGIN|function |^  RE = |^  CRED = ' bin/safe-env`.

Baseline, run before anything was touched:

    bash tests/test_safe_env.sh           # passed 9, failed 0
    bash tests/test_safe_env.sh --pwsh    # passed 9, failed 0
    bash tests/test_redact.sh             # passed 89, failed 0  (includes the
                                          #   tier-1 diff against safe-env)

## How to work through this file

1. Read `docs/patterns.en.md` first — it is the specification for this file, and
   several things that look like defects are its stated decisions.
2. Every item below has a reproduction. Reproduce first, then write the case in
   `tests/test_safe_env.sh`, then fix.
3. Order: the fix order below, then B, then D. There is no C: 500 variables go
   through in 0.020 s, and nothing here is worth a measurement.
4. After each item: `bash tests/test_safe_env.sh` **and** `--pwsh`, then
   `bash tests/test_redact.sh`.
5. **Read every verdict from a `grep -Fq` exit status on the original value, not
   from the screen.** This session's own redactor rewrites terminal output, and
   it masked parts of the probe output during this pass. The probe used here
   asks one question — "does the planted value survive into stdout" — and
   answers it with an exit code.
6. **Never plant a real value.** Every value quoted below is invented and has
   the shape of a credential without being one.

**Invariants — a fix may not break these**, taken from what the project says
about itself:

- **The output stays useful.** `docs/patterns.en.md:3-14`: everything that is
  not a credential prints normally. A fix that masks more by masking
  indiscriminately fails this; `TOKENIZERS_PARALLELISM=false` is the named case
  and `tests/test_safe_env.sh:119` pins it.
- **The length is kept on purpose** — `<REDACTED:length>` distinguishes two keys
  in one output (`docs/patterns.en.md:13`). A1 breaks this invariant today.
- **Tier 1 is character-for-character the list in `bin/secrets-redact`** —
  `docs/design.en.md:191`, enforced by `tests/test_redact.sh:688-706`. Any
  change to the `RE =` lines must land in **both** files in the same commit or
  that test fails.
- **`env` by absolute path, never through `PATH`** — `bin/safe-env:12-20`. The
  uv installer's own `env` file in `~/.local/bin` once made this tool print an
  empty environment and exit 0. Do not "simplify" this back.
- **The name decides only what the shape cannot** — `bin/safe-env:43-49`,
  `bin/safe-env:74`. Shape rules run first; the name rule takes the leftovers.

**Fix order.**

1. **A3, A4** — one boundary each in a pattern, independent of each other and of
   everything else. A4 touches `bin/secrets-redact` too (invariant above).
2. **A1** — changes how records are read, so it moves the ground under every
   other reproduction here. After it, re-run A2's, A3's and A4's.
3. **A2** — widen the fallback character class, written against the record shape
   A1 leaves behind.

**Exposure schedule.** A1 is the worst item and goes second, because A3 and A4
are minutes and A1 is a change of mechanism. Until A1 lands, any multi-line
value in the environment has everything after its first line printed in full —
`safe-env` is the command the guard offers as the safe one, so this is a leak
through the sanctioned path. There is no cheap interim measure: `safe-env |
grep NAME` shows the first line only and looks clean. Until the fix, a
multi-line secret in the environment should be read with `printenv NAME | head
-1`, or not read at all.

Reproductions were run from a throwaway directory made with `mktemp -d`
(`/tmp/tmp.WsTCrVE7rM`), with `env -i` so each probe saw only the one planted
variable and nothing real was ever in scope.

---

## A. Defects (each reproduced)

### A1. A multi-line value has everything after its first line printed in full, and the reported length is wrong

**Class:** silent wrong result — the output looks masked, the mask carries a
plausible number, and the secret is on the next line.

**Where:** the awk program reads `env`'s output **line by line** (`bin/safe-env`,
the main rule block, `key = $1; val = substr($0, length(key) + 2)`). A value
containing a newline arrives as several records. The first carries `NAME=` and
is judged; the rest have no `=`, so `val` is empty and line 65 takes the
`{ print key; next }` branch, which prints that line verbatim with no test of
any kind.

**Reproduction** — an invented key block, planted with `env -i`, verdict from
`grep -Fq` on the body:

    body='MIIEpAIBAAKCAQEAxGZlbGxvd3NoaXBvZnRoZXJpbmdvbmVyaW5ndG9ydWxldGhlbQ'
    pk="-----BEGIN RSA PRIVATE KEY-----
    $body
    -----END RSA PRIVATE KEY-----"
    env -i "PK=$pk" bin/safe-env
    # PK=<REDACTED:31>
    # MIIEpAIBAAKCAQEAxGZlbGxvd3NoaXBvZnRoZXJpbmdvbmVyaW5ndG9ydWxldGhlbQ
    # -----END RSA PRIVATE KEY-----
    # → LEAK: private key body printed in full

Two separate wrongs in three lines. The body is printed. And `31` is the length
of the header line, not of the value, which is 98 — so the number the project
keeps deliberately, to tell two keys apart, describes something else entirely.

**The PowerShell port gets this right**, which is where the fix comes from. It
iterates variables rather than lines (`bin/safe-env.ps1`, `Get-ChildItem Env: |
Sort-Object Name | ForEach-Object`), so the whole value is one string:

    $env:MYPK = "-----BEGIN RSA PRIVATE KEY-----`nMIIEp…`n-----END RSA PRIVATE KEY-----"
    & bin/safe-env.ps1 | Select-String '^MYPK=' -CaseSensitive
    # MYPK=<REDACTED:96>
    # masked: body absent

**Fix:** read NUL-separated pairs instead of lines — `"$ENV_BIN" -0` with
`RS="\0"` in the awk program. Verified to produce one record per variable here:

    env -i "PK=<the three-line block>" /usr/bin/env -0 \
      | gawk 'BEGIN{RS="\0"} {n=index($0,"="); print substr($0,1,n-1) "=[" length(substr($0,n+1)) " chars]"}'
    # PK=[81 chars]

Two things the fix has to handle. `$1` stops being usable once `RS` changes, so
the split has to be `index($0, "=")`, as above. And `mawk` does not take a NUL
record separator — the script falls back to `awk` when `gawk` is absent
(`bin/safe-env:10`), so either require `gawk` for the NUL path and keep the
line-based path as the fallback, or join continuation lines in the shell before
awk sees them. Say which in a comment; a silent fallback to the broken path is
the same defect with a longer fuse.

**Touches:** `bin/safe-env` only — the port is already correct. Add the case to
`tests/test_safe_env.sh` so the port is pinned against regressing into the same
shape.

**Test:** new group `multi-line values`: plant a three-line block, assert the
body does not appear in the output, and assert the reported length equals the
full value's length, not the first line's.

### A2. A base64 value is not masked: the fallbacks exclude `+`, `/` and `=`

**CLOSED 2026-09-17.** `bash tests/test_safe_env.sh` and `--pwsh`, both
`passed 18, failed 0`. A fifth fallback, `^[A-Za-z0-9+/=]{40,}$`, with values
starting `/`, `~`, `.` or a drive letter excluded — `/` is in that alphabet, so
a long absolute path is letters, digits and slashes and nothing else. The
residue is a relative path over forty characters with no leading dot, which is
rarer than the secret this catches; it is named in the comment rather than
left to be rediscovered. Closes B1 with it: the table in
`docs/patterns.en.md` / `docs/patterns.ru.md` now spells out every alphabet and
carries the base64 row.

**Class:** silent wrong result.

**Where:** all four generic fallbacks use `[A-Za-z0-9_-]` or `[A-Fa-f0-9]`.
Standard base64 alphabet adds `+`, `/` and the `=` padding, and any of the three
breaks every run long enough to trigger a rule — the same mechanism as the
`key.signature` miss `docs/patterns.en.md:47-56` already records.

**Reproduction:**

    env -i 'B64VAR=QWxhZGRpbjpvcGVuIHNlc2FtZQ+abcdefghij/klmnopqrst=' bin/safe-env
    # B64VAR=QWxhZGRpbjpvcGVuIHNlc2FtZQ+abcdefghij/klmnopqrst=      → LEAK

    env -i 'B64EQ=QWxhZGRpbjpvcGVuc2VzYW1lMTIzNDU2Nzg5MGFiY2RlZg==' bin/safe-env
    # → LEAK

    env -i 'OPAQUE=QWERTYuiop1234567890QWERTYuiop1234567890' bin/safe-env
    # OPAQUE=<REDACTED:40>                                          → masked

The third line is the same length and the same entropy; only the alphabet
differs. A 32-byte random secret encoded as base64 is 44 characters and, with
probability near one, contains at least one of `+`, `/`, `=`.

**Fix:** add a fallback for the base64 alphabet — 40 or more of
`[A-Za-z0-9+/=]`, anchored, which does not overlap what is already matched.
Watch the false positives this class brings: a long `LS_COLORS`, a flag string
and a PATH all stay safe because they contain `:`, `;`, `,` or a space, and the
rule must stay anchored so they keep breaking the run. The base64 rule must not
be widened into "any 40 characters".

**Touches:** `bin/safe-env`, `bin/safe-env.ps1` (`$fallbacks`). Not
`bin/secrets-redact`: the generic fallbacks are deliberately **not** carried
into free text (`docs/patterns.en.md:58-67`), and that decision stands.

**Test:** in the generic-fallback group, one case per alphabet — base64 with
`+`, base64 with `/`, base64 with `==` padding — plus a `kept` case for a long
PATH so the new rule is shown not to eat it.

### A3. Any variable whose name merely contains `pass` is masked

**CLOSED 2026-09-17.** Same commands, plus `bash tests/test_policy.sh` →
`passed 178, failed 0`. The name is matched as a whole underscore-separated
component now, and `PASS` needs a neighbour — identical to the fix in
`bin/secrets-guard`, because it was the same list with the same defect.

The list lived in four files and nothing compared them, which is what D asked
for: `tests/test_policy.sh` gained a second section that asks all four the same
names — the two guards by whether `echo "$NAME"` is denied, the two maskers by
whether the value comes back `<REDACTED:…>`.

**Class:** damage — the tool's whole purpose is that the non-secret part of the
output stays readable, and this silently deletes ordinary configuration.

**Where:** `CRED`, first alternative `PASS`, used as
`toupper(key) !~ CRED` — an unanchored substring test.

**Reproduction:**

    env -i 'BYPASS_CACHE=never-on-tuesdays'      bin/safe-env  # → MASKED
    env -i 'PASSENGER_ROOT=opt-passenger-6-0-17' bin/safe-env  # → MASKED
    env -i 'MYTEST_PLAIN=hello-world'            bin/safe-env  # → kept

**Fix:** require a boundary on the left — `(^|_)PASS` — which is how
`PASSWORD`, `DB_PASSWORD` and `db_password` are spelled and how `bypass`,
`compass` and `passenger` are not. Keep the case-insensitive comparison:
`toupper(key)` already normalises it, and `tests/test_safe_env.sh` pins the
lowercase spelling.

**Touches:** `bin/safe-env`, `bin/safe-env.ps1`, and note that
`bin/secrets-guard` carries the same list under the name `CRED_NAME` with the
same defect (item A6 of `review-2026-09-17-secrets-guard.md`). Nothing compares
the three copies — see D.

**Test:** in the name-decides group, `kept` for `BYPASS_CACHE` and
`PASSENGER_ROOT`, beside the existing masked `MYTEST_JIRA_API_TOKEN`.

### A4. `sk-` matches inside an ordinary value, so a model name is masked

**OPEN.** Untouched: the `RE` lines are diffed character for character against
`bin/secrets-redact` by `tests/test_redact.sh`, so anchoring the OpenAI
alternative has to land in four files at once and the redactor has no `NAME=`
frame to anchor against. It needs its own decision, not a quick edit.

**Class:** damage.

**Where:** `RE`'s `sk-(or-v1-|proj-|ant-)?[A-Za-z0-9-]{20,}` alternative, and
`val ~ RE` is unanchored, so the prefix may sit anywhere in the value.

**Reproduction:**

    env -i 'ANTHROPIC_MODEL=zai-sk-glm-4-6-turbo-preview' bin/safe-env
    # ANTHROPIC_MODEL=<REDACTED:28>                                → MASKED

`ANTHROPIC_MODEL` is the variable `docs/patterns.en.md:8` uses as its example of
a value that prints normally. It is also the one a model reads most often to
learn what it is running as.

**Fix:** anchor the OpenAI-family alternative to the start of the value, or to a
non-`[A-Za-z0-9]` boundary on its left. Real keys of that family begin the
value; a `sk-` in the middle of a hyphenated name does not.

**Touches:** `bin/safe-env` **and** `bin/secrets-redact` in the same commit —
the `RE =` lines are diffed character for character by
`tests/test_redact.sh:688-706` — plus `bin/safe-env.ps1` and
`bin/secrets-redact.ps1`, whose `$patterns` arrays carry the same list. Check the
consequence for the redactor before committing: there the value has no `NAME=`
frame, so an anchor to "start of value" has to become a word boundary.

**Test:** in the provider group, `kept` for `zai-sk-glm-4-6-turbo-preview`,
masked for a value that starts with `sk-` and for one that starts with
`sk-ant-`. Add the mirror cases to `tests/test_redact.sh`, since the pattern is
shared.

---

## B. Documentation disagrees with the code

### B1. `docs/patterns.en.md:40-46` calls the fallbacks "opaque characters"

The table row reads

> | 40 or more opaque characters | long random strings |

and the program means 40 or more of `[A-Za-z0-9_-]`. Base64 — the single
commonest encoding for a random secret — is not covered (A2). A reader checking
whether their token shape is handled reads that row and stops.

**Fix:** name the alphabet in the row, and after A2 lands add the base64 row
beside it. Both language versions: `docs/patterns.en.md`, `docs/patterns.ru.md`.

### B2. The "Private key" row is true of the pattern and false of the result

`docs/patterns.en.md:31` says the recognised format is "a `BEGIN … PRIVATE KEY`
line", which is exactly what the pattern matches — and exactly why A1 is
invisible from the documentation. The reader's question is whether a private key
in a variable is safe to have in the environment, and today the answer is no.

**Fix:** after A1 lands the row becomes true of the value and needs no change.
Until then, one sentence under the table saying that a multi-line value is
handled line by line. If A1 is fixed in the same pass, skip this item and say so
in the commit. Both language versions.

---

## C. Efficiency

Nothing to report, and the measurement is here so nobody repeats it: an
environment of 500 variables goes through in **0.020 s**, producing 504 lines,
exit 0. The tool runs once when a human or a model asks for it, never in a loop.

---

## D. Judgement on the design (change only after the person agrees)

What is right and must stay:

- **Shape first, name last** (`bin/safe-env:74`). The name rule only sees what
  no shape rule claimed, so a match keeps the precise reason. Reproduced: an
  invented 24-character Atlassian-shaped token in `ATLASSIAN_API_TOKEN` is
  masked by the name; the same value in `BUILD_ID` is not, which is the intended
  asymmetry and the argument `docs/patterns.en.md` makes for having a name tier
  at all.
- **The three exclusions in `named_credential`** — path, boolean-or-number,
  shorter than eight. Reproduced: `API_KEY_FILE=/run/secrets/api_key` and
  `TOKENIZERS_PARALLELISM=false` both print. Without these the name tier would
  mask most of a CI environment.
- **`/usr/bin/env` by absolute path.** The incident is in the file's own comment
  and in `tests/test_safe_env.sh:15-20`, and the failure mode it prevents — an
  empty environment that reads as "nothing is set" — is the worst shape this
  tool can fail in.

What is arguable:

- **`^[A-Fa-f0-9]{32,}$` masks every hash-valued variable.** Reproduced:
  `GIT_COMMIT=5100e79…abcd` comes out as `<REDACTED:41>`, while
  `IMAGE=sha256:e3b0…b855` prints, because the `sha256:` prefix breaks the
  anchor. In CI that is a handful of variables the reader wanted to see.
  `docs/patterns.en.md:64-67` argues the trade explicitly and accepts it for
  `NAME=value` input. Recommendation: **not now**. The alternative — exempt
  names like `*_COMMIT`, `*_SHA`, `*_REVISION` — trades a readability annoyance
  for a name-shaped hole, and the project has already chosen which way it errs.
- **Three copies of the credential-name list**, in `bin/safe-env` (`CRED`),
  `bin/secrets-guard` (`CRED_NAME`) and their two ports, with nothing comparing
  them. Tier 1 has a drift test and this does not, which is why A3 is a defect
  in two programs at once. Recommendation: one diff test, the shape that already
  works at `tests/test_redact.sh:688-706`. It is cheap and it is the reason A3
  was found in `bin/secrets-guard` first and here second rather than in both at
  once.

---

## What is NOT a defect (checked, so nobody spends the time again)

- **Tier 1 does not drift from the redactor.** `tests/test_redact.sh:688-706`
  diffs the `RE =` lines of `bin/safe-env` against `bin/secrets-redact`, and the
  `--pwsh` run does the same for the two ports. It passes today.
- **A UUID, a `sha256:` digest, a PATH, a flag string, `JAVA_TOOL_OPTIONS` and
  `LANG` all print unchanged.** Each was planted and checked; none is a
  credential and none is masked.
- **A URL without a password prints; a URL with one is masked.**
  `postgres://user@db.example:5432/app` survives,
  `postgres://user:…@db.example:5432/app` comes out `<REDACTED:46>`.
- **Invalid UTF-8 in a value does not break the program.** A value containing
  `\xff\xfe` produced exit 0 and an empty stderr; gawk did not choke.
- **A value shorter than eight characters under a credential name is printed on
  purpose**, and so are paths and booleans — `bin/safe-env:51-61`, pinned by
  `tests/test_safe_env.sh`.
- **The port passes its own suite** (`--pwsh`, 9 of 9) and is *ahead* of the
  POSIX version on A1. This review does not cover the rest of it; the parity
  pass is separate.
- **Speed is not an issue** — see C.

## Done when

Commands to paste, each with the status it should exit with:

    bash tests/test_safe_env.sh            # passed ≥ 16, failed 0; exit 0
    bash tests/test_safe_env.sh --pwsh     # same count; exit 0
    bash tests/test_redact.sh              # passed 89, failed 0; exit 0
                                           #   (the tier-1 diff; A4 moves it)
    bash tests/test_redact.sh --pwsh       # passed 85, failed 0; exit 0

Per item — each plants one invented value with `env -i` and asks whether it
survived, so the answer is an exit status and not a glance:

    s () { env -i "$1" bin/safe-env; }

    A1  s "PK=$(printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----')"
        # one line, PK=<REDACTED:60>; no MIIEpAIB anywhere in the output
    A2  s 'B64=QWxhZGRpbjpvcGVuIHNlc2FtZQ+abcdefghij/klmnopqrst='   # <REDACTED:
        s 'MYPATH=/usr/local/bin:/usr/bin:/bin'                     # unchanged
    A3  s 'BYPASS_CACHE=never-on-tuesdays'                          # unchanged
        s 'DB_PASSWORD=correct-horse-battery'                       # <REDACTED:
    A4  s 'ANTHROPIC_MODEL=zai-sk-glm-4-6-turbo-preview'            # unchanged
        s 'OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx'              # <REDACTED:

- every A item has a case in `tests/test_safe_env.sh` that failed before the fix
  and passes after, in both the POSIX and `--pwsh` runs
- B1 and B2 are corrected in both language versions, or B2 is closed by A1 and
  the commit says so
- if D's diff test is accepted, `CRED` in `bin/safe-env` and `CRED_NAME` in
  `bin/secrets-guard` are compared by it, and A3 is fixed in both
