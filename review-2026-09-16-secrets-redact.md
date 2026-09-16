# Review — `bin/secrets-redact`

| | |
|---|---|
| Object | `bin/secrets-redact` (391 lines), the masking hook |
| Date | 2026-09-16 (`date -Is` → `2026-09-16T17:00:55+00:00`) |
| Commit | `7a4a94d Read a JSONC config, refuse to rewrite one, and stop swallowing the exit code` |
| Runtime here | bash 5.3.9, GNU Awk 5.3.2, jq 1.8.1, `/usr/bin/awk → gawk` |
| Reviewed by | a session that did not write this file |

Not audited here, and each needs its own pass: `bin/secrets-redact.ps1` (329
lines, the port — a parity check is the cheaper way in), `bin/safe-env` (whose
tier-1 pattern this file duplicates character for character), and
`plugins/opencode/secrets-redact.ts`.

## Baseline, before anything was touched

```
$ bash tests/test_redact.sh          | tail -1     passed 66, failed 0
$ bash tests/test_redact.sh --pwsh   | tail -1     passed 64, failed 0
$ bash tests/test_guard.sh           | tail -1     passed 76, failed 0
$ bash tests/test_install.sh         | tail -1     passed 33, failed 0
$ bash tests/test_safe_env.sh        | tail -1     passed  9, failed 0
$ bash tests/test_scan.sh            | tail -1     passed 16, failed 0
$ shellcheck -S style bin/secrets-redact            info-level only (SC2016)
```

## How to work through this file

1. **A1 first, and on its own.** It is a one-line change with a measured 33×
   effect, it needs no new patterns, and it is what makes every other item
   matter: a hook that is killed masks nothing at all.
2. The rest of **A** is pattern work (A2–A5) and can go in any order, but write
   the failing test first each time — this object's whole risk is that a
   pattern change fixes one shape and breaks two others, and the suite is what
   says otherwise.
3. Reproductions ran in `/tmp/tmp.snGXbDrywJ` (`mktemp -d`, nothing deleted).
   Nothing was run against the real configuration; `--filter` reads stdin and
   writes stdout, so most of them need no sandbox at all.
4. The credential-shaped strings below are invented: `ghp_` + 36 `a`,
   `hunter2…`, a base64 blob that decodes to nothing. No rotation is needed.

## Invariants — what a fix may not break

| # | Invariant | Where the project says it |
|---|---|---|
| I1 | Fails open: no jq, unparsable input, nothing to mask → exit 0, no output | `bin/secrets-redact` lines 26–28 |
| I2 | Tier 1 is character-for-character the RE in `bin/safe-env`; the suite diffs them | lines 44–46 |
| I3 | Tier 2 needs a label, because length alone cannot tell a secret from an md5 or a git SHA | lines 79–80 |
| I4 | A name is not a secret — `usage.outputTokens` and `ANTHROPIC_API_KEY` must survive | lines 85–100 |
| I5 | The label is never masked, only the value after it | lines 125–127 |
| I6 | It redacts, it does not reformat — `--rawfile`, byte-exact | lines 215–219 |

I4 is the one that bites back: every widening below has to be checked against
the `keep` half of the suite, not just the `mask` half.

---

# A. Defects

## A1 — two separators, alternated per line, cost 33× the whole runtime

**✔ Closed 2026-09-16** (`a6f7cb8`). One `scrub_labelled` call, both spellings
in one alternation. `bash tests/test_redact.sh` → `passed 66, failed 0`,
`--pwsh` → `passed 64, failed 0`, and 1.1 MB through `--filter` in **0.36 s**
where it was 10.73 s. The PowerShell port never had the defect: it builds both
regexes once with `[regex]::new` at load time.

**Class: silent wrong result** — through the timeout, which is what actually
reaches the user: a hook killed at its limit replaces nothing, and the result
goes to the model unmasked.

**Where:** the main block, lines 170–175 — `scrub_labelled` called twice with
different `sep` arguments. `rg -n 'scrub_labelled\(' bin/secrets-redact`

**Mechanism.** `pat = LABEL sep VALUE` is a *dynamic* regular expression: gawk
compiles it at the point of use and caches the compiled form. Two different
`sep` values, alternating on every line, miss that cache every time, so the
large LABEL alternation is recompiled twice per line of input.

**Reproduction.** The same program, one pass at a time and then in pairs, over
a 1 179 396-byte payload of this repository's own sources:

```
$ cd /tmp/tmp.snGXbDrywJ && for v in neither tier1-only labelled-eq labelled-sp; do …
  neither        exit=1  0.03s
  tier1-only     exit=0  0.12s
  labelled-eq    exit=0  0.23s
  labelled-sp    exit=0  0.23s
  shipped               10.50s

  t1+eq    0.35s
  eq+sp    10.53s      ← the two separators together
  t1+sp    0.33s
  eq+eq    0.34s       ← the same separator twice: fast
```

`eq+eq` is the control: two calls are not the problem, two *different patterns*
are. mawk does not do this — `mawk -f v-eq+sp.awk` is 0.10 s — but the file
prefers gawk when it is present, and `/usr/bin/awk` is gawk here.

**Fix, measured.** One `scrub_labelled` call whose separator is an alternation:

```awk
  scrub(RE)
  scrub_labelled("([[:space:]]*[=:][[:space:]]*|[[:space:]]+)\"?")
  print
```

```
$ for prog in v-eq+sp.awk v-one-sep.awk; do for bin in gawk mawk; do …
  v-eq+sp.awk    gawk  9.02s
  v-eq+sp.awk    mawk  0.10s
  v-one-sep.awk  gawk  0.27s
  v-one-sep.awk  mawk  0.11s

$ bash tests/test_redact.sh                                           passed 66, failed 0
$ bash tests/test_redact.sh --tool /tmp/…/secrets-redact-onesep       passed 66, failed 0
$ /home/env2hell/bin/secrets-redact --filter < p1m.txt    10.73s
$ ./secrets-redact-onesep            --filter < p1m.txt     0.29s
```

Identical output on every case probed, and the project's own suite passes
unchanged against the patched copy.

**What this closes elsewhere.** `review-2026-09-15-patch_config.md` A1 raised
the hook timeout from 10 s to 60 s as an interim measure and said the repair
belonged here. At 0.29 s/MB the 60 s budget covers roughly 200 MB instead of
5 MB, and the item there can be closed rather than merely mitigated.

**Test.** `tests/test_redact.sh`: a payload of a few MB through `--filter`
under `timeout 10`, asserting a non-empty result. A test that asserts seconds
is flaky on a loaded machine; a test that asserts *finished inside a limit* is
the property that matters.

---

## A2 — a private key block is announced and then handed over

**✔ Closed 2026-09-16** (`d78a6c1`). A block rule: the header sets a flag, the
footer clears it, the body is replaced line for line. Both markers anchored to
a line of their own, so the phrase in prose swallows nothing. Ported the same
day — the port needed a variable-length lookbehind instead, see its review.
Tests: *masks an OpenSSH private key, line for line*, *masks an RSA private
key*, *the phrase in a sentence does not swallow what follows*.

**Class: silent wrong result.** The output *looks* redacted: the first line
comes back as `<REDACTED:25>`, which reads as "handled".

**Where:** tier 1, line 66 — `BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY`
matches the header text and nothing else. awk works a line at a time, and the
key is the lines after it.

**Reproduction**, through the hook path a `Read` of an `id_rsa` takes:

```
$ bash /tmp/tmp.snGXbDrywJ/r1.sh
  -----<REDACTED:25>-----
  b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt
  cnNhAAAAAwEAAQAAAYEAvtbqvKZ9pQ3Xp7nZ0oR2lM4cW8sT1yU6iE5aB3dF7gH9jK2
  -----END OPENSSH PRIVATE KEY-----

$ secrets-redact < key.json    # {"tool_response":{"file":{"content": …}}}
  lines back: 8
  base64 body still there: True
  first line: -----<REDACTED:25>-----
```

**Fix.** A state flag in the awk program: set it on `BEGIN … PRIVATE KEY`,
clear it on `END … PRIVATE KEY`, and while set replace the line with a mask
rather than scrubbing it. Mask the whole block as one — `<REDACTED:key>` — or
line by line; either is honest, and the current output is not.

Note the interaction with I6: the replacement must keep the line count, or a
diff of the result against the file no longer lines up.

**Test.** `tests/test_redact.sh`: an OpenSSH block and an RSA block, asserting
no base64 line survives; plus a `keep` case for the words "BEGIN PRIVATE KEY"
inside ordinary prose, which must not start swallowing the rest of a document.

---

## A3 — `Authorization: Bearer …` is not a label this file knows

**✔ Closed 2026-09-16** (`d78a6c1`). `authorization` joined the label list and
the separator admits an optional scheme word, so `Bearer` stays readable and
the token after it does not. Tests: *an HTTP bearer token*, *the same, lower
case*, *keeps the scheme word readable*, *a header with no value after it*.

**Class: silent wrong result.**

**Where:** `LABEL`, lines 69–78. It has `auth[-_]?token`, and neither
`authorization` nor `bearer`.

**Reproduction:**

```
  THROUGH  Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789
  THROUGH  authorization: bearer abcdefghijklmnopqrstuvwxyz0123456789
```

Both come back byte for byte. `curl -v`, an HTTP client log and half the API
error messages in existence print exactly this line.

**Fix.** Add `authorization` to LABEL, and let the separator swallow the scheme
word: the value to mask is what follows `Bearer`/`Basic`/`Token`, not the
scheme itself — masking the scheme would break I5's spirit, since the model can
no longer see what kind of credential went.

**Test.** `mask` cases for `Authorization: Bearer …` and `authorization: basic
…`; a `keep` case for `Authorization: Bearer` with nothing after it.

---

## A4 — a password with punctuation in it is not masked

**✔ Closed 2026-09-16** (`d78a6c1`). A quoted value is bounded by its quotes,
with a floor of 8 rather than 16 — inside quotes the writer has already said
where the value ends. The quotes stay in the output. Tests: *a quoted password
with punctuation*, *the same in single quotes*, *a quoted name, not a value*,
*a quoted value too short to be a secret*.

**Class: silent wrong result.**

**Where:** `VALUE`, line 81 — `[A-Za-z0-9+/=_.~-]{16,}`. A password is exactly
the kind of string that contains `!`, `#`, `%`, `$`.

**Reproduction:**

```
  THROUGH  password = "S3cr3t!Passw0rd#2026-long-enough"
  THROUGH  PGPASSWORD='S3cr3t!Passw0rd#2026'
```

The label matches, the run of value characters stops at the first `!`, six
characters is under the floor of 16, and the line is left alone.

**Fix.** When the value is quoted, take the quoted string as the value: the
quotes are the boundary the writer already supplied, and inside them
punctuation is ordinary. Unquoted values keep the current charset — widening
that would put every path and URL in range and break I4.

Note `PGPASSWORD='…'`: the separator pattern admits `"` and not `'`.

**Test.** `mask` cases for both quoting styles with punctuation inside; `keep`
cases for a quoted *name* (`password_field = "user_password"`) and for a quoted
short value.

---

## A5 — the JSON spelling of a labelled secret is missed

**✔ Closed 2026-09-16** (`d78a6c1`). An optional closing quote before the
separator, in the same single pattern A1 introduced — not a third call. Tests:
*the JSON spelling of a labelled secret*, *the JSON spelling of a name*.

**Class: silent wrong result.**

**Where:** the separator arguments, lines 172–173. Between the label and the
`:` there is a closing quote, which neither separator admits.

**Reproduction:**

```
  THROUGH  {"password": "hunter2-hunter2-hunter2-hunter2"}
```

A JSON body is what an API error, a config dump and a `kubectl get -o json`
print, and it is the shape most likely to carry a credential verbatim.

**Fix.** Allow an optional closing quote before the separator — `"?[[:space:]]*[=:]`.
It must go into the *same* single pattern A1 introduces, not a third call, or
A1 comes straight back.

**Test.** `mask` case for the JSON form; `keep` case for `{"password_field":
"user_password"}`, which I4 says must survive.

---

## A6 — the warning counts lines, not values

**Closed 2026-09-16** (`8c150ff`). `grep -o '<REDACTED:' | wc -l` counts the
masks themselves. The PowerShell port already did this and was the reference.
Tests: *the warning counts values, not lines (three on one line)* and *the
warning counts values across lines*.

**Class: visible failure** — the number is wrong in the one message a human
acts on, and it is wrong downwards.

**Where:** line 272 — `grep -c '<REDACTED:'`. `grep -c` counts *matching
lines*.

**Reproduction:**

```
values in payload: 4, on 2 lines
  warning says: 2 value(s)
values in payload: 3, on 1 line
  warning says: 1 value(s)
```

**Fix.** `grep -o '<REDACTED:' | wc -l`, or count in awk while masking — `hits`
already exists in the program and is exactly this number; it is thrown away
when the awk exits.

**Test.** `tests/test_redact.sh`: a payload with three values on one line,
asserting the warning says three.

---

## A7 — a killed hook leaves the whole tool result in `/tmp`

**✔ Closed 2026-09-16** (`7fd3692`). Everything goes under
`${TMPDIR:-/tmp}/secrets-redact/run.XXXXXX`; the parent is `chmod 700` whatever
the umask says, and each run sweeps sibling run directories older than an hour
before creating its own. An hour, not "all of them": `lib/patch_config.py` had
the same sweep take a concurrent patcher's live file, and this is the same
shape with that lesson in it. Tests: *the scratch directory is private whatever
the umask says* and *a later run sweeps what a killed one left*, which kills the
hook mid-payload with `TMPDIR` inside the suite's own directory.


**Class: damage.** Not a leak to another user — `mktemp -d` is 0700 — but a
copy of the output, secrets included, that nothing ever removes.

**Where:** lines 220–223 — `trap 'rm -rf "$tmp"' EXIT`, which a SIGKILL does
not run. The hook is killed by the harness exactly when it is slow, which is
A1's case.

**Reproduction** — a 38 MB payload, killed after two seconds:

```
  payload: 38480054 bytes
  /tmp/tmp.* directories before=38 after=39
    74M  /tmp/tmp.zqWlQuqMDA
      in.err
      in.out
      payload
```

74 MB left behind from one killed run: the payload plus the two extracted
streams.

**Fix.** A1 removes most of the exposure by removing the kills. Beyond that:
write under one known directory (`${TMPDIR:-/tmp}/secrets-redact/`) and sweep
entries older than an hour at start-up, the same shape
`lib/patch_config.py:save` now uses for its temp files. A `trap … INT TERM` is
worth adding too, and does nothing for SIGKILL.

**Test.** Kill the hook mid-run, assert a later run leaves no directory older
than the sweep window.

---

## A8 — `--filter` adds a trailing newline the input did not have

**Closed 2026-09-16** (`8c150ff`). `--filter` buffers to a temp directory and
reuses the hook path's `untrail`; with no `mktemp` it falls open to the old
streaming behaviour. Cost of the buffering, measured: 0.39 s to 0.48 s per
megabyte. Tests: *--filter adds no newline the input did not have* and
*--filter keeps the newline the input did have*.

**Class: damage, one byte.** The smallest A item here, and it is an A rather
than a C because I6 is a promise about bytes: this mode redacts, it does not
reformat.

**Where:** `redact ()` at line 179 — awk's `print` terminates every line. The
hook path repairs it with `untrail` (lines 329–334); `--filter` never calls
that, and `--filter` is the mode the Opencode plugin uses.

**Reproduction**, found by putting the same bytes through the PowerShell port
(`review-2026-09-16-secrets-redact-ps1.md`), which gets it right:

```
$ printf 'x --pass 63108c3a9f4b4d2e8c7a1b5e9d0f2a6c' > nl-in
input:  41 bytes, ends with newline: 0
posix:  23 bytes, ends with newline: 1
pwsh:   22 bytes, ends with newline: 0

$ secrets-redact < nl.json        # the hook path, which has untrail
hook stdout ends with newline: False len 22
```

So the same text masked through the hook is 22 bytes and through `--filter` is
23.

**Fix.** Give `--filter` the same treatment the hook path has: remember whether
the input ended in a newline and strip the added one if it did not. The awk
program can do it itself — track the last line and use `printf` for it — which
is cheaper than another pass over the output.

**Test.** `tests/test_redact.sh`: input with no trailing newline through
`--filter`, asserting the output has none either; and the same for input that
does. Run it for both ports — the port already passes.

---

# B. Documentation disagrees with the code

## B1 — the header documents `--filter`'s exit codes, not the hook's

**✔ Closed 2026-09-16** (`f713e03`). Both roles are stated next to each other,
in both ports, and the trap is named: `1` from `--filter` means "nothing was
masked" and reads as failure to `set -e` or a `&&` chain.

**Where:** lines 195–196 say exit 0 means something was masked and 1 means the
text came through unchanged. That is `--filter`. In hook mode every path exits
0, by design (I1), including "nothing matched" and "no jq".

```
  --filter, no match : exit 1
  --filter, a match  : exit 0
  hook, no match     : exit 0
  hook, a match      : exit 0
```

One binary, two roles, and `1` means opposite things in them. A caller with
`set -e` that pipes through `--filter` treats "nothing to mask" as a failure.

**Fix.** State the codes per role, next to each other, the way
`lib/patch_config.py` now does.

## B2 — the module header says "two tiers" and the file has three passes

**✔ Closed 2026-09-16** (`f713e03`). A1 had already collapsed the three passes
to two; what the header now also says is that tier 1 has one member that is a
*block* rather than a match — the private key.

**Where:** lines 14–25 describe tier 1 and tier 2. The program runs `scrub(RE)`
and then `scrub_labelled` twice, and the reason for the second call — one
separator for `=`/`:`, one for whitespace — is documented only at the call
site. A1 collapses them to one call, at which point the header becomes true
again. Worth one line either way.

---

# C. Efficiency

## C1 — tier 1 is one alternation of 17 patterns, run per line

Measured: `tier1-only` is 0.12 s over 25 857 lines, against 0.03 s for
`{ print }`. That is 0.09 s per MB for the whole tier — not a problem, and
recorded here so the next reader does not go looking for one. After A1 the
whole program is 0.29 s/MB, of which tier 1 is roughly a third.

No other measurement in this pass showed a cost worth an item.

---

# D. Judgement on the design

**D1 — answered 2026-09-16: the floor stays at 16 for a bare value, and a
quoted one already goes from 8.** Asked and measured properly, because the
first measurement was not enough to decide on.

A corpus of 126 KB of real output — `ls -la`, sixty lines of `git log`, both
READMEs, this project's own sources, three `--help` texts — masks 11 lines at
a floor of 16, **the same 11** at 12, and 12 at a floor of 8, where the extra
one is prose from the README: `a token <REDACTED:8> in a remote URL`.

That reads like "12 is free", and it is not. The corpus simply had no line of
the shape *label + a word of twelve characters or more*. One exists in ordinary
documentation:

```
  floor 16   the token configuration lives in git      keep
  floor 12   the token configuration lives in git      MASK   <- "configuration"
```

**The mitigation that looked obvious breaks the flagship case.** Adding "a bare
lowercase word is a word, not a secret" (`^[a-z]+$`) to `is_name` keeps
`configuration` — and also keeps `deadbeefdeadbeefdeadbeefdeadbeef`, the
md5-shaped relay password this hook was written for, because `deadbeef` is
letters all the way down. Verified by exit status, not by reading the text:

```
                                       floor 16   floor 12   12 + the word rule
  password=hunter2Trust                 keep       mask       mask
  password=deadbeef… (32 hex)           mask       mask       keep   <- the case
  the token configuration lives …       keep       mask       keep
```

**And the gap is smaller than it looked.** A quoted value already goes from
eight characters, because the quotes are a boundary the writer supplied:

```
  password = "S3cr3t!Pass"     mask      password=hunter2Trust    keep
  PGPASSWORD='Tr0ub4dor'       mask      password=Tr0ub4dor       keep
```

So what 16 actually costs is an *unquoted* short password on a labelled line,
and what lowering it costs is every long word after the word "token" in
documentation. The floor stays. **Read by exit status, always** — the session's
own redactor masks these samples in the terminal, which is how the first reading
of this experiment came out wrong.

**D2 — the `is_name` list.** Unchanged as a judgement: seven shapes, each with a
`keep` case, and the risk is the eighth nobody notices. What today added is the
evidence for how the list fails — see D1: a rule that looks obviously right can
delete the one case the tool exists for, and only an exit-status probe against a
real value says so. Any new shape belongs in `tests/test_redact.sh` in the same
commit, with a `mask` case for a real secret of that shape beside it.

**D3 — answered: the case counts differ by four, and every one is accounted
for.** `tests/test_redact.sh` runs 85 cases and `--pwsh` runs 81. Two are about
jq, which the port does not use (*fails open when jq is unavailable*,
*--filter needs no jq*); two are the scratch-directory group, which the port has
no equivalent of because it writes nothing to disk. `tests/test_parity.sh` is
what covers the rest — same bytes, both ports, diffed.

---

# What is NOT a defect

- **It does not damage ordinary output.** 1 474 lines of real machine output —
  `ls -la` of three directories, 40 lines of `git log --oneline`, three
  `--help` texts, this project's README, and 942 lines of its own Python and
  shell — through `--filter` and diffed against the input: **0 lines changed**
  in every one of them. That is the failure mode that gets a redactor switched
  off, and it is not present.
- **The label is never eaten with the value.** `--pass 63108c…` comes back as
  `--pass <REDACTED:32>`, `HW_SECRET_KEY=…` keeps its name. I5 holds.
- **Names survive.** The `keep` half of the suite covers dotted identifiers,
  SCREAMING_SNAKE metavars, Terraform references and kebab-case names, and it
  passes: `passed 66, failed 0`.
- **The 128 KB argument limit is genuinely gone.** `--rawfile` and files on
  disk throughout; a 38 MB payload is read without complaint (A7's
  reproduction is proof of the reading, if not of the cleanup).
- **Tier 1 still matches `bin/safe-env` character for character** — asserted by
  *tier-1 patterns match safe-env character for character*, which passes.
- **The single-separator fix in A1 does not change behaviour.** Ten probed
  shapes identical, and the project's own suite green against the patched copy.

---

# Fix order, and what stays open while you work

1. ~~**A1**~~ — **done 2026-09-16**, alone and in its own commit, as the order
   asked.
2. ~~**A6**~~ — **done 2026-09-16.**
3. ~~**A2**~~ — **done 2026-09-16.**
4. ~~**A3, A4, A5 together**~~ — **done 2026-09-16**, exactly as the order said:
   thirteen failing cases first, then one change, then the whole suite with the
   `keep` half read line by line. It found nothing broken there, and the
   corpora diff between the two ports stayed at zero.
5. ~~**A7**~~ — **done 2026-09-16.**
6. ~~**A8**~~ — **done 2026-09-16**, from the port's behaviour as the model.

**Exposure, as it stands on 2026-09-16.** All eight closed the same day they
were written up. What is left in this file is B, C and D — text, one
measurement, and three questions.

---

# Done when

```bash
bash tests/test_redact.sh        | tail -1   # passed 85, failed 0 (66 at the
                                             #   baseline, +13 A2–A5, +4 A6/A8,
                                             #   +2 A7)
bash tests/test_parity.sh        | tail -1   # passed 15, failed 0
bash tests/test_redact.sh --pwsh | tail -1   # passed 81, failed 0 (the same
                                             #   minus the two jq cases)
bash tests/test_guard.sh         | tail -1   # passed 76, failed 0
bash tests/test_safe_env.sh      | tail -1   # passed  9, failed 0  (I2)
bash tests/test_install.sh       | tail -1   # passed 33, failed 0
shellcheck -S style bin/secrets-redact       # info-level only, exit 0
```

| Item | The assertion |
|---|---|
| A1 | ✔ **closed 2026-09-16** — 1.1 MB in 0.36 s; the standing assertion is a multi-MB payload through `--filter` under `timeout 10` coming back non-empty |
| A2 | ✔ **closed 2026-09-16** — *masks an OpenSSH private key, line for line*; the phrase in prose swallows nothing after it |
| A3 | ✔ **closed 2026-09-16** — *an HTTP bearer token*, *keeps the scheme word readable* |
| A4 | ✔ **closed 2026-09-16** — *a quoted password with punctuation*, *the same in single quotes* |
| A5 | ✔ **closed 2026-09-16** — *the JSON spelling of a labelled secret*; the name form is kept |
| A6 | ✔ **closed 2026-09-16** — *the warning counts values, not lines*, and across lines |
| A7 | ✔ **closed 2026-09-16** — *a later run sweeps what a killed one left*, and the scratch parent is 700 |
| A8 | ✔ **closed 2026-09-16** — *--filter adds no newline the input did not have*, and keeps the one it did |
| — | the timing pair from A1, recorded in the commit message rather than asserted in a test |

And the one number that says A1 landed:

```bash
time bin/secrets-redact --filter < /tmp/<your-sandbox>/p1m.txt > /dev/null
# ~0.3 s for 1.1 MB; it was ~10.5 s
```

---

**A: 8 — all closed. B: 2 — both closed. C: 1. D: 3 — all three answered.**

File: `/home/env2hell/review-2026-09-16-secrets-redact.md`. Sandbox with every
probe and payload: `/tmp/tmp.snGXbDrywJ` (`r1.sh`, `r2.sh`, the `v-*.awk`
variants, `secrets-redact-onesep`).

The fixes are a separate run against this file. This pass changed nothing.
