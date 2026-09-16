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

# B. Documentation disagrees with the code

## B1 — the header documents `--filter`'s exit codes, not the hook's

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

**D1 — the floor of 16 characters is doing a lot of work.** I3 explains why it
cannot be lowered: an md5 is 32 and a git SHA is 40, so length cannot decide.
But it also means a 12-character password with a label in front of it goes
through, and short passwords are common. Worth deciding deliberately rather
than by inheritance: with a label present, is 8 enough?

**D2 — `is_name` is a list of shapes, and lists go stale.** Seven rules today,
each with a `keep` case. The risk is not that a rule is wrong; it is that the
next widening of VALUE or LABEL makes an eighth shape necessary and nobody
notices until a name is masked in someone's session. The suite's `keep` half is
the guard — it deserves to grow with every A2–A5 fix here.

**D3 — the port is a second implementation of every decision above.**
`bin/secrets-redact.ps1` is 329 lines and carries its own copy of the patterns.
`tests/test_redact.sh --pwsh` runs 64 cases against it, two fewer than the
POSIX side runs: the difference is worth a line somewhere, because "the same
cases against both" is what the file claims.

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

1. **A1** — alone, first, and commit it alone. It is one line, it is measured,
   and every later item is worth more once the hook finishes. Re-run
   `tests/test_redact.sh` and `--pwsh`.
2. **A6** — one line, independent of the pattern work.
3. **A2** — the private key block. Independent of A3–A5: it is a state flag,
   not a pattern change.
4. **A3, A4, A5 together** — all three touch LABEL/VALUE/sep, and each changes
   what the next one's reproduction runs through. Write the three failing tests
   first, then make them pass as one change, then re-run the whole suite and
   read the `keep` half specifically.
5. **A7** — after A1, because A1 removes most of the kills that cause it.

**Exposure while you work.** A2 through A5 are all "a credential in this shape
reaches the model" and all stay open until step 3 and step 4 land. There is no
interim measure for them — a wider pattern is exactly the change that needs the
tests. What can be said plainly: until then, a private key read through `Read`,
a Bearer token, a punctuated password and a JSON `"password"` field are not
masked, and the transcript is where they end up.

---

# Done when

```bash
bash tests/test_redact.sh        | tail -1   # passed >= 74, failed 0
                                             #   (66 today, +8 from A2–A6)
bash tests/test_redact.sh --pwsh | tail -1   # passed >= 72, failed 0
bash tests/test_guard.sh         | tail -1   # passed 76, failed 0
bash tests/test_safe_env.sh      | tail -1   # passed  9, failed 0  (I2)
bash tests/test_install.sh       | tail -1   # passed 33, failed 0
shellcheck -S style bin/secrets-redact       # info-level only, exit 0
```

| Item | The assertion |
|---|---|
| A1 | a multi-MB payload through `--filter` under `timeout 10` comes back non-empty |
| A2 | no base64 line of an OpenSSH or RSA block survives; prose saying "BEGIN PRIVATE KEY" does |
| A3 | `Authorization: Bearer …` is masked, the scheme word is not |
| A4 | a quoted password containing `!` and `#` is masked, in both quoting styles |
| A5 | `{"password": "…"}` is masked; `{"password_field": "user_password"}` is not |
| A6 | three values on one line produce a warning that says three |
| A7 | a killed run leaves nothing a later run does not sweep |
| — | the timing pair from A1, recorded in the commit message rather than asserted in a test |

And the one number that says A1 landed:

```bash
time bin/secrets-redact --filter < /tmp/<your-sandbox>/p1m.txt > /dev/null
# ~0.3 s for 1.1 MB; it was ~10.5 s
```

---

**A: 7, B: 2, C: 1, D: 3 open questions.**

File: `/home/env2hell/review-2026-09-16-secrets-redact.md`. Sandbox with every
probe and payload: `/tmp/tmp.snGXbDrywJ` (`r1.sh`, `r2.sh`, the `v-*.awk`
variants, `secrets-redact-onesep`).

The fixes are a separate run against this file. This pass changed nothing.
