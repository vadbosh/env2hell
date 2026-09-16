# Review — `bin/secrets-redact.ps1`

| | |
|---|---|
| Object | `bin/secrets-redact.ps1` (329 lines), the Windows port of the masking hook |
| Date | 2026-09-16 (`date -Is` → `2026-09-16T17:00:55+00:00`) |
| Commit | `e1ff1b3 reviews: A1 closed on both sides` |
| Runtime here | PowerShell on Linux, bash 5.3.9, jq 1.8.1, gawk 5.3.2 |
| Reviewed by | a session that did not write this file |

**This is a parity pass, not a pass from nothing.** The port implements the same
decisions as `bin/secrets-redact`, which was reviewed the same day
(`review-2026-09-16-secrets-redact.md`). The cheap and sharp way in is to put
the same bytes through both and list the differences — which is what every
reproduction below does. Findings that belong to the POSIX side are named as
such and were added to that review rather than restated here.

## Baseline, before anything was touched

```
$ bash tests/test_redact.sh          | tail -1     passed 66, failed 0
$ bash tests/test_redact.sh --pwsh   | tail -1     passed 64, failed 0
```

The two-case difference is explained and deliberate, not a gap — see "What is
NOT a defect".

## How to work through this file

1. There is **one** defect here (A1) and it is the smallest kind: a cost, not a
   miss. Read C1 next; it is the number that decides whether A1 ever matters.
2. Everything else in this file is a statement that the port agrees with the
   POSIX version, each backed by a diff. That is the point of a parity pass:
   the expensive outcome is a port that drifts silently, and the evidence that
   it has not is worth as much as a defect would be.
3. Reproductions: `/tmp/tmp.snGXbDrywJ/ps1.sh` (`mktemp -d`, nothing deleted).
   Both ports read stdin and write stdout, so nothing outside the sandbox is
   touched.
4. The credential-shaped strings are invented — `--pass 63108c…`, `ghp_` + 36
   `a`, a base64 blob that decodes to nothing. No rotation is needed.

## Invariants — what a fix may not break

Same six as the POSIX review, plus the one this object exists to satisfy:

| # | Invariant | Where the project says it |
|---|---|---|
| I7 | The port needs neither Python nor Git Bash nor jq — it parses with `ConvertFrom-Json` and masks with .NET regex | `tests/test_redact.sh` lines 354–355 |

---

# A. Defects

## A1 — the port is 6.8× slower than the POSIX version on the same bytes

**Class: a cost today; a silent wrong result only past ~26 MB.** A hook killed
at its timeout replaces nothing, so slowness turns into an unmasked result at
whatever size crosses the limit — see the POSIX review's A1 for the mechanism.
The number here is far from that limit, which is why this is one item and not
an alarm.

**Where:** `Edit-Line`, lines 116–133 — two `[regex]::Replace` calls per line,
each with a script-block callback, over a string split into lines by
`Edit-Text`. `rg -n 'function Edit-' bin/secrets-redact.ps1`

**Reproduction**, 1 179 396 bytes of this repository's own sources:

```
$ bash /tmp/tmp.snGXbDrywJ/ps1.sh
===== 6 speed on 1 MB =====
  posix  0.34s
  pwsh   2.30s
```

**What the number means.** `lib/patch_config.py` gives the redactor 60 s
(`REDACT_TIMEOUT`). At 2.30 s/MB that covers roughly 26 MB of tool output, and
past that a result reaches the model unmasked. The POSIX side covers ~200 MB
after its own fix. Both are far above the size of an ordinary tool result; a
`Read` of a large log is the case that gets close.

**Fix, if it is judged worth one.** The port does not have the POSIX defect
that A1 there described — it builds both regexes once with `[regex]::new` at
load — so there is no equivalent single change. What is left is ordinary: one
combined pattern instead of two `Replace` passes, and `[regex]::Options` with
`Compiled` where .NET can then cache a compiled automaton. Neither is a
one-liner, and neither is urgent at 26 MB.

**Test.** Only if the fix lands: a multi-MB payload through `--filter` under
`timeout 30`, non-empty. A test asserting seconds is flaky under load.

---

# B. Documentation disagrees with the code

Nothing. The port's header documents what it is, the two-case difference in the
suite is explained where it happens (`tests/test_redact.sh` lines 354–355 and
386–389), and every claim checked below held.

---

# C. Efficiency

## C1 — where the 2.30 s goes, and why it is not A-shaped

The whole cost is per line, in `Edit-Line`: two `.Replace` calls over 25 857
lines, each invoking a PowerShell script block per match. The POSIX version's
equivalent is 0.34 s after its own fix, and was 10.50 s before it — so the port
was the *faster* of the two for as long as that defect stood.

No other measurement in this pass produced a number worth an item. Startup is
the one to watch on Windows rather than here: every reproduction above paid
PowerShell's start-up once per invocation, and the hook pays it per tool call.
**Unverified on Windows** — the command that settles it is
`Measure-Command { pwsh -NoProfile -File bin\secrets-redact.ps1 --filter < small.txt }`
on a real machine, which this pass had no way to run.

---

# D. Judgement on the design

**D1 — two implementations, one behaviour, and only the patterns are diffed.**
The suite asserts that the tier-1 list matches `bin/safe-env.ps1` character for
character. Nothing compares the *port* with the *POSIX version*: the 66-vs-64
case counts come from running the same file twice with a different tool, which
catches a missing behaviour only if somebody wrote a case for it. The parity
table in "What is NOT a defect" below is what a test could assert mechanically
— same input, same output, both ports — and it would have caught the trailing
newline the POSIX side is losing (A8 there).

**D2 — the port counts better than the original.** `--warn-only` reports 4
values where the POSIX version reports 2, because .NET counts matches and
`grep -c` counts lines. When the POSIX A6 is fixed, this file is the reference:
the behaviour to converge on already exists here.

**D3 — `Compiled` regexes are a question, not an answer.** They cost start-up
time and save per-line time, and the hook's shape (one short-lived process per
tool call) is exactly the case where that trade can go the wrong way. Measure on
Windows before changing it.

---

# What is NOT a defect

Every line below is a diff that came back empty. This is the substance of a
parity pass.

- **Masking is identical on real machine output.** 1 132 lines through both
  ports and diffed: `cases` 10, `ls -la` 36, this project's README 333,
  `lib/patch_config.py` 691, two `--help` texts 62 — **0 differing lines** in
  every corpus.
- **The edges agree, byte for byte**: CRLF, a trailing newline, no trailing
  newline*, empty input, a lone newline, text with no match, UTF-8 around a
  secret, two values on one line, and a NUL byte mid-line. (*the one exception
  is the POSIX side's extra byte — A8 there, and the port is the one that is
  right.)
- **All four tool-result shapes come back equivalent.** `streams`, `file`,
  `content` and `string`, compared by key set rather than by text, because the
  two emit their JSON keys in different order and that is not a difference:

  ```
    streams  posix  keys=additionalContext,hookEventName,updatedToolOutput event=PostToolUse masked=true
    streams  pwsh   keys=additionalContext,hookEventName,updatedToolOutput event=PostToolUse masked=true
    file     …      identical
    content  …      identical
    string   …      identical
  ```

  Worth recording because reading the raw output side by side *looks* like three
  of the four differ — key order alone.
- **Exit codes agree in both roles**: `--filter` 1 on no match and 0 on a
  match, hook mode 0 either way.
- **The two missing test cases are deliberate and local.** Both are about jq:
  *fails open when jq is unavailable* and *--filter needs no jq*. The port
  parses with `ConvertFrom-Json` and has no such dependency to lose, so the
  suite skips them for `--pwsh` (`tests/test_redact.sh` lines 356, 390). 66 − 2
  = 64.
- **The port shares the POSIX misses exactly** — `Authorization: Bearer`, the
  JSON `"password"` spelling, a password with punctuation, `PGPASSWORD='…'`,
  and a private key block whose BEGIN line is masked and whose body is not.
  Identical behaviour is the finding here; the defects are A2–A5 in
  `review-2026-09-16-secrets-redact.md` and each fix has to land twice.
- **No temp files at all.** `rg -n 'TempPath|GetTempFileName|New-TemporaryFile'`
  finds nothing: the port keeps the payload in memory, so the POSIX side's A7
  (a killed run leaving 74 MB in `/tmp`) has no equivalent here.

---

# Fix order, and what stays open while you work

One item, no interactions: **A1** can be taken whenever, or declined with a
sentence saying 26 MB is enough. Nothing in this file blocks anything else.

**What is open and is not in this file:** A2–A5 of the POSIX review apply
verbatim to this port, because the patterns are a faithful copy. Every one of
those fixes has to be made twice, and the only thing that will notice a
half-done pair is `tests/test_redact.sh --pwsh`. Write the case for both ports
in the same commit as the fix.

---

# Done when

```bash
bash tests/test_redact.sh --pwsh | tail -1   # passed 64, failed 0
bash tests/test_redact.sh        | tail -1   # passed 66, failed 0
pwsh -NoProfile -Command '$e=$null; [System.Management.Automation.Language.Parser]::ParseFile("bin/secrets-redact.ps1",[ref]$null,[ref]$e); $e.Count'
                                             # 0
```

| Item | The assertion |
|---|---|
| A1 | only if taken: a multi-MB payload through `--filter` under `timeout 30` comes back non-empty |
| D1 | a parity case in the suite: one corpus, both ports, `diff` empty |

---

**A: 1, B: 0, C: 1, D: 3 open questions.**

File: `/home/env2hell/review-2026-09-16-secrets-redact-ps1.md`. Reproductions:
`/tmp/tmp.snGXbDrywJ/ps1.sh`.

The fixes are a separate run against this file. This pass changed nothing.
