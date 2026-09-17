# Review of bin/secrets-guard.ps1 — a parity pass

<!-- filename: review-2026-09-17-secrets-guard-ps1.md — one review per object -->

Date: 2026-09-17. Object: `bin/secrets-guard.ps1`, 213 lines, PowerShell 7.
Line numbers are as of commit `4d42200`. Anchor by name:
`rg -n 'pass A|rawSubs|credVar|envTemplates' bin/secrets-guard.ps1`.

**This is a parity pass, not a cold audit.** The question asked was not "is this
file correct" but "do the same bytes get the same verdict from both
implementations". That is cheaper and sharper: it needs no model of what the
policy should be, only the other implementation, and every finding comes with
its own counter-example already attached. `bin/secrets-guard` was audited
separately today — `review-2026-09-17-secrets-guard.md` — and items open there
are open here too unless this file says otherwise.

Baseline, run before anything was touched:

    bash tests/test_guard.sh            # passed 95, failed 0
    bash tests/test_guard.sh --pwsh     # passed 95, failed 0
    pwsh --version                      # PowerShell 7.x on this machine

Method: every command string fed to both implementations as the same JSON
payload, verdict taken from the **exit status** (`2` denies, `0` allows), never
from the text — this session's own redactor rewrites terminal output, and it
masked parts of the probe output during this pass.

    corpus of single-line commands:  357 cases, 0 divergences
    multi-line shapes:                10 cases, 3 divergences
    locality across a newline:         5 cases, 4 divergences

The corpus was every probe case written during today's audit, plus every
command line in the code blocks of `README.md` and `docs/*.md`, plus the
non-comment lines of `install.sh`, `uninstall.sh`, `release.sh` and
`bin/safe-env`. It found nothing — which is the useful half of the result, and
it is why the divergences below are all one root cause.

## How to work through this file

1. There is one defect. It has two consequences that fail in opposite
   directions, and both need a test.
2. Reproduce first, then write the case in `tests/test_guard.sh` — it runs both
   implementations from the same case list, so one case covers both.
3. After the fix: `bash tests/test_guard.sh` **and** `--pwsh`, then re-run the
   parity scripts named at the end.

**Invariants** — from `docs/design.en.md` and the file's own header:

- **"Policy is kept identical to the POSIX version on purpose: one behaviour to
  learn, one set of documentation, whichever machine you are on"** —
  `bin/secrets-guard.ps1:22-23`. That sentence is what makes every divergence
  below a defect rather than a difference.
- **Locality**: reader and path must be in the same sub-command. The
  `rsync -e "ssh -i …pem" … | head` incident bought this, and
  `tests/test_guard.sh` pins it.
- **Fail open** on an unexpected payload.

---

## A. Defects (each reproduced)

### A1. A newline is not a sub-command boundary, so a two-line command is judged as one

**Class:** both at once, which is why it ranks first —
**silent wrong result** in pass A (a dump on the second line is not seen) and
**damage** in pass B (an ordinary two-line command is denied for something on
the other line).

**Where:** `bin/secrets-guard.ps1:59` —

    foreach ($part in ($scan -split '\|\||&&|;|&|\|')) {

— and the character loop that builds `$rawSubs`, which treats `"`/`'`/`;`/`&`/`|`
as special and a newline as ordinary text.

The POSIX guard has no such line: its awk program reads **records**, and a
record is a line, so a newline has always been a boundary there. The port was
written from the separator list and the record-based part of the design was
invisible in it.

**Reproduction, direction one — a dump goes through** (verdict from exit
status):

    printf 'ls -la\nenv'            → posix DENY   pwsh pass
    printf 'cd /tmp\nsudo env'      → posix DENY   pwsh pass
    printf 'echo hi && \\\nenv'     → posix DENY   pwsh pass

A command whose second line is `env` prints the whole environment on Windows and
is denied everywhere else. Multi-line Bash calls are ordinary — a `&&` chain
broken over lines, a `\`-continued command, anything pasted.

**Reproduction, direction two — ordinary work is denied.** These are the cases
the project already pins as must-pass, moved onto two lines:

    printf 'ssh -i ~/.ssh/id.pem host uptime\nhead -5 report.txt'
                                                → posix pass   pwsh DENY
    printf 'rsync -e "ssh -i ~/.ssh/id.pem" a b\ncat report.txt'
                                                → posix pass   pwsh DENY
    printf 'git commit -m "docs: cat .env ends the same way"\nhead -5 CHANGELOG.md'
                                                → posix pass   pwsh DENY

The same three on one line with `;` between them: `posix pass  pwsh pass`. The
newline is the whole difference. The third is the commit-message case
`docs/design.en.md:108-117` describes as the reason pass B strips quotes at all
— the port undoes it as soon as the command has two lines.

**Fix:** one change in two places.

- pass A: add the newline to the split — `'\|\||&&|;|&|\||\r?\n'`. `\r?\n`
  rather than `\n`, because this is the implementation that runs where line
  endings are CRLF.
- the `$rawSubs` character loop: treat `` `n `` (and `` `r ``) as a separator
  when `$quote` is empty, exactly as `;` is treated now.

Keep the quote handling as it is in pass A. Note the one semantic difference
that stays: the POSIX awk restarts its quote state on every record, so a `"`
opened on line one does not continue to line two, while the port's loop carries
it. Both denied the probe for that shape, so it is not a divergence today —
say so in a comment rather than changing it, because making the port match
would mean pretending a quoted multi-line string is two commands.

**Touches:** `bin/secrets-guard.ps1` only. `bin/secrets-guard` is already right.
Nothing enforces the agreement — `tests/test_guard.sh` runs both from one case
list, but its cases were all single-line until this pass, which is exactly how
this survived.

**Test:** a new group `multi-line commands` in `tests/test_guard.sh`, with the
six commands above. The harness already runs every case through both
implementations, so the group closes the gap in both directions at once. Note
that `check` takes its command as a single argument — these need a real newline
in the string, not a literal `\n`.

---

## B. Documentation disagrees with the code

Nothing. The port's own header claims policy identical to the POSIX version,
which is the claim A1 breaks — but that is a defect in the code, not in the
sentence, and it is filed as A1. `docs/design.en.md` describes the split in
terms of sub-commands without saying what separates them, which is accurate for
both files.

---

## C. Efficiency

The port is single-process by construction — `-match` and `-replace` on strings,
no forks — so the rewrite that item A1 of the POSIX review needed does not apply
here. Measured on the same input that defined that item, 2000 sub-commands
ending in a denied read:

    bin/secrets-guard                      DENY   0.320 s
    pwsh -File bin/secrets-guard.ps1       DENY   2.324 s

Most of the 2.3 s is PowerShell startup: an ordinary one-line command costs
about the same. Against `GUARD_TIMEOUT = 30` there is no exposure here, and no
item.

---

## D. Judgement on the design

What is right and must stay:

- **The command-substitution unwrap.** It was missing once and the port denied
  `printf "%s" "$(curl -u "$E:$JIRA_API_TOKEN" …)"`; the comment at
  `bin/secrets-guard.ps1:195-198` records it. Both implementations now agree on
  all of today's substitution cases.
- **`Set-StrictMode -Version Latest`.** It is what turned an empty-object
  settings file into a loud failure in `install.ps1` rather than a silent one.

What is arguable:

- **Two implementations of one policy with one shared case list.** The list is
  the only thing holding them together, and it held for 357 single-line cases
  and failed for every multi-line one, because nobody had written a multi-line
  case. A parity script that generates its corpus rather than curating it —
  today's ran against the project's own documentation and scripts — costs
  minutes and asks a different question. Recommendation: keep the two scripts
  in `tests/` rather than in `/tmp`, and run them the way
  `tests/test_parity.sh` is run for the redactor.

---

## What is NOT a defect (checked, so nobody spends the time again)

- **357 single-line commands, zero divergences.** Provider-prefixed values,
  every dump form, every reader-and-path shape, the credential-name cases, the
  command-substitution cases, and the real command lines out of the project's
  own documentation and scripts.
- **Both fixes made to the POSIX guard today are present and agree**: the
  `.env` template exemption and the whole-component credential name. Checked by
  the shared case list, 95 of 95 on both sides.
- **The size behaviour is fine** — see C.
- **A quoted string opened on one line and closed on the next** gives the same
  verdict from both, despite the implementations reaching it differently.
- **`$wrappers` contains `'&'`**, which looks like a stray. It is harmless: the
  split has already removed every `&`, so the entry can never match a token.
  Worth deleting for clarity, not worth a finding.

## Done when

    bash tests/test_guard.sh             # passed ≥ 101, failed 0; exit 0
    bash tests/test_guard.sh --pwsh      # same count; exit 0

and the parity scripts report zero:

    bash <the multi-line parity script>   # 0 divergences
    bash <the locality parity script>     # 0 divergences

- the six commands in A1 are cases in `tests/test_guard.sh`, failing on
  `--pwsh` before the fix and passing after
- the parity scripts live in `tests/` rather than in a temporary directory
