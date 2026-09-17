# Review of bin/safe-env.ps1 — a parity pass

<!-- filename: review-2026-09-17-safe-env-ps1.md — one review per object -->

Date: 2026-09-17. Object: `bin/safe-env.ps1`, 89 lines, PowerShell 7.
Line numbers are as of commit `4d42200`. Anchor by name:
`rg -n '\$patterns|\$fallbacks|function Test-|Get-ChildItem' bin/safe-env.ps1`.

**This is a parity pass, not a cold audit.** The question is whether the same
values get the same treatment from both implementations. `bin/safe-env` was
audited separately today — `review-2026-09-17-safe-env.md` — and its open items
are open here unless this file says otherwise.

Baseline, run before anything was touched:

    bash tests/test_safe_env.sh          # passed 9, failed 0
    bash tests/test_safe_env.sh --pwsh   # passed 9, failed 0
    bash tests/test_redact.sh            # passed 89, failed 0
                                         #   (diffs tier 1 against the redactor)

Method: 44 invented `NAME=value` pairs planted in one process on each side —
`env -i` for POSIX, `$env:` assignments for PowerShell — output filtered to the
planted prefix, sorted, diffed. One process per implementation, so the whole
table is one comparison rather than 44.

    44 values, 2 divergences.

Every value is invented and has the shape of a credential without being one.
The pairs cover every provider row of `docs/patterns.en.md`, all four generic
fallbacks, the base64 alphabets, the name tier and each of its exclusions, and
the ordinary values that must survive — a UUID, a digest, a PATH, a flag
string, a locale, a sentence, a value containing `=`, an empty value and a
non-ASCII one.

**One harness bug is recorded here because it cost a false finding.** The first
run reported a third divergence on a base64 value; it was
`IFS='=' read -r name value` in the generator, which discards a trailing
delimiter and ate the `==` padding before PowerShell ever saw it. A parity
harness that mangles one side produces exactly the shape of finding this pass
exists to produce, so check the generated input before believing a difference.

## How to work through this file

1. Two items, independent of each other.
2. Reproduce first, then add the value to `tests/test_safe_env.sh`, which runs
   both implementations from one case list.
3. After each: `bash tests/test_safe_env.sh` and `--pwsh`.

**Invariants:**

- **Tier 1 is character-for-character the list in `bin/secrets-redact.ps1`**,
  enforced by `tests/test_redact.sh --pwsh`. Any change to `$patterns` lands in
  both files or that test fails.
- **The output stays useful** — a non-credential prints normally.
- **One behaviour whichever machine you are on** — the reason the two items
  below are items.

---

## A. Defects (each reproduced)

### A1. A Windows drive path is exempt from the name tier in the port and masked by the POSIX version

**CLOSED 2026-09-17.** `bash tests/test_safe_env.sh` and `--pwsh`, both
`passed 15, failed 0`; `bash tests/test_parity_safe_env.sh` → `passed 4,
failed 0`. Resolved the port's way, as proposed: the POSIX `named_credential`
gained `^[A-Za-z]:[\/\\]`, and the existing exclusion was widened from
`^[~.]?\/` to `^[~.]?[\/\\]` so the backslash spellings of `/path`, `./path`
and `~/path` are covered too.

**Class:** divergence with a security direction — the port shows a value the
POSIX version hides. Whether that is the wrong direction depends on the value,
which is the problem: the two files disagree about a rule that is written down
in neither.

**Where:** `bin/safe-env.ps1`, `Test-NamedCredential`:

    if ($Value -match '^[~.]?[\\/]')                  { return $false }
    if ($Value -match '^[A-Za-z]:[\\/]')              { return $false }   # ← only here

`bin/safe-env`'s `named_credential` has the first line and not the second:

    if (val ~ /^[~.]?\//)                         return 0

**Reproduction:**

    PARITY_TOKEN_WIN=C:/Users/me/token
    posix:  PARITY_TOKEN_WIN=<REDACTED:17>
    pwsh:   PARITY_TOKEN_WIN=C:/Users/me/token

This is not hypothetical on a machine with Git Bash or WSL, where a Windows
path is routinely handed to a POSIX tool.

**Fix:** decide which way, then make both match. The port's reading is the
consistent one — the exclusion exists because *a path is configuration, not a
secret*, and `C:/Users/me/token` is as much a path as `/run/secrets/token`. So:
add `^[A-Za-z]:[\\/]` to the POSIX `named_credential`, and say in the comment
that the Windows spelling is covered for the same reason as the POSIX one.

Note the POSIX pattern also misses the backslash spelling, `~\` and `.\` — the
port's `[\\/]` takes both separators and `^[~.]?\/` takes only one. Fix that in
the same line.

**Touches:** `bin/safe-env`; `docs/patterns.*.md` if the exclusions are
described there.

**Test:** `PARITY_TOKEN_WIN`-style values in `tests/test_safe_env.sh` — the
drive-letter form, the backslash form, and `.\` — each expected to print.

### A2. An empty value prints as `NAME` in one implementation and `NAME=` in the other

**CLOSED 2026-09-17.** Same commands as A1. Resolved as proposed — `NAME=` on
both sides, the POSIX one changing.

**Class:** divergence only — no security consequence. It is listed because the
risk is that someone later "fixes" one to match the other by guesswork, and the
two spellings break different consumers.

**Where:** `bin/safe-env`, the main rule: `if (val == "") { print key; next }`.
`bin/safe-env.ps1:82-83`: `if ([string]::IsNullOrEmpty($value)) { "$($_.Name)=" }`.

**Reproduction:**

    PARITY_EMPTY=
    posix:  PARITY_EMPTY
    pwsh:   PARITY_EMPTY=

**Fix:** `NAME=` in both. It is what `env` itself prints, it is what
`grep '^NAME='` expects, and a bare name reads as a variable with no value
rather than one with an empty value. That is the POSIX side changing.

**Touches:** `bin/safe-env`.

**Test:** an empty planted variable in `tests/test_safe_env.sh`, asserting the
exact line `NAME=`.

---

## B. Documentation disagrees with the code

Nothing new. `docs/patterns.en.md` describes the exclusions in prose — "a path
stays visible because it is configuration" — without listing the spellings, so
it is true of both files and useless for settling A1. After A1 lands, listing
the spellings in the same sentence costs one clause and would have prevented
this.

---

## C. Efficiency

Nothing. 44 values through either implementation is one invocation; the POSIX
side did 500 variables in 0.020 s (`review-2026-09-17-safe-env.md`), and the
port's cost is PowerShell startup either way.

---

## D. Judgement on the design

What is right and must stay:

- **`Get-ChildItem Env:` rather than parsing lines.** It is why the port has no
  equivalent of `A1` in the POSIX review: a value containing a newline is one
  object here, so a private key block is masked whole. The POSIX version prints
  its body. The port is the correct one and the fix over there is to copy its
  shape.
- **The SQL-password pattern kept out of `$patterns`** with a comment saying
  why — the redactor has no SQL rule, and the tier-1 diff would fail if it were
  inside the list. That is the kind of note that survives a refactor.

What is arguable:

- **The two files reach the same verdict by different routes.** POSIX runs the
  shape rules first and the name rule last, so a match keeps the precise reason;
  the port ORs `Test-Secret` with `Test-NamedCredential`. The result is
  identical because both only produce a boolean, so this is not a divergence
  today. It becomes one the moment either wants to report *why* a value was
  masked. Recommendation: leave it, and note it in whichever file grows that
  feature first.
- **`$fallbacks` holds three rules and the fourth sits below the loop**, mirrored
  by the POSIX order where the compound rule is third. Same outcome, different
  reading order. Not worth changing; worth knowing when diffing the two by eye.

---

## What is NOT a defect (checked, so nobody spends the time again)

- **42 of 44 values agree exactly**, including every provider prefix, both JWT
  halves, the URL-with-password and the URL-without, all four generic
  fallbacks, the `key.signature` shape, the SQL `IDENTIFIED BY` form, and the
  name tier with its short/path/boolean exclusions.
- **Ordinary values survive on both sides**: a UUID, a `sha256:` digest, a PATH
  list, `JAVA_TOOL_OPTIONS`, a flag string, a locale, a plain sentence, a value
  containing `=`, a value with leading spaces, and a non-ASCII value.
- **Tier 1 does not drift** — `tests/test_redact.sh --pwsh` diffs `$patterns`
  against `bin/secrets-redact.ps1` and passes.
- **The base64 miss and the `PASS` substring miss are present in both**, so they
  are not parity defects. They are A2 and A3 of
  `review-2026-09-17-safe-env.md` and must be fixed in both files together.

## Done when

    bash tests/test_safe_env.sh          # passed ≥ 14, failed 0; exit 0
    bash tests/test_safe_env.sh --pwsh   # same count; exit 0
    bash tests/test_redact.sh            # passed 89, failed 0; exit 0
    bash tests/test_parity_safe_env.sh   # passed 4, failed 0; exit 0

- both items have a case in `tests/test_safe_env.sh` that failed on one
  implementation before the fix and passes on both after
- **Done 2026-09-17:** the parity script lives in `tests/`, not in a temporary
  directory. It needs no batching — the whole table is one process per side by
  construction
