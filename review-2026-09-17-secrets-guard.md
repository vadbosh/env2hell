# Review of bin/secrets-guard — a task for whoever fixes it

<!-- filename: review-2026-09-17-secrets-guard.md — one review per object -->

Date: 2026-09-17. Object: `bin/secrets-guard`, 196 lines, bash. Its PowerShell
port `bin/secrets-guard.ps1` (213 lines) is **not** in this pass — it gets its
own, as a parity check. `lib/patch_config.py` is read here only where it holds
the same policy (`DUMP_RULES`, `READERS`, `SECRET_FILES`); it is not the object.

Line numbers are as of commit `5100e79`. They will rot; anchor by name:
`rg -n 'pass A|pass B|CRED_NAME|READERS|SECRET_PATHS' bin/secrets-guard`.

Baseline, run before anything was touched:

    bash tests/test_guard.sh
    # passed 76, failed 0

    bash tests/test_safe_env.sh
    # passed 9, failed 0

    git status --short          # empty; main == origin/main

## How to work through this file

1. Read `docs/design.en.md` (§ "Pass A", § "Pass B", § "Failing open",
   § "What this does not do") and `kb/01-traps.md` first. Several things that
   look like defects are decisions with an incident behind them.
2. Every item below has a reproduction. Reproduce on the broken input BEFORE
   fixing, then write the case in `tests/test_guard.sh`, then fix.
3. Order: A by the fix order below, then B, then C. D only after the person
   agrees.
4. After each item: `bash tests/test_guard.sh` → `passed N, failed 0`.
5. **Take every verdict from the exit status, never from the text on screen.**
   This session's own `secrets-redact` hook rewrites terminal output, and it
   masked parts of the probe output during this very pass. `2` denies, `0`
   allows, `124` under `timeout` means the guard was killed. `kb/01-traps.md`
   records the hour this cost once already.
6. **The installed guard blocks the work of fixing it.** A heredoc whose body
   contains `env` or `cat .env` is denied (A8) — that is how this pass first met
   A8. Write case files with an editor, not with a shell heredoc.

**Invariants — a fix may not break these**, taken from what the project says
about itself:

- **Fail open on anything unexpected** — `docs/design.en.md` § "Failing open":
  no jq, no JSON, no command field ⇒ exit 0. "A guard that breaks the assistant
  when something unexpected arrives gets uninstalled." A fix that closes a miss
  by refusing to run is a regression by this project's own criteria.
- **It is not a sandbox** — `docs/design.en.md:278`, `README.md:325`. The target
  is "the ordinary accident". Encoding, reversing or writing to a file first is
  explicitly out of scope. Every A item below is an *ordinary* shape, not an
  evasion; that is the test each one had to pass to be listed.
- **The reader is looked for in quote-stripped text, the path in raw text** —
  `docs/design.en.md:98-117`. This split is what keeps a commit message out of
  the decision. Do not merge the two passes.
- **Locality**: reader and path must be in the same sub-command
  (`bin/secrets-guard:106-119`). The `rsync -e "ssh -i …pem" … | head` incident
  is what bought this; `tests/test_guard.sh:132-142` pins it.
- **Dependencies**: `bash` + `jq` + `sed` + `grep` + `awk`. No Python, no
  network. `install.sh` installs a single file.

**Fix order.** A1 and C1 are the same code; A6/A7/A8 are cheap and independent;
A2–A5, A9, A10 are pattern work in one place each.

1. **A6, A7** — one regex each, no structural change, and A6 currently denies a
   line of the project's own test harness. Cheapest, do them first.
2. **A1 with C1 together** — A1 *is* C1's number turned into a consequence.
   Rewriting pass B and the credential pass into one awk program removes the
   per-sub-command forks and the timeout with them. After this step re-run the
   reproductions of **every** other A item: they all live in the loops this step
   replaces.
3. **A2, A3, A4, A5** — pattern and tokenizer work in pass A / `SECRET_PATHS`.
   Independent of each other; each is one case plus one line.
4. **A9** — policy drift. Do it last of the A items: it is the one that changes
   two files and needs a test that diffs them, and steps 1–3 will have moved
   both lists.
5. **A8, A10** — independent of everything above.

**Exposure schedule.** A1 is the worst item and it is second, not first, because
A6/A7 take minutes and A1 is a rewrite. Until A1 lands, any Bash call with more
than ~520 sub-commands — a heredoc writing a file of that many lines is the
ordinary case — runs **completely unguarded**, with no message anywhere. The
interim measure that costs one line: raise `GUARD_TIMEOUT` from 5 to 30 in
`lib/patch_config.py` and re-run `./install.sh`. That moves the threshold from
~520 sub-commands to ~3100 and is worth doing on the day this review is read,
before any of the items are fixed. It does not close A1 — the guard still fails
open, just later.

Reproductions were run from a throwaway directory made with `mktemp -d`
(`/tmp/tmp.WsTCrVE7rM` on the machine that produced this file), with the case
files written by an editor and fed to the guard as JSON on stdin. Nothing was
deleted and no live configuration was touched. The one live check — A1 — used a
dummy `.env` created inside that directory, containing `DUMMY=not-a-secret`.

---

## A. Defects (each reproduced)

### A1. Past ~520 sub-commands the guard is killed by its own hook timeout and the command runs unguarded

**Class:** silent wrong result — the assistant runs the command, the guard says
nothing, and nothing in the transcript records that the check did not happen.

**Where:** the two `while IFS= read -r rawsub` loops, lines 137-145 and 163-194.
Each iteration forks `sed` once and `grep` two to four times, so the cost is
per *sub-command*, not per byte. `raw_subs` splits on `;`, `&`, `|` **and** on
newlines, so every line of a heredoc body is one iteration. The guard is wired
with `"timeout": 5` (`lib/patch_config.py:79`, `GUARD_TIMEOUT = 5`), and a
PreToolUse hook killed at its timeout does not deny: the call proceeds.

**Reproduction** — the pair, verdict from exit status (`2` denied, `124`
killed):

    # 500 lines of ordinary text, then the denied read
    …/perf4.sh
    #   500 lines + "cat .env"   BLOCK    4.730790638 s
    #   550 lines + "cat .env"   KILLED   5.035828874 s
    #  1000 lines + "cat .env"   KILLED   5.025805625 s

The same threshold reached with separators instead of newlines — a 1208-byte
command is enough:

    #   400 x ':;' + cat .env   BLOCK    3.818 s  len=808
    #   600 x ':;' + cat .env   KILLED   5.019 s  len=1208

And on this machine, through the **installed** guard and the real Claude Code
hook runner, with a dummy `.env` holding `DUMMY=not-a-secret`:

    :;:;:; … (600 times) … ;cat /tmp/tmp.WsTCrVE7rM/sbx/.env
    # DUMMY=not-a-secret

The file was read and printed. The guard neither denied nor reported anything.

Cost by line count, measured on ordinary text that is *not* denied (so the whole
program runs):

    10 lines    0.273 s
    100 lines   1.281 s
    500 lines   6.925 s
    1000 lines  13.342 s
    2000 lines  26.616 s

≈ 13 ms per sub-command, linear. Size alone is not the problem: a single-token
1 MB command costs 0.83 s.

**Fix:** move pass B and the credential-name pass into the awk program that
already splits the input (lines 120-135), so the whole scan is one process
instead of 4-7 per sub-command. Keep the quote-stripped/raw split inside awk —
the invariant above is what the split buys, and it is expressible there. Keep
the fail-open contract: awk failing for any reason must still exit 0.
Independently of the rewrite, raise `GUARD_TIMEOUT`; 5 s was never measured
against anything but a one-line command.

**Touches:** `bin/secrets-guard`; `bin/secrets-guard.ps1` (the port has the same
per-line loop shape — check it, that is its own pass); `lib/patch_config.py`
(`GUARD_TIMEOUT`); nothing enforces agreement between the two implementations
today — see A9.

**Test:** new group `size and timeout` in `tests/test_guard.sh`: a command of
2000 `:;` separators ending in `cat .env`, expected exit 2, run under
`timeout 5`. It fails before the fix (`124`) and passes after (`2`). Add the
mirror case for the port.

### A2. `/proc/self/environ` is not matched

**Class:** silent wrong result — it dumps the current process's environment,
which is the whole thing this tool exists to stop.

**Where:** `SECRET_PATHS`, line 103: `/proc/[0-9]+/environ`. `self`, `thread-self`
and `$$` are not digits.

**Reproduction:**

    cat /proc/self/environ        → pass(0)
    strings /proc/self/environ    → pass(0)
    cat /proc/1/environ           → BLOCK

**Fix:** widen the alternation to `/proc/([0-9]+|self|thread-self)/environ`.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`, and the file list in
`docs/patterns.en.md` / `docs/patterns.ru.md` and `docs/design.en.md:92`
(`/proc/N/environ`), which describe the numeric form only.

**Test:** `check 2 'cat /proc/self/environ'` in the pass B group, beside the
existing `check 2 'cat /proc/1/environ'`.

### A3. An inline script in any interpreter passes

**Class:** silent wrong result.

**Where:** pass A only classifies the first word of a sub-command; `python3`,
`node`, `perl`, `ruby`, `bash`, `sh` are not in the wrapper list (line 42) and
have no case of their own, so their `-c` / `-e` payload is never looked at.

**Reproduction** (none of these are evasions — each is a shape an assistant
writes by habit):

    python3 -c 'import os; print(os.environ)'   → pass(0)
    node -e 'console.log(process.env)'          → pass(0)
    perl -e 'print %ENV'                        → pass(0)
    ruby -e 'puts ENV.to_h'                     → pass(0)
    bash -c env                                 → pass(0)
    sh -c "printenv"                            → pass(0)
    eval env                                    → pass(0)
    python3 -c "print(open('.env').read())"     → pass(0)

**Fix:** two separate changes, and they are not the same size.

- `bash -c`, `sh -c`, `zsh -c`, `eval`: treat as wrappers whose *argument* is a
  command line, and re-run pass A on it. Small and exact.
- `python3 -c` and friends: the payload is not shell. Do not try to parse it —
  match the environment-dumping idioms as text (`os.environ`, `process.env`,
  `%ENV`, `ENV.to_h`) and deny those. Say in the message that it is the idiom
  that was recognised, not the language.

The second half is a pattern list, so it will always be partial; that is
acceptable under the "not a sandbox" invariant, and it is worth saying so in
`docs/design.en.md` § "What this does not do" rather than leaving the reader to
assume coverage.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`, `docs/design.*.md`.

**Test:** new group `inline interpreters` — one `check 2` per line above, plus
`check 0 'python3 -c "print(1+1)"'` and `check 0 'bash -c "ls -la"'` so the
cure is not worse than the disease.

### A4. A command name pass A refuses to classify disables the whole sub-command

**Class:** silent wrong result.

**Where:** lines 49-53. A fragment that does not start with `[a-zA-Z_]`, or that
contains any character outside `[a-zA-Z0-9_.-]`, is `continue`d — the *entire*
sub-command is skipped, not just that token.

**Reproduction:**

    /usr/bin/env       → pass(0)      # absolute path
    \env               → pass(0)      # the ordinary "bypass my alias" form
    "env"              → pass(0)      # quotes removed by pass A's stripping
    FOO=bar env        → pass(0)      # assignment prefix; `=` fails the charset test
    env                → BLOCK        # the same command, plainly written

**Fix:** three parts. Take the basename when the first token contains a `/` or
`\` — the tool already does exactly this for hook ownership
(`lib/patch_config.py`, `is_ours`, which splits on the separator and compares
basenames). Strip a leading `\`. Skip *leading assignment tokens* (`NAME=value`)
and classify the first token after them, rather than abandoning the
sub-command. The quoted form `"env"` follows from pass A's stripping and is the
one case worth leaving alone — it cannot be fixed without giving up the
stripping the invariants list protects; say so in `docs/design.en.md:60`.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`, `docs/design.en.md`
(the list of skipped fragment shapes — see B3).

**Test:** new group `command name forms`: `check 2` for the first four lines
above except `"env"`, which gets `check 0` with a comment naming the reason.

### A5. `printenv -0` dumps everything and is allowed

**Class:** silent wrong result.

**Where:** line 64 — `printenv` is denied only when it has **no** arguments.

**Reproduction** (run in an isolated environment so nothing real was printed):

    env -i FOO=bar printenv -0 | tr '\0' '\n'
    # FOO=bar
    env -i FOO=bar /usr/bin/printenv --null | tr '\0' '\n'
    # FOO=bar

    printenv -0        → pass(0)
    printenv           → BLOCK

`-0` / `--null` changes the separator, not the scope: with no VARIABLE named it
still prints every pair.

**Fix:** deny `printenv` when every remaining argument starts with `-`, the same
shape pass A already uses for `env` (line 58-62). `printenv PATH` must keep
working — `tests/test_guard.sh:96` pins it.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`, and `DUMP_RULES` in
`lib/patch_config.py`, where `"printenv *": "ask"` lets `printenv -0` through as
a prompt rather than a denial in Opencode.

**Test:** `check 2 'printenv -0'`, `check 2 'printenv --null'` beside the
existing `check 0 'printenv PATH'`.

### A6. `$pass` and `$passed` are denied — including a line of this project's own test harness

**Class:** damage — this is the class that gets a guard switched off, and with
it everything the guard was giving.

**Where:** `CRED_NAME`, line 159: the alternation starts with `PASS`, and it is
used with `grep -Eqi` inside `[A-Za-z0-9_]*…[A-Za-z0-9_]*` (lines 187, 191). So
any variable whose name merely *contains* `pass`, in any case, is denied.

**Reproduction** — found by running the guard over every non-comment line of the
project's own shell scripts, 1368 lines, 2 denied, both of them this:

    printf '\npassed %d, failed %d\n' "$pass" "$fail"   → BLOCK
    echo "$passed of $total"                            → BLOCK
    echo "$bypass_cache"                                → BLOCK
    echo "$compass_dir"                                 → BLOCK

The first line is `tests/test_guard.sh`'s own summary line. The guard denies the
command that reports its own test results.

**Fix:** require a word boundary on the left of `PASS` — `(^|_)` in the variable
name, which is how `PASSWORD`, `DB_PASSWORD` and `db_password` are written and
how `bypass`/`compass`/`passed` are not. Keep the case-insensitive match:
`tests/test_guard.sh:155` pins `echo "$db_password"`.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`.

**Test:** in the credential-name group, `check 0` for `"$pass"`, `"$passed"`,
`"$bypass_cache"`, next to the existing `check 2 'echo "$db_password"'`.

### A7. `.env.example` and its siblings are denied

**Class:** damage.

**Where:** `SECRET_PATHS`, line 90: `\.env([.[:space:]"']|$)` — the trailing
alternative `.` is what makes `.env.production` match, and it matches
`.env.example` with it.

**Reproduction:**

    cat .env.example      → BLOCK
    head -1 .env.sample   → BLOCK
    cat .env.template     → BLOCK
    cat .env.dist         → BLOCK
    cat /srv/app/.env.production   → BLOCK   (correct — tests/test_guard.sh:74)

`.env.example` is the file that is committed to git precisely because it holds
no values. Reading it is routine, and this is the first thing anybody does in an
unfamiliar repository.

**Fix:** exempt the well-known template suffixes — `example`, `sample`,
`template`, `dist`, `defaults` — after the `.env.` prefix. Keep everything else
denied: the miss to avoid is `.env.prod-example` style names, so anchor the
exemption at the end of the path.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`, `SECRET_FILES` in
`lib/patch_config.py` (`*.env.*` denies the same files in Opencode), and the
file table in `docs/patterns.*.md`.

**Test:** `check 0` for the four template names, `check 2 'cat .env.production'`
kept as it is.

### A8. A heredoc body is scanned as if it were commands

**Class:** damage.

**Where:** the awk splitter (lines 120-135) knows quotes and separators but not
heredocs, so `<<'EOF' … EOF` contributes one sub-command per line of *content*.

**Reproduction:**

    cat > /tmp/cases.txt <<'CASES'
    env
    printenv
    CASES
    → BLOCK

    cat > /tmp/notes.md <<'EOF'
    Then run cat .env to see it.
    EOF
    → BLOCK

Nothing here reads or prints anything: the text is being *written to a file*.
This is how the pass that produced this review first met the item — the first
attempt to write a case file was denied by the installed guard.

**Fix:** in the splitter, recognise `<<` / `<<-` followed by a (possibly quoted)
delimiter, and treat every line up to the delimiter as data: emit it as a single
inert record rather than as sub-commands. A heredoc *body* is never a command;
the `cat > file` in front of it still is and must still be classified.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`, and
`kb/01-traps.md`, which currently records the workaround ("write case files
with an editor") as a fact of life — once this is fixed, that note should say
which release fixed it.

**Test:** new group `heredocs`: the two cases above as `check 0`, plus
`check 2` for a heredoc followed by a real `; env` outside it, so the fix does
not swallow the rest of the line.

### A9. The same policy exists in two places and they disagree

**Class:** silent wrong result — the same command is denied in Opencode and
allowed in Claude Code and Codex, on the same machine, with no sign anywhere
that the two differ.

**Where:** `READERS` and `SECRET_PATHS` in `bin/secrets-guard` (lines 82-104)
versus `READERS` and `SECRET_FILES` in `lib/patch_config.py` (lines 167-182).
The Python lists are turned into Opencode `permission.bash` deny rules by
`file_rules()`; the shell lists serve the Claude Code and Codex hooks. Nothing
compares them.

**Reproduction** — present in `SECRET_FILES`, absent from the shell guard:

    cat server.key          → pass(0)      # "*.key"
    cat credentials.json    → pass(0)      # "*credentials*"
    cat secrets.yaml        → pass(0)      # "*secrets*"
    cat my-credentials.txt  → pass(0)      # "*credentials*"
    cat prod.env            → pass(0)      # "*.env" — the guard needs a boundary
                                           #   before ".env", so only a leading
                                           #   dot matches

And the other direction: `view`, `type` and `gc` are readers in the shell guard
(line 82) and are missing from `lib/patch_config.py:167`, so `type
C:\Users\me\.aws\credentials` — a case the suite pins at
`tests/test_guard.sh:86` — is denied by the hook and allowed by the Opencode
rule set.

**Fix:** one source, or a test that diffs the two. Given the dependency
invariant (the hook is a single bash file with no Python), the practical shape
is the second: a case in `tests/test_release.sh` or a new `tests/test_policy.sh`
that extracts both lists and compares them character for character, the way
`tests/test_redact.sh` already diffs the two tier-1 pattern lists. Decide
per entry which list is right — `*secrets*` and `*credentials*` are broad and
may be deliberate for Opencode's prompt-based rules and wrong for a hard deny.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`,
`lib/patch_config.py`, `docs/patterns.*.md` (see B1, B2), plus whichever test
file gets the diff. **Nothing enforces the agreement today** — that is the
finding.

**Test:** the diff test itself, plus `check 2` cases for whichever paths the
decision adds to the shell guard.

### A10. Only `echo` and `printf` count as printing a credential-named variable

**Class:** silent wrong result.

**Where:** line 167 — the gate for the credential-name pass is
`(^|[[:space:]])(echo|printf)([[:space:]]|$)`.

**Reproduction:**

    cat <<< "$GITHUB_TOKEN"                  → pass(0)
    tee <<< "$API_KEY"                       → pass(0)
    awk -v k="$API_KEY" 'BEGIN{print k}'     → pass(0)
    echo "$GITHUB_TOKEN"                     → BLOCK

**Fix:** add the here-string form — a `<<<` whose text contains a
credential-named expansion is the same act as `echo` — and add `tee` and `cat`
to the gate. `awk -v` is a further step and is worth listing in
`docs/design.en.md` § "What this does not do" rather than chasing: the argument
of an arbitrary program is not decidable, and the invariant says so.

**Touches:** `bin/secrets-guard`, `bin/secrets-guard.ps1`, `docs/design.*.md`.

**Test:** in the credential-name group, `check 2 'cat <<< "$GITHUB_TOKEN"'` and
`check 2 'tee <<< "$API_KEY"'`; keep `check 0` for `grep TOKEN file` so the
widened gate does not start denying reads.

---

## B. Documentation disagrees with the code

### B1. `docs/patterns.en.md:121` says the guard's lists live in `lib/patch_config.py`

The text:

> `safe-env` masks values. `secrets-guard` denies commands — a different list,
> kept in `lib/patch_config.py` (`DUMP_RULES`, `READERS`, `SECRET_FILES`) so that
> the installer and the documentation cannot disagree.

They are kept there for the *installer*. `bin/secrets-guard` carries its own
copies (lines 82-104, 159-161) and reads nothing from Python, which is why A9
exists. A reader who changes only the Python list changes Opencode's behaviour
and nothing else.

**Fix:** say which consumer each list serves, and name the drift as a known gap
until A9 lands. Both language versions: `docs/patterns.en.md`,
`docs/patterns.ru.md`.

### B2. The file table in `docs/patterns.en.md:128-133` lists paths the guard never matches

`*.key`, `*credentials*` and `*secrets*` appear in the table; the shell guard
has none of them (reproduced under A9). A reader takes the table as the policy.

**Fix:** either the table or the guard — the decision belongs to A9. Whichever
way it goes, the table is generated from one of the two lists or annotated per
row with which engine enforces it. Both language versions.

### B3. `docs/design.en.md:60` lists the skipped fragment shapes incompletely

The text names fragments starting with `"`, `=`, `{`, `[`, `$` or `*`. The code
(lines 49-53) also skips anything starting with `/`, `\`, `.` or a digit, and
anything containing a character outside `[a-zA-Z0-9_.-]` — which is how
`/usr/bin/env` and `FOO=bar env` get through (A4).

**Fix:** after A4 lands, rewrite the paragraph to describe what is left. Both
language versions.

---

## C. Efficiency

Measurements on this object, this machine, GNU Awk 5.3.2, bash 5.3.9, from
`date +%s.%N` around a single invocation.

### C1. Three to seven processes per sub-command

Pass B forks `sed` once and `grep` twice per sub-command (lines 141-142); the
credential pass forks `grep` once more per sub-command and two to three per
command substitution (lines 167-190). Cost is ≈ 13 ms per sub-command and
linear in their count, against 0.83 s for a 1 MB single-token command — the work
is in the forks, not in the text.

Baseline for an ordinary one-line command, which is what most of them are:

    ls -la               0.062 s
    git status --short   0.083 s
    rg -n foo src/       0.063 s

That is 60-80 ms added to every Bash call in every session, of which most is
process startup, not matching.

**Fix:** the same rewrite as A1 — one awk program instead of a loop of forks.
This item exists separately because it is true even at sizes where A1 never
fires: a fix that only raises the timeout closes A1's blast radius and leaves
this number where it is.

---

## D. Judgement on the design (change only after the person agrees)

What is right and must stay:

- **Two passes over differently-stripped text.** Reproduced: `git commit -m
  "docs: cat .env ends the same way"` passes, `jq -r '.permission.bash.env'
  opencode.json | head` passes. Both were false denials once, both are pinned by
  tests, and both come straight back if the passes are merged.
- **Locality of reader and path.** `rsync -e "ssh -i ~/.ssh/id.pem" host:/src
  /dst | head -5` passes; `ssh -i ~/.ssh/id.pem host uptime && cat .env` is
  denied. The distinction is exactly right and is not obvious.
- **Fail open.** Uncomfortable and correct, for the reason the design document
  gives. It is also the reason A1 is as bad as it is — see the next point.
- **Command substitutions are unwrapped innermost-first** (lines 184-190), so
  `echo "$(curl -u "$E:$API_TOKEN" …)"` passes while
  `echo "$(printf %s "$JIRA_API_TOKEN")"` is denied. That is a hard distinction,
  drawn correctly, with tests on both sides.

What is arguable:

- **Failing open on *timeout* is not the same decision as failing open on a
  missing `jq`.** The documented rationale is "do not break the assistant when
  something unexpected arrives". A timeout is not an unexpected payload; it is
  the guard saying it did not finish. A hook that exits 2 with "guard timed out,
  re-run with fewer sub-commands" costs one denied call and never lets a dump
  through. Recommendation: **not now** — it needs a measured worst case first,
  and after A1 the worst case changes by an order of magnitude. Revisit once A1
  has landed and the 13 ms is a fraction of itself.
- **Credential names are matched as substrings, in any case, with no regard for
  suffix conventions.** A6 is the sharp end of it, but the same looseness denies
  `echo "$API_KEY_FILE"`, `echo "$TOKEN_PATH"` and `echo "$SECRET_NAME is not
  set"` — all reproduced, all `BLOCK`. `NAME_FILE` is the Docker and systemd
  convention for "the path to the secret, not the secret". Recommendation: fix
  the boundary (A6) now, and treat the `_FILE`/`_PATH` suffix exemption as a
  separate decision — it trades a real false positive for a real miss
  (`$TOKEN_PATH` genuinely holding a token), and the project's own rule file
  argues that the name is the only thing that can decide.
- **One policy, three implementations** (bash, PowerShell, Python), with a
  parity test for the redactor and none for the guard. A9 proposes the test.
  Worth noting that the redactor's parity check found three defects in one day
  that one-sided tests could not — `kb/07-state-2026-09-16.md`.

---

## What is NOT a defect (checked, so nobody spends the time again)

- **False-positive rate on real input is low.** Every non-empty, non-comment
  line of `README.md` and `docs/*.md` code blocks — 135 lines — produced 8
  denials, and all 8 are the documentation's own examples of denied commands.
  Every such line of `install.sh`, `uninstall.sh`, `release.sh`, `bin/safe-env`
  and `tests/*.sh` — 1368 lines — produced 2 denials, both of them A6.
- **Apostrophes in double-quoted text do not break the stripping.**
  `git commit -m "don't cat .env now"` passes; `echo "it's fine" && cat .env` is
  denied. The unbalanced-quote case works out correctly in both directions.
- **Codex sends the payload shape the guard expects.** `tool_input.command`,
  confirmed against a working Codex PreToolUse hook on this machine
  (`~/.codex/hooks/large-read-guard.py`, which reads the same field) and against
  Codex 0.154.0's live `~/.codex/hooks.json` wiring. Read, not modified.
- **Size alone is not a problem.** A 1 MB single-token command: 0.83 s, still
  denied. The timeout item (A1) is about the *count* of sub-commands.
- **`set -f` makes the unquoted `toks=($sub)` expansion safe** — globbing is off
  for the whole script (line 16), which is the risk that construct normally
  carries.
- **The wrapper list works as documented.** `rtk env`, `sudo env`, `command env`
  and `env --` are denied; `helm history`, `docker history`, `env VAR=1 cmd`,
  `set -e`, `declare X=1` and `printenv PATH` pass.
- **Comments are not mistaken for commands.** `ls -la   # then env is dumped`
  passes.
- **The guard covering only `Bash` is deliberate, not a gap.** A `.env` read
  through the Read tool is caught afterwards by `secrets-redact`, whose
  PostToolUse matcher is `Bash|Read|Grep` (`README.md:252`).
- **Fail-open on a missing `jq` or a non-JSON payload** is the documented
  contract, not an oversight (`docs/design.en.md` § "Failing open").

**One item could not be verified here.** Under `set -u`, bash before 4.4 treats
`"${rest[@]}"` on an empty array as an unbound variable and exits — which would
make `env` and `declare` fail open on macOS, where the system bash is 3.2.
`README.md:10` claims macOS support. `BASH_COMPAT=4.3` does not restore the old
behaviour, so it cannot be reproduced on this machine. The one command that
settles it, on a macOS box or in a container with that bash:

    /bin/bash --version | head -1        # expect 3.2.x
    echo '{"tool_input":{"command":"env"}}' | /bin/bash bin/secrets-guard; echo $?
    # 2 = correct. 1 with "unbound variable" on stderr = the defect.

## Done when

Commands to paste, each with the status it should exit with:

    bash tests/test_guard.sh                    # passed ≥ 100, failed 0; exit 0
    bash tests/test_guard.sh --pwsh             # same count as above; exit 0
    bash tests/test_safe_env.sh                 # passed 9, failed 0; exit 0
    bash tests/test_install.sh                  # passed 52, failed 0; exit 0
    bash tests/test_release.sh                  # passed ≥ 9, failed 0; exit 0

Per item — every line below feeds the command to the guard on stdin and reads
the exit status, because `2` is the correct answer for most of them and a `&&`
chain would read that as failure:

    g () { jq -nc --arg c "$1" '{tool_input:{command:$c}}' | bin/secrets-guard >/dev/null 2>&1; echo "$?"; }

    A1  timeout 5 … 2000 ':;' + 'cat .env'      # 2, not 124
    A2  g 'cat /proc/self/environ'              # 2
    A3  g 'python3 -c "import os; print(os.environ)"'   # 2
        g 'bash -c env'                         # 2
        g 'python3 -c "print(1+1)"'             # 0
    A4  g '/usr/bin/env'                        # 2
        g 'FOO=bar env'                         # 2
    A5  g 'printenv -0'                         # 2
        g 'printenv PATH'                       # 0
    A6  g 'printf "passed %d\n" "$pass"'        # 0
        g 'echo "$db_password"'                 # 2
    A7  g 'cat .env.example'                    # 0
        g 'cat .env.production'                 # 2
    A8  g "$(printf 'cat > /tmp/x <<EOF\nenv\nEOF\n')"  # 0
    A9  the list-diff test                      # exit 0
    A10 g 'cat <<< "$GITHUB_TOKEN"'             # 2

- every A item has a case in `tests/test_guard.sh` that failed before the fix
  and passes after, in both the POSIX and `--pwsh` runs
- B1-B3 are corrected in both language versions, with the real output pasted in
  rather than retyped
- `kb/01-traps.md` loses the heredoc workaround once A8 lands, and gains the
  release that fixed it
- `docs/design.en.md` § "What this does not do" names what A3 and A10 leave
  uncovered on purpose
