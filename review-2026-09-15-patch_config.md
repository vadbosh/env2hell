# Review — `lib/patch_config.py`

| | |
|---|---|
| Object | `lib/patch_config.py` (514 lines), the installer's config patcher |
| Date | 2026-09-15 (`date -Is` → `2026-09-15T22:29:05+00:00`) |
| Commit | `bf6fba1 redact: a label followed by a name is not a secret`, working tree clean |
| Runtime here | Python 3.14.4, bash 5.3.9, shellcheck 0.11.0, `/usr/bin/awk → gawk` |
| Reviewed by | a session that did not write this file |

Related code read as part of the object's contract, not audited here:
`install.sh` (call site, lines 155–167), `install.ps1` (the Windows port of the
same decisions), `tests/test_install.sh` (its only test), `bin/secrets-redact`
(the command whose timeout this file writes).

## Baseline, before anything was touched

```
$ bash tests/test_install.sh   | tail -1      passed 14, failed 0
$ bash tests/test_guard.sh     | tail -1      passed 76, failed 0
$ bash tests/test_redact.sh    | tail -1      passed 62, failed 0
$ bash tests/test_safe_env.sh  | tail -1      passed  9, failed 0
$ bash tests/test_scan.sh      | tail -1      passed 16, failed 0
$ shellcheck -S style install.sh uninstall.sh release.sh bin/* tools/* tests/*.sh
   info-level only (SC2016 in tests, deliberate single quotes)
$ python3 -m py_compile lib/patch_config.py   → OK
```

177 tests green. Every failure below is new ground, not a broken tree.

## How to work through this file

1. Read **Invariants** first. A fix that closes a finding by breaking one of
   them is not a fix.
2. Work **A** in the order given in **Fix order** — not top to bottom. Items
   A2 and A3 share a code path; A1 depends on a decision, not on code.
3. Reproduce before fixing. Every item carries the command that shows it. Run
   it, see it fail, then change the code.
4. Reproductions run in a throwaway sandbox from `mktemp -d`, with `HOME`
   pointed inside it. Nothing here was run against the real `~/.claude`,
   `~/.codex` or `~/.config/opencode`. The sandbox used was
   `/tmp/tmp.snGXbDrywJ`; make your own — a fixed path collides with the next
   run. Nothing in it is deleted, so the evidence stays readable.
5. `B` is text work and can go at any time. `C` needs a decision about cost.
   `D` is questions for the author, not tasks.

The reproductions used two credential-shaped strings, invented for the probes:
a GitLab personal-token shape (`glpat-` plus twenty placeholder characters) and
the `<REDACTED:…>` samples. Neither is written out here, and no rotation is
needed — a review that quotes a token in full makes every later edit of itself
trip the redactor it is reviewing, which is how this line came to be phrased by
description instead.

## Invariants — what a fix may not break

Taken from the project's own words, not from taste:

| # | Invariant | Where the project says it |
|---|---|---|
| I1 | The hook fails **open**: a broken hook must never break the session | `bin/secrets-redact` lines 26–28 |
| I2 | Patching is idempotent — a second run changes nothing | `lib/patch_config.py` line 29, `tests/test_install.sh` |
| I3 | A file about to change is backed up first | `lib/patch_config.py` line 30 |
| I4 | The POSIX and PowerShell installers write the same policy | `install.ps1` line 106 |
| I5 | No test may touch the real configuration | `tests/test_install.sh` lines 13–14 |
| I6 | A mangled tool result is worse than an unmasked one | `patch_notice_hooks` docstring, lines 290–294 |

I1 is the one that bites: it is exactly why A1 is severe, and it forbids the
obvious fix of making the hook block when it cannot finish.

---

# A. Defects

## A1 — `timeout: 10` drops the redactor on every result over ~1 MB, and it fails open

**✔ Closed 2026-09-16.** Two steps, and the second is the real one. The three
entries carry `REDACT_TIMEOUT = 60` (`$RedactTimeout` in `install.ps1`), which
moved the cliff from ~1 MB to ~5 MB; then `a6f7cb8` made the masking pass 33×
faster — one pattern for both separators, see
`review-2026-09-16-secrets-redact.md` A1 — so the same 60 s now covers roughly
200 MB. 1.1 MB takes 0.36 s where it took 10.73 s.

The number stays at 60 rather than going back to 10: it costs nothing when the
hook finishes in fractions of a second, and it is the margin for a machine
slower than this one. Tests: *the redactor is given at least 60 s* (a floor,
not the value) and *install.ps1 gives the redactor the same 60 s as
lib/patch_config.py*.

**Class: silent wrong result.**

**Where:** `lib/patch_config.py` lines 264, 340, 406 — the `"timeout": 10` field
of the three `secrets-redact` entries. Names outlast the line numbers:
`rg -n '"timeout"' lib/patch_config.py`.

**Mechanism.** The redactor's masking pass costs ~11 s per MB on this machine.
Claude Code kills a hook at its `timeout` and keeps the original result, so
every tool result larger than roughly 1 MB reaches the model exactly as it was —
unmasked and, because the `--warn-only` entries have the same 10 s limit, also
unannounced.

**Reproduction.** The pair: just under the line, and just over.

```
$ bash /tmp/tmp.snGXbDrywJ/probe3.sh
===== 2 the size at which the 10 s hook timeout starts dropping results =====
  512K   payload=693978    exit=0    stdout=668342B    replaced
  768K   payload=971542    exit=0    stdout=935564B    replaced
  896K   payload=1110324   exit=124  stdout=0B         result reaches the model as it was
  1024K  payload=1249106   exit=124  stdout=0B         result reaches the model as it was
```

With a real token in a payload just over the line:

```
===== 3 a token in a payload just over the line =====
payload bytes: 1130313
  exit=124  stdout bytes=0
  the hook produced nothing: the token stays in the transcript verbatim

===== 4 the same payload with no time limit =====
  exit=0
  REDACTED count: 1
```

Same payload, same code — the only difference is the number this file writes.

**Which way it fails:** open. The guarded thing (the tool result) passes through
unguarded. That is I1 working as designed and is not negotiable; the number is.

**Where the time goes**, so the fix has a direction — it is the masking regex,
not the JSON handling, and not the choice of awk:

```
$ bash /tmp/tmp.snGXbDrywJ/probe4.sh
payload json: 1249106 bytes; plain text: 1158606 bytes
  jq: read the json, print stdout    exit=0   0.05s
  secrets-redact --filter (text in)  exit=0   11.54s
  whole hook path (json in)          exit=0   12.67s
  cat only                           exit=0   0.02s

$ bash /tmp/tmp.snGXbDrywJ/probe3.sh    # one 1 MB payload, each awk
  gawk (what runs here)  exit=0   seconds=11.25   out=1202786B
  mawk (gawk hidden)     exit=0   seconds=11.85   out=1202786B
```

mawk is not faster here. Do not "fix" this by switching awk.

**Fix.** Two halves, and this file owns only the first:

1. Raise the three `timeout` values to a number that covers the results this
   assistant actually produces, and say in the code comment which payload size
   that number buys at the measured ~90 KB/s. A tool result of 10 MB is not
   exotic; 10 s covers under 1 MB.
2. The real repair belongs to `bin/secrets-redact` — its throughput. That is a
   separate object with its own review. Until it lands, the number here is the
   only lever.

**Test.** In `tests/test_install.sh`, a new group asserting the written timeout
is at least the measured cost of the largest payload the suite feeds the
redactor. A test that only asserts `timeout == 10` locks the defect in.

---

## A2 — `--remove` deletes hook entries the user wrote themselves

**✔ Closed 2026-09-16.** Ownership is `is_ours(command, tool)`: `shlex.split`
the command, take `argv[0]`, compare its basename with the program name. A
substring is not a name. Ported to `install.ps1` as `Test-OurCommand`, which
splits on both path separators by hand — `[System.IO.Path]` uses the separator
of the machine it runs on, so under the Linux pwsh the tests use it read a
whole Windows path as one filename and matched nothing.
Tests: *install leaves a third-party hook and its arguments alone*,
*--remove takes ours out and leaves theirs*, *--remove still takes every entry
of ours out*, and `tests/test_ownership.ps1` (8 cases) for the port.

**Class: damage.**

**Where:** `patch_post_hooks` lines 234–239 and `patch_failure_hooks` lines
382–388 — the removal branch matches `"secrets-redact" in command` over every
entry in the list, not over the entries this installer added.
`rg -n 'secrets-redact" in str' lib/patch_config.py`

**Mechanism.** Ownership is inferred from a substring of the command path. Any
command whose path contains the string — a wrapper, an audit script, a fork —
is read as ours and removed.

**Reproduction.** A user with their own `secrets-redact-audit` hook on `Write`:

```
$ bash /tmp/tmp.snGXbDrywJ/probe2.sh
===== 5 --remove next to a hook the user wrote themselves =====
    hook removed
    post-hook removed
    post-hook removed
    failure-hook removed
--- what survived ---
  PostToolUse	Bash	/home/me/bin/my-logger
```

`/home/me/bin/secrets-redact-audit` is gone. `my-logger` survived only because
its name does not contain the string.

**Fix.** Match on the exact command this installation writes (`h["command"] ==
wanted`), or write an ownership marker into the entry (`"env2hell": true`) and
remove on that. The marker also fixes A3 and makes the `_is_replace` flag
gymnastics at lines 218–230 unnecessary.

**Test.** `tests/test_install.sh`: seed a config with a third-party hook whose
command contains `secrets-redact`, install, remove, assert the third-party entry
is still there byte for byte.

---

## A3 — install silently repoints a command the user wrote

**✔ Closed 2026-09-16** by the same `is_ours` / `Test-OurCommand` change as A2 —
the repoint branch asks the same question as the remove branch. Test:
*our own entries are added next to the third-party ones*, with the wrapper and
its arguments unchanged.

**Class: damage, silent.**

**Where:** `patch_hooks` lines 189–196, the "already wired — make sure it points
at this installation" branch, and the same shape in `patch_post_hooks`
253–256, `patch_notice_hooks` 329–332, `patch_failure_hooks` 395–398.

**Mechanism.** Same ownership inference as A2, on the install path instead of
the remove path: any `PreToolUse` command containing `secrets-guard` is
overwritten with this installation's path. The user's wrapper, and its
arguments, vanish.

**Reproduction.**

```
$ bash /tmp/tmp.snGXbDrywJ/probe2.sh
===== 6 a user's own entry that merely mentions the name, on install =====
    hook repointed to /opt/env2hell/secrets-guard
  PreToolUse: /opt/env2hell/secrets-guard
```

Before the run the entry read `/home/me/bin/wrap-secrets-guard --audit`. The
installer reports this as `hook repointed`, which reads like housekeeping.

**Fix.** As A2 — exact match or an ownership marker. Repointing must only touch
an entry this installer recognises as its own; anything else is left alone and
mentioned in the output.

**Test.** Same group as A2, on the install path: the wrapper entry survives, and
a second entry is added beside it.

---

## A4 — an Opencode `.jsonc` config is unreadable, and the installer reports success anyway

**✔ Closed 2026-09-16, in both halves.**

`load` strips comments before parsing (`strip_jsonc`, a character at a time —
a regular expression cannot tell `//` inside `"https://…"` from a comment). So
a `.jsonc` is now *read*, which is what lets "= already current" answer
truthfully on such a machine. It is not *rewritten* when it actually carries
comments: `json.dump` would drop every one of them, and I6 says a mangled
configuration is worse than an unwired one. Instead the run exits 1, names the
file, and offers the two ways forward — rename it to `opencode.json`, which
Opencode also reads, or merge the wiring in by hand from the new
`patch_config.py opencode --print`. A `.jsonc` with no comments in it is
ordinary JSON and is wired normally.

`install.sh` no longer ends the call in `|| true`. Exit 1 marks the assistant
unwired, prints a red line, is repeated in the verify section, and makes the
whole run finish non-zero; exit 3 still means "this assistant is not installed
here" and is not an error.

Tests: *three runs write the rules once (394 plugin)*, *a commented .jsonc is
refused loudly and left untouched*, *a .jsonc with no comments in it is wired
normally*, *a missing configuration exits 3, not 1*. Before today nothing in
`tests/` ran `patch_opencode` at all.

**Class: silent wrong result.**

**Where:** `_opencode_config` lines 49–66 (picks `.jsonc` when it exists),
`load` lines 142–144 (`json.load`, which rejects comments), `main` lines
482–484 (the error path), and the call site `install.sh` lines 160–167, which
ends in `|| true`.

**Mechanism.** `_opencode_config` exists specifically so that a machine using
`opencode.jsonc` is not skipped — its docstring says so, at length. But the
loader is strict JSON, and a `.jsonc` earns its extension by carrying comments.
The patch aborts with exit 1, the installer discards the exit code, and the
run's own "verify" section probes the guard binary rather than the wiring. The
user is told the install succeeded; Opencode has no permission rules and no
plugin registration.

**Reproduction.**

```
$ bash /tmp/tmp.snGXbDrywJ/probe1.sh
===== 1 opencode .jsonc with a comment =====
    …/opencode.jsonc is not valid JSON (Expecting property name enclosed in
    double quotes: line 2 column 3 (char 4)) — left untouched
exit=1
--- file after: ---
{
  // the model this machine uses
  "model": "anthropic/claude-opus-5"
}
--- backups: ---
opencode.jsonc
```

And the call site that hides it:

```
$ rg -n 'patch_config.py' install.sh
160:        "$PY" "$SRC/lib/patch_config.py" "$ide" --guard … --dry-run || true
164:        "$PY" "$SRC/lib/patch_config.py" "$ide" --guard … || true
```

**Fix.** Two independent halves, both needed:

1. Strip `//` and `/* */` comments before `json.load` when the path ends in
   `.jsonc` (and keep them out of the written file — or decline to rewrite a
   `.jsonc` at all and say so loudly). Note I6's spirit: rewriting a commented
   file with `json.dump` destroys the comments, which is its own damage. The
   honest minimum is to detect, refuse, and tell the user what to add by hand.
2. `install.sh` must stop swallowing the exit status. Exit 3 (config absent) is
   the only one that deserves `|| true`; 1 must fail the run or at least print
   a red line in the verify section.

**Test.** A new `tests/test_install.sh` group driving `opencode` — there is none
today (see the test-gap note under A7) — with three configs: `.json`, `.jsonc`
with comments, and neither present.

---

## A5 — a config that is a symlink is replaced by a regular file

**✔ Closed 2026-09-16.** `save` calls `os.path.realpath(path)` before the backup
and the write. Test: *a symlinked config stays a link and the target is wired*
(`tests/test_install.sh`) — `passed 22, failed 0`.

**Class: damage, silent.**

**Where:** `save` lines 147–156 — `os.replace(tmp, path)` where `path` is the
symlink itself.

**Mechanism.** Dotfiles under version control are usually symlinks into a repo.
`shutil.copy2` follows the link for the backup, the rename does not: the link is
replaced by a regular file. The user's repo keeps the old content, the live file
holds the wiring, and every later `git pull` in the dotfiles repo silently stops
reaching the assistant.

**Reproduction.**

```
$ bash /tmp/tmp.snGXbDrywJ/probe1.sh
===== 4 config that is a symlink into a dotfiles repo =====
before: symlink
after : REGULAR FILE — link broken
dotfiles copy hooks: False
ls:
/tmp/…/h-link/.claude:   settings.json  settings.json.bak.20260915-223140
/tmp/…/h-link/dotfiles:  settings.json
```

**Fix.** `path = os.path.realpath(path)` before backing up and writing, so the
rename lands on the real file and the link survives. State the choice in the
docstring: the tool follows the link and edits the target.

**Test.** `tests/test_install.sh`: seed a symlinked config, patch, assert
`[ -L ]` still holds and the target carries the hooks.

---

## A6 — the rewritten config loses its mode: 600 becomes 644

**✔ Closed 2026-09-16.** The mode is read from the original and applied with
`os.fchmod` to the temp file before anything is written into it — at creation,
not before the rename, which is what also closes A9. Test: *a 600 config is
still 600 after a patch*.

**Class: damage.**

**Where:** `save` lines 152–156 — the temp file is created with the default
umask and renamed over the original.

**Mechanism.** `os.replace` carries the temp file's mode, not the original's.
A config deliberately kept private becomes world-readable. This matters here
more than elsewhere: `~/.claude/settings.json` has an `env` block, which is a
documented place to put API keys — the very thing this repository exists to keep
out of sight.

**Reproduction.**

```
$ bash /tmp/tmp.snGXbDrywJ/probe1.sh
===== 3 permissions on the rewritten file =====
before: 600
after : 644
backup: 600
```

The backup keeps 600 (`shutil.copy2` preserves mode); the live file does not.

**Fix.** `os.chmod(tmp, os.stat(path).st_mode & 0o7777)` before the rename, or
`shutil.copymode(path, tmp)`. Do it for every IDE — Opencode's config carries
the permission rules and Codex's carries hook paths.

**Test.** `tests/test_install.sh`: `chmod 600`, patch, assert `stat -c %a` is
still 600.

---

## A7 — Windows installs are missing the Edit/Write/MCP warning, and the failure matcher is narrower

**✔ Closed 2026-09-16** (`101eecd`). `install.ps1` writes the notice entry, tells
it apart from the replacing one by the flag, and carries the three matchers as
named variables instead of literals in three functions. The agreement is
mechanical now: `tests/test_install.sh` reads the constants out of
`lib/patch_config.py` and the literals out of `install.ps1` and compares them
one by one — the redactor matcher, the notice matcher, the failure matcher and
the timeout. That is what the comment claiming "same rule set" was standing in
for, and what failed for two days.


**Class: silent wrong result, Windows only.**

**Where:** the divergence is between `lib/patch_config.py` (`NOTICE_MATCHER`
line 272, `FAILURE_MATCHER` line 278) and `install.ps1` line 247. Nothing
enforces the agreement; `install.ps1` line 106 asserts it in a comment.

**Mechanism.** The Python side grew a third entry (commit `2e4a0fc`, "Warn on
Edit, Write and MCP results") and widened the failure matcher. The PowerShell
port kept the older shape, so a Windows user editing a `.env`, or a failed
`Edit`/MCP call quoting a credential, produces no warning at all.

**Reproduction.**

```
$ bash /tmp/tmp.snGXbDrywJ/probe5.sh
===== 2 every PostToolUse-family entry each installer writes =====
-- python (lib/patch_config.py) --
  PostToolUse         Bash|Read|Grep | redact
  PostToolUse         Edit|Write|mcp__.* | redact --warn-only
  PostToolUseFailure  Bash|Read|Grep|Edit|Write|mcp__.* | redact --warn-only
-- powershell (install.ps1) --
  247:        matcher = 'Bash|Read|Grep'
  notice entry (Edit|Write|mcp) present: 0
```

**Blast radius of any fix in this area.** Every matcher, timeout and rule list
exists twice. Changing one means changing:

| Changed here | Must change with it | Enforced by |
|---|---|---|
| `GUARD_MATCHER`, `REDACT_MATCHER` | `install.ps1` lines 137, 183 | nothing |
| `NOTICE_MATCHER`, `FAILURE_MATCHER` | `install.ps1` line 247 (+ a missing entry) | nothing |
| `"timeout"` values | `install.ps1` lines 150, 211, 252 | nothing |
| `DUMP_RULES`, `READERS`, `SECRET_FILES` | `install.ps1` lines 107–121 | nothing |
| the written shape | `docs/install.en.md` line 48, `docs/install.ru.md` line 50 | nothing |

The rule lists are in step **today** — verified character for character, see
"What is NOT a defect". The matchers are not. A comment is what kept them
aligned, and it is what failed.

**Fix.** Add the notice entry to `install.ps1` and widen its failure matcher, then
make the agreement mechanical: a test that imports the constants from
`lib/patch_config.py`, extracts the literals from `install.ps1`, and diffs the
two sets. `probe5.sh` §1 is that test already written for the rule lists — it
passes; extend it to the four matchers and the timeouts and put it in
`tests/test_install.sh`.

**Test gap this exposes.** Nothing in `tests/` drives Opencode, `patch_opencode`
or `install.ps1`:

```
$ bash /tmp/tmp.snGXbDrywJ/probe5.sh
===== 3 what the test suite reaches =====
  ides driven by tests/test_install.sh: for ide in claude codex
  patch_opencode exercised anywhere:    0 lines
  install.ps1 exercised anywhere:       0 lines
```

`patch_opencode` writes 394 rules into a live config and has no test at all.

---

## A8 — a config holding valid JSON that is not an object crashes with a traceback

**✔ Closed 2026-09-16.** `main` refuses anything that is not a dict, in the same
wording as the decode-error branch beside it. Test: *a config holding a list is
refused with a sentence* — asserts exit 1 **and** no `Traceback` on the output.
Not ported to `install.ps1`: its reader builds a `PSCustomObject` and the shape
of the failure there was not reproduced, so it is untouched rather than assumed.

**Class: visible failure. Lowest of the A items — it fails closed and says so,
badly.**

**Where:** `main` lines 480–489 catches `json.JSONDecodeError` only; the first
`data.setdefault` in `patch_hooks` (line 174) assumes a dict.

**Reproduction.**

```
$ bash /tmp/tmp.snGXbDrywJ/probe1.sh
===== 5 settings.json containing a list =====
    hooks = data.setdefault("hooks", {})
            ^^^^^^^^^^^^^^^
AttributeError: 'list' object has no attribute 'setdefault'
exit=1
```

**Fix.** After `load`, `if not isinstance(data, dict): print(f"{path} is not a
JSON object — left untouched", file=sys.stderr); return 1`. One line, same
wording as the existing decode-error branch.

**Test.** `tests/test_install.sh`: a config containing `[]`, assert exit 1 and
no traceback on stderr.

---

## A9 — a killed run leaves a world-readable copy of the whole config behind

**✔ Closed 2026-09-16, with one thing worth knowing.** The temp file is created
by `mkstemp` (0600) and `fchmod`-ed to the original's mode before a byte is
written, so the leftover is no longer world-readable. Removing it has two
halves, because **a SIGKILL runs no `finally`**: the `finally` covers an
exception or a SIGINT, and a *stale-file sweep* at the top of `save` covers the
kill. Tests: *the copy a killed run leaves behind is not world-readable* and
*the next run sweeps a stale temp file the killed one left*.

The sweep only takes files older than `STALE_TEMP_SECONDS` (60). The first
version took every match and promptly deleted the in-flight temp file of a
patcher running alongside — the A10 race, re-introduced by its own fix, caught
by the A10 test in the same run:

```
FileNotFoundError: [Errno 2] No such file or directory:
  '.../settings.json.ym4f28mm.env2hell.tmp' -> '.../settings.json'
```

**Class: silent wrong result.** Worse than A6, which loses the mode of one
file: this leaves a *second* file with the same contents and no protection at
all, and nothing in the config itself shows that it exists.

**Where:** `save` line 152 — the temp file is created, written, and only then
renamed. Between those points it holds the entire new config at the default
umask, while the original is 600.

**Mechanism.** `shutil.copy2` takes the backup (mode preserved), the temp file
is written, `os.replace` renames it. A process killed in that window leaves
`<path>.env2hell.tmp` on disk. Nothing removes it — not an error path, and the
next run only overwrites it. On `~/.claude/settings.json` that file carries the
`env` block: the documented place for API keys, readable by anyone on the
machine.

**Reproduction** — killed between `copy2` and `os.replace`:

```
exit=9
config unchanged: yes
  600  settings.json
  600  settings.json.bak.20260915-224647
  644  settings.json.env2hell.tmp
leftover tmp carries the env block: matches: 1
```

The config itself is intact — the atomic write holds and the next run finishes
the job. The leftover is the finding.

**Fix.** Set the mode at creation rather than before the rename: `os.open(tmp,
O_CREAT|O_WRONLY|O_TRUNC, 0o600)`, or `shutil.copymode(path, tmp)` immediately
after creating it — the same edit A6 needs, one step earlier. Then remove the
temp file in a `finally`, so a crash or a signal after the write leaves nothing.

**Touches:** `lib/patch_config.py` (`save`); `install.ps1` if its writer has the
same shape. Fix together with A6 — one function, two lines, one reproduction.

**Test.** `tests/test_install.sh`: kill the patcher mid-write, assert the config
is unchanged **and** that no `*.env2hell.tmp` is left in the directory.

---

## A10 — two runs at once share one temp filename; the loser's edit vanishes

**◐ Half closed 2026-09-16 — the crash is gone, the lost update is not.**
`tempfile.mkstemp(dir=…)` gives each run its own name, so neither patcher can
pull the file out from under the other: both exit 0, and the config is valid
JSON carrying exactly one installation's paths. Tests: *two patchers at once
both finish cleanly* and *the config a race leaves behind is readable and wired
once*.

What remains is last-writer-wins. Each run computes its change from the file as
it was when that run started, so the slower one overwrites whatever the faster
one added. It is benign in the only case that occurs in practice — two runs of
the same installer write the same wiring — and it would need a lock, or a
re-read of the file inside the write, to be genuinely closed. That is a design
question, not a patch: see D5.

**Class: visible failure** — it exits non-zero with a traceback, but what was
lost is a patch, and nothing says which one.

**Where:** `save` line 152 — the temp name is `{path}.env2hell.tmp`, fixed and
derived from the target alone.

**Mechanism.** Two patchers on one config — `install.sh` re-run while the first
is still going, two IDE sessions, a manual run beside an automated one — write
the same temp path. Whichever renames first wins; the other finds its file gone.

**Reproduction:**

```
FileNotFoundError: [Errno 2] No such file or directory:
  '.../settings.json.env2hell.tmp' -> '.../settings.json'
A exit=1
```

**Fix.** `tempfile.mkstemp(dir=os.path.dirname(path))` — unique by construction
and already in the target's directory, so `os.replace` stays atomic. Mechanical;
this is not a design question.

**Touches:** `lib/patch_config.py` (`save`) only.

**Test.** `tests/test_install.sh`: start two patchers on one config, assert both
exit 0 and the result carries both edits — or that the second reports a lock
instead of a traceback.

---

## A11 — `install.ps1` died on an empty configuration, and nothing had ever run it

**✔ Closed 2026-09-16** (`f1968c5`), and written up because the gap it exposes
outlives the fix.

**Class: visible failure** — it stops and says something, but what it says names
no file and no cause, and the run has already printed three green lines above it.

**Where:** every `$o.PSObject.Properties.Name -contains …` in `install.ps1`,
fourteen of them. Under `Set-StrictMode -Version Latest` member enumeration over
an *empty* collection is an error rather than an empty result, and a
`settings.json` holding `{}` is exactly that object.

**Reproduction** — the first end-to-end run this file has ever had:

```
$ USERPROFILE=$H LOCALAPPDATA=$H/AppData pwsh -NoProfile -File install.ps1 -BinDir $H/bin
-- commands --
    + …/bin\secrets-guard.ps1
    + …/bin\secrets-redact.ps1
    + …/bin\safe-env.ps1
-- claude --
install.ps1: The property 'Name' cannot be found on this object. Verify that the property exists.
```

```
$ pwsh -NoProfile -File strict.ps1        # $data = '{}' | ConvertFrom-Json
props count: 0
THREW: The property 'Name' cannot be found on this object.
non-empty notcontains: True              # the same line, on an object with a key
```

**Fix.** `Test-Property`, which iterates the collection rather than enumerating
a member of it, in all fourteen places.

**What this says about the test gap**, which is the point of the item: A7 above
closed the *content* divergence between the two installers and left the port
still unexecuted. Reading a file for its literals is not running it. The suite
now runs it end to end with `USERPROFILE` and `LOCALAPPDATA` inside its own
temporary directory — three runs, the four entries, the 394 opencode rules —
and that group found this defect on its first execution.

**Test.** `tests/test_install.sh`: *a run over an empty configuration finishes*,
*three runs leave the same wiring*, four *wired …* assertions, and *opencode
gets the same 394 rules and the plugin*.

---

# B. Documentation disagrees with the code

## B1 — the docstring promises `.jsonc` support the loader does not have

**✔ Closed 2026-09-16** by making the code true rather than the text weaker:
the loader reads JSONC now. What the docstring gained is the limit — such a
file is read but not rewritten while it carries comments.

**Where:** module docstring line 9, `_opencode_config` docstring lines 50–60.
The function's whole justification is a machine that uses `opencode.jsonc`;
`load` cannot read one that has a comment in it. See A4 for the reproduction.

**Fix.** Either the code change in A4, or a sentence saying the file is
selected but only plain JSON can be patched. Not both.

## B2 — the stated exit codes are discarded by the only caller, and they use different streams

**✔ Closed 2026-09-16.** The docstring states each code with what it means to a
person *and* to `install.sh`; `install.sh` acts on 1 and finishes non-zero;
`config not found` moved to stderr, so every diagnostic is on one stream and
stdout carries only the running commentary.

**Where:** docstring line 35 ("Exit codes: 0 done (or nothing to do), 1 error,
3 config file absent") against `install.sh` lines 160–167 (`|| true`).

Two roles, one binary: run by hand the codes are the answer; run from
`install.sh` nothing reads them. Also `config not found` prints to **stdout**
(line 473) while every other diagnostic goes to **stderr** (lines 477, 483), so
a caller filtering stderr sees an empty report of a real problem:

```
$ bash /tmp/tmp.snGXbDrywJ/probe1.sh
===== 8 config absent =====
    config not found: /tmp/…/h-absent/.claude/settings.json
exit=3  (stdout above, not stderr)
exit with stdout discarded=3
```

**Fix.** Document the codes per role, send every diagnostic to stderr, and make
`install.sh` act on 1 (see A4).

---

# C. Efficiency

## C1 — 394 permission rules, 13 249 bytes, written into the user's Opencode config

**Measured:**

```
$ bash /tmp/tmp.snGXbDrywJ/probe1.sh
===== 2 opencode idempotency over three runs =====
    394 permission rules written
bash rules    : 394
file bytes    : 13249
```

The set is a cross product: `file_rules()` at line 138 is 12 readers × 32
patterns + 10 dump rules. One more reader costs 32 rules; one more secret-file
pattern costs 12.

**When it starts to hurt:** Opencode matches `permission.bash` per shell call,
and the file is re-read at startup. The per-call cost was not measured here —
Opencode is not installed on this machine, and a claim about its matcher would
be a guess. **Unverified.** The command that settles it: on a machine with
Opencode, time a trivial `bash` tool call with and without the block present.

**Fix, if the measurement justifies it:** collapse the cross product into
alternation patterns per reader rather than one key per pair, if Opencode's
matcher supports it — that is a question for its config schema, not for this
file.

## C2 — backups accumulate forever; 21 copies of one config on this machine

```
$ ls ~/.claude/ | grep -c 'settings.json.bak'
21
```

Each is a full copy of a file whose `env` block may carry keys, sitting in the
directory this project's own rule file tells people is sensitive. `save` (line
151) writes one on every changing run and nothing ever prunes them.

**Fix.** Keep the newest N (3 is plenty), or write into
`~/.local/state/env2hell/` instead of beside the original. The second option
also stops a `.bak` from being picked up by anything that scans the config
directory.

## C3 — a patch reformats the whole file: 68 changed lines for a 3-key config

```
$ bash /tmp/tmp.snGXbDrywJ/probe2.sh
===== 4 what a patch does to an existing hand-formatted settings.json =====
semantically identical
lines changed: 68
```

`json.dump(..., indent=2)` rewrites the user's indentation. Harmless in
meaning, expensive in a git-tracked dotfiles repo where the real change is four
lines. Pairs with A5: the users most affected are exactly the ones keeping the
file in git.

**Fix.** Detect the existing indent (first indented line) and reuse it. Cheap;
do it in `save`.

---

# D. Judgement on the design

Proposals, not tasks. None of these are changed without the author agreeing.

**D1 — matcher coverage is a list, and lists go stale.** `Bash|Read|Grep`
covers three tools by name. Not listed: `BashOutput` (the result of a background
shell — raw command output, precisely the leak class this exists for),
`NotebookRead`, `Task`, `WebFetch`. Whether `Bash` already matches `BashOutput`
depends on whether Claude Code anchors the matcher regex, which was **not
verified here** — no reproduction on this machine settles it, and a quote from
documentation is a hypothesis. The command that would settle it: wire a hook
with matcher `^Bash$` in a sandbox `HOME`, run a background shell, and see
whether it fires. Worth doing before adding names.

**D2 — `--remove` only deletes a permission rule whose value still matches**
(lines 434–440). A user who changed `env` from `deny` to `ask` keeps that key
after uninstall. Defensible — it is their edit — but undocumented, and the
opposite of what "uninstall" suggests.

**D3 — uninstall leaves empty scaffolding behind.** After `--remove`:

```
claude:   {"model": "x", "hooks": {"PreToolUse": []}}
opencode: leftover keys: ['instructions', 'permission', 'plugin'] — all empty
```

`patch_post_hooks` and `patch_failure_hooks` pop their empty event lists;
`patch_hooks` does not, and `patch_opencode` never prunes. Whether an empty
`permission.bash` means anything to Opencode is unknown here (same gap as C1).
Consistency is the argument, not a known bug.

**D4 — ownership by substring is the root of A2 and A3.** Both disappear if an
entry this installer writes carries a marker key and removal matches on it. It
would also retire the `_is_replace` flag reasoning at lines 218–230, whose own
comment records an incident it caused on Codex (2026-09-14, three duplicate
entries). Worth pinning that incident as a test case **before** touching it —
see the fix order.

**D5 — decided 2026-09-16: two installers at once are unsupported, and that
sentence is about Windows.** On POSIX the write is atomic and the temp name is
unique, so a race costs the slower run's patch and never the file: worth
recording as last-writer-wins, not as a prohibition. On Windows `Write-Json`
has no temp file at all —

```
install.ps1:60      Copy-Item $Path "$Path.bak.$Stamp" -Force
install.ps1:61      ($Data | ConvertTo-Json -Depth 100) | Set-Content -Encoding UTF8 $Path
```

— so two installers there can tear the configuration, not merely overwrite each
other's change. Neither a lock nor a re-read is being added; what is owed is a
line in the Windows installer's own documentation saying so. The reasoning that
led here, kept because it is what a later reader will re-derive:

**a lock, or a re-read inside the write?** A10 left last-writer-wins in
place (see the item). Two ways out, neither free: a lock file beside the config,
which is a new failure mode when a killed run leaves one behind; or re-reading
and re-patching the file inside `save`, which makes `save` know about patching
and is the larger change. A third answer is defensible: leave it, and say in the
docstring that two installers at once are not supported. Whoever decides should
know that the only concurrent case seen so far is two runs of the same
installer, which write the same thing.

---

# What is NOT a defect

Examined, reproduced, found correct — so the next reader does not spend the
time again.

- **Idempotency for Claude Code and Codex.** Three runs, entries compared as a
  whole shape and counted: `tests/test_install.sh` → `passed 14, failed 0`.
- **Idempotency for Opencode**, which no test covers — checked by hand:
  first run `394 permission rules written`, second and third `= already
  current`, exactly one backup written (probe1 §2).
- **The rule lists are in step with the PowerShell port**, character for
  character: readers 12/12, secret files 32/32, dump rules 10/10, all
  `identical=True` (probe5 §1). It is the matchers that diverged, not these.
- **The write is atomic and backed up.** Temp file in the same directory, then
  `os.replace`; `copy2` backup taken first and it preserves mode 600
  (probe1 §3). A4's error path genuinely leaves the file untouched — verified
  by diffing the `.jsonc` before and after.
- **An interrupted multi-IDE install heals itself.** Killed after the first
  IDE was wired, the machine is left with `claude` patched and `codex` and
  `opencode` untouched; running the installer again completes both and adds no
  duplicate entries. The half-applied state is a state the next run handles,
  not one it trips over. What the killed run *does* leave behind is A9.
- **The backup names this file generates are not eaten by `secrets-redact`.**
  Checked because the shape invites it: `save` (line 150) writes
  `%Y%m%d-%H%M%S`, so every backup ends in a 15-character run of digits and a
  dash — the shape a high-entropy rule would take for a token, and a redactor
  that mangles ordinary output is what gets a redactor switched off. Real
  machine output, `ls -la` of a config directory after three patches, piped
  through `secrets-redact --filter` and diffed against the input:

  ```
  $ bash /tmp/tmp.snGXbDrywJ/probe8.sh
  ===== 1 real ls of a config directory that has been patched =====
    identical — nothing masked

  ===== 2 the backup name on its own, in the shapes it actually appears in =====
    kept      settings.json.bak.20260915-224647
    kept      ~/.claude/settings.json.bak.20260915-224647
    kept      cp settings.json settings.json.bak.20260915-224647
    kept      -rw------- 1 root root 4096 Sep 15 22:46 settings.json.bak.20260915-224647
    kept      settings.json.env2hell.tmp
  ```

  Neighbouring widths (`20260915-2246`, `202609155-2246470`, `20260915_224647`,
  `v1.2.3-20260915-224647`) and the bare timestamp survive too (probe8 §3, §5):
  nothing in tier 1 matches the shape, and tier 2 needs a credential-shaped
  label on the line, which a filename does not carry. **No defect here today.**

  **Pinned since 2026-09-15**, four `check_shape keep` cases at
  `tests/test_redact.sh` lines 168–171 — the bare name, the name with a path,
  an `ls -la` line carrying one, and the installer's `*.env2hell.tmp`:

  ```
  $ bash tests/test_redact.sh            passed 66, failed 0   (was 62)
  $ bash tests/test_redact.sh --pwsh     passed 64, failed 0   (was 60)
  $ rg -c 'bak\.' tests/*.sh             tests/test_redact.sh:3
  ```

  Without the pin the next widening of the tier-2 entropy rule would start
  eating these names, and the first symptom would be an unreadable `ls` of a
  config directory in someone's session. Now it is a red test instead.
- **`--guard` is required where it matters** (line 476) and not demanded for
  Opencode or for `--remove`.
- **The guard's own `timeout: 5` is generous**: a 200 000-character command
  line returns in 0.73 s (probe2 §3). A1 is about the redactor's 10, not this 5.
- **`--remove` followed by a re-install lands in the same place** — a known-good
  round trip, asserted by the suite.
- **The `_is_replace` flag logic** (lines 218–230) does tell the warn-only entry
  from the replacing one on Claude Code, and does not do so on Codex where it
  would break: no duplicates after three runs on either.

---

# Fix order, and what stays open while you work

The items are not independent: A2 and A3 are the same inference in two
directions, and the marker that fixes them changes the code A4's and A8's
reproductions run through.

1. ~~**A8**~~ — **done 2026-09-16.**
2. ~~**A6 + A9 together, then A10, then A5**~~ — **done 2026-09-16**, in one
   pass over `save` as the order predicted; A10 came back half open (see its
   item) and produced D5. The five checks are in `tests/test_install.sh`:
   `passed 22, failed 0`, up from 14.
3. ~~**A2 + A3 together**~~ — **done 2026-09-16.** The 2026-09-14 Codex
   incident was already pinned by *no duplicate hook entries after three runs*,
   which is what that group was written for; it stayed green throughout. The
   fix turned out not to need the marker key of D4 — reading `argv[0]` answers
   the same question without touching the entry's schema, so nothing an
   assistant might validate was invented.
4. ~~**A4**~~ — **done 2026-09-16**, with the Opencode test group it needed.
   B1 and B2 closed with it: they were the same defect described in prose.
5. ~~**A7**~~ — **done 2026-09-16**, last as the order said.
6. ~~**A1**~~ — **done 2026-09-16**: the number first, then the throughput fix
   it was standing in for.

**Exposure, as it stands on 2026-09-16.** Closed. The interim measure landed
first and the throughput fix followed the same day, so the window is now results
larger than roughly 200 MB. `bin/secrets-redact` has its own review, and six of
its items are open — but none of them is this one.

A7 closed the same day: the entry is there, the matcher is wide, and the two
installers are diffed literal by literal rather than by a comment.

---

# Done when

Every command below is meant to be pasted and believed. Exit status given where
it is not the obvious 0.

```bash
# The baseline suites still pass, and the install suite has grown.
bash tests/test_guard.sh    | tail -1     # passed 76, failed 0
bash tests/test_redact.sh   | tail -1     # passed 66, failed 0 (62 at baseline,
                                          #   +4 from the backup-name pin)
bash tests/test_redact.sh --pwsh | tail -1  # passed 64, failed 0 (60 at baseline)
bash tests/test_safe_env.sh | tail -1     # passed  9, failed 0
bash tests/test_scan.sh     | tail -1     # passed 16, failed 0
bash tests/test_install.sh  | tail -1     # passed 43, failed 0 (14 at the
                                          #   baseline; +8 A5/A6/A8/A9/A10,
                                          #   +4 A2/A3, +4 A4, +1 the port,
                                          #   +5 A1/A7 matcher parity, +7 A11)
bash tests/test_parity.sh   | tail -1     # passed 15, failed 0
pwsh -NoProfile -File tests/test_ownership.ps1   # passed 8, failed 0
python3 -m py_compile lib/patch_config.py # no output, exit 0
shellcheck -S style install.sh uninstall.sh release.sh bin/* tools/* tests/*.sh
                                          # info-level only, as today
```

New groups that must appear in `tests/test_install.sh`, one per item:

| Item | The assertion |
|---|---|
| A2 | ✔ **closed 2026-09-16** — *--remove takes ours out and leaves theirs*, plus `tests/test_ownership.ps1` for the port |
| A3 | ✔ **closed 2026-09-16** — *install leaves a third-party hook and its arguments alone* |
| A4 | ✔ **closed 2026-09-16** — *a commented .jsonc is refused loudly and left untouched*, *a .jsonc with no comments in it is wired normally*, *three runs write the rules once*, *a missing configuration exits 3, not 1* |
| A5 | ✔ **closed 2026-09-16** — *a symlinked config stays a link and the target is wired* |
| A6 | ✔ **closed 2026-09-16** — *a 600 config is still 600 after a patch* |
| A7 | ✔ **closed 2026-09-16** — all three matchers and the timeout diffed against `lib/patch_config.py`, and the notice entry is written |
| A11 | ✔ **closed 2026-09-16** — *a run over an empty configuration finishes*, *three runs leave the same wiring*, and the four *wired …* assertions |
| A8 | ✔ **closed 2026-09-16** — *a config holding a list is refused with a sentence* (exit 1, no `Traceback`) |
| A9 | ✔ **closed 2026-09-16** — *config untouched*, *the leftover copy is not world-readable*, *the next run sweeps a stale temp file*. The original wording asked for no leftover at all; a SIGKILL cannot promise that, so the assertion is mode + sweep |
| A10 | ◐ **half closed 2026-09-16** — *two patchers at once both finish cleanly* and *the config a race leaves behind is readable and wired once*. Both edits surviving is still open: see D5 |
| — | ✔ **closed 2026-09-16** — Opencode: three runs, `394 → = already current → = already current` |
| — | ✔ **closed 2026-09-15** — `tests/test_redact.sh` lines 168–171 keep a backup name, the same with a path, an `ls -la` line carrying one, and `*.env2hell.tmp` byte for byte: `passed 66, failed 0` and `--pwsh passed 64, failed 0` |

And the two hand checks that close A1:

```bash
# 1 MB payload, the timeout the installer writes, through a sandbox HOME.
# Must print a non-zero stdout length — today it prints 0.
bash /tmp/<your-sandbox>/probe3.sh | sed -n '/size at which/,/^$/p'

# The number that is actually in the file.
rg -n '"timeout"' lib/patch_config.py install.ps1
```

---

**A: 11 — all closed (A10 half: the crash is gone, last-writer-wins remains,
see D5). B: 2 — both closed. C: 3 open. D: 5, one of them decided.**

File: `/home/env2hell/review-2026-09-15-patch_config.md`. Sandbox with every
probe script and payload: `/tmp/tmp.snGXbDrywJ` (nothing in it is deleted).

The fixes are a separate run against this file. This pass changed nothing.
