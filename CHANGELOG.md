# Changelog

## 0.5.1 — 2026-08-22

### Fixed

- **Opencode was silently getting half an installation.** `patch_config.py`
  hardcoded `~/.config/opencode/opencode.json`, and Opencode accepts more than
  one filename — its own startup log shows it trying `opencode.json` and then
  `opencode.jsonc`. On a machine using the second spelling the installer wrote
  the plugin, printed `config not found: …/opencode.json`, and moved on. The
  `permission.bash` deny rules — the layer that works before a plugin is even
  loaded — were never installed, and the line announcing it reads like a note
  rather than a failure.

  The path is now resolved the way Opencode resolves it: first filename that
  exists, and the first of the pair when neither does. On the machine this was
  found on, wiring it afterwards wrote 394 permission rules that had been
  missing since the first install.

## 0.5.0 — 2026-08-22

### Added

- **Codex gets `secrets-redact` after all, as a warning.** 0.4.0 filed Codex
  under "cannot", which was true about redaction and wrong as a conclusion:
  `install.sh` was putting the command on PATH and then wiring nothing, so the
  one assistant that could not mask a secret also said nothing about one.

  `PostToolUseOutcome` still has no field that replaces output. What it does
  have is `additional_contexts`, so `--warn-only` uses it:

  ```
  [secrets-redact] This output contains 1 credential-shaped value(s). Hooks in
  this assistant cannot remove it, so it is already in the transcript. Do not
  repeat it, do not echo the command that produced it, and tell the user the
  value has to be rotated.
  ```

  No value, no command — either would put a second copy in the transcript the
  warning is about. This is not redaction and the flag name says so; what it
  buys is that the leak stops being silent, which is what starts a rotation.

  The mode also reads `tool_response.output`, the field Codex uses for a shell
  result. Claude Code splits the same thing into `stdout` and `stderr`, and the
  redaction path had only ever looked at those two — against a Codex payload it
  would have found nothing to examine.

### Changed

- `lib/patch_config.py` picks the mode per assistant rather than skipping the
  ones it cannot fully serve: `REDACT_IDES` replaces the result, `WARN_IDES`
  reports it.
- Four more cases in `tests/test_redact.sh` (28 total), including one that
  fails if the warning ever contains the value it is warning about, and one
  that fails if `--warn-only` emits `updatedToolOutput` — a field Codex
  ignores, which would make the mode look like protection it is not.

## 0.4.0 — 2026-08-22

### Added

- **`secrets-redact` now covers Opencode too**, through a `tool.execute.after`
  plugin. Opencode hands a plugin a mutable `output`, so the masked string is
  written back in place — a different mechanism from Claude Code's
  `updatedToolOutput`, same policy underneath.

- **`secrets-redact --filter`** — plain text in, masked text out, exit 0 when
  something changed and 1 when nothing did. This is what the plugin calls:
  wrapping a string in the Claude Code payload shape only to unwrap it again
  would be ceremony, and this mode needs no `jq`. It is also the mode to reach
  for by hand, in a pipe.

### Not added, and why

- **Codex cannot redact output, and this is settled rather than assumed.** Its
  `PostToolUseOutcome` (`codex-rs/hooks/src/events/post_tool_use.rs`) carries
  `should_block`, `additional_contexts` and `feedback_message` — nothing that
  replaces a result. A hook there could tell the model that the output it has
  already read contained a password, which is not redaction but a second copy
  of the problem. Codex keeps `secrets-guard`, the half that works there.

  The 0.3.0 notes said no *verified* equivalent existed. It is verified now, in
  both directions: Opencode can, Codex cannot.

### Changed

- `install.sh` installs the second Opencode plugin; `uninstall.sh` removes it.
- Five more cases in `tests/test_redact.sh` (24 total): `--filter` in both
  directions, `--filter` without `jq`, and two that hold the plugin to
  delegating rather than growing its own copy of the pattern list.

## 0.3.0 — 2026-08-22

### Added

- **`secrets-redact` — the output half of the pair.** `secrets-guard` reads a
  command before it runs, so it cannot know what the command will print. A
  program handed a password prints that password back:

  ```
  $ croc send report.pdf
  On the other computer, run:
    croc --relay relay.example:9009 --pass deadbeefdeadbeefdeadbeefdeadbeef quiet-otter-lamp
  ```

  Nothing in that command line says a secret is coming. The new hook runs on
  `PostToolUse` and replaces the result through
  `hookSpecificOutput.updatedToolOutput`, so the masked text is what reaches
  the model.

  Two tiers. Provider shapes (`ghp_`, `glpat-`, `AKIA`, JWT, private key
  headers, credentials in a URL) are masked anywhere — that list is
  character-for-character the one in `safe-env`, and `tests/test_redact.sh`
  diffs the two files so they cannot drift apart unnoticed. A high-entropy run
  with no recognisable prefix is masked only when a label on the same line
  calls it a secret: `--pass`, `--token`, `password=`, `Authorization: Bearer`.

  The label is not decoration. The password this was written for was 32 hex
  characters, exactly like every md5sum in the session; masking bare hex would
  redact every checksum and commit hash the model needs. Both directions are
  asserted in the tests.

  Wired for Claude Code only. Replacing a result after the fact needs
  `updatedToolOutput`, and no verified equivalent exists in the Codex or
  Opencode hook contracts. A hook whose output is ignored reads as protection
  that is not there.

  It fails open on the same reasoning as the guard: no `jq`, unparsable input,
  or a tool result carrying no `stdout`/`stderr` all mean exit 0 with no
  output.

### Changed

- `install.sh` puts three commands on PATH instead of two, and verifies the
  redactor in both directions — a labelled password masked, a bare checksum
  left alone. `uninstall.sh` removes it.
- The "Limits" section of both READMEs no longer says output is out of reach.
  It now says what is actually true: output is covered, but only after the
  command has run, only for labelled values, and the assistant's telemetry
  still records the original.

## 0.2.1 — 2026-08-20

### Fixed

- **A key handed to `ssh` was read as a file being read.** Pass B looked for a
  reader anywhere in the command and a secret path anywhere in the command,
  without requiring the two to be in the same place. So

  ```
  rsync -e "ssh -i ~/.ssh/id.pem" host:/src /dst | head -5
  ```

  was denied: `.pem` is the identity ssh authenticates with, `head` reads
  rsync's output, and neither reads a key. Both passes now split the command
  and require the reader and the path to land in the **same sub-command**.
  Every real case already satisfies that — `cat .env`, `cat .env | grep X`,
  `ls && cat .env` all carry both halves in one piece — so nothing that was
  denied before is allowed now. Four cases were added proving the ssh forms
  pass, and four more proving a genuine read in any sub-command is still
  denied, including when it sits next to one of those ssh commands.

  The split is quote-aware and runs on the raw text: the path is what is being
  matched, quote-stripping would erase a quoted one, and a separator inside
  quotes is not a separator — a quoted `jq` program holding `;` or `|` stays
  whole.

- **The PowerShell port had the same bug and now has the same fix**, verified
  by running the suite against it — `./tests/test_guard.sh --pwsh`, 55 of 55.
  Both ports are tested here for the first time; before this the port was
  shipped on inspection alone.

## 0.2.0 — 2026-08-20

The release that found out `safe-env` had been printing nothing. Restoring this
machine from a backup is what surfaced it, and neither the tool nor its tests
would have said a word.

### Fixed

- **`safe-env` called `env` through PATH, and got the wrong one.** The uv
  installer writes a file of its own named `env` into `~/.local/bin` — a
  PATH-setup snippet meant to be sourced, not run. With `~/.local/bin` first on
  PATH, `safe-env` executed that instead: it set a variable, printed nothing and
  exited 0. So the sanctioned replacement for a bare `env` returned an empty
  environment, and an empty answer here reads like "nothing is set" rather than
  "this is broken". Now `/usr/bin/env` by absolute path, with `/bin/env` as the
  fallback and a real error if neither exists.

### Added

- **`tests/test_safe_env.sh`.** The bug above was silent because nothing
  asserted that the output was non-empty. Five cases: the environment comes
  back at all, a planted `ghp_` token is masked, the masked variable is still
  named, a plain value is untouched, and an unprefixed hex run is masked anyway.
  Verified against the broken copy — 4 of the 5 fail there.

### Changed

- **`release.sh`** checks the changelog, the tag and the installed copies
  against each other, so a mirror that drifted from this checkout is reported
  instead of being discovered later.
- **Work notes are kept out of the published tree.**
- **The Windows path case in the guard tests is marked as intentional shell
  text**, so it stops reading like an escaping mistake.

## 0.1.0 — 2026-08-13

First release. Everything here came out of one incident and the session that
followed it, so the entries are written as what was learned rather than as a
feature list.

### Added

- `bin/secrets-guard` — denies commands that would print the environment or
  read a file holding credentials. Two passes: dump commands are looked for in
  the quote-stripped text, and a secret-file read needs a reader there plus a
  path in the raw text.
- `bin/safe-env` — prints the environment with credential-shaped values
  replaced by `<REDACTED:length>`.
- PowerShell ports of both, for Windows machines with neither Git Bash nor WSL.
  The credential stores are covered in their Windows spelling too: `_netrc`,
  the PowerShell profile, and every path with either separator.
- `install.sh` / `install.ps1` — wire Claude Code, Codex and Opencode; back up
  every file before changing it; idempotent on re-run.
- `uninstall.sh` — reverses all of it, keeping the backups.
- `lib/patch_config.py` — the JSON editing, kept in one place so the three
  assistants cannot drift apart.
- `plugins/opencode/secrets-guard.ts` — `tool.execute.before` plugin that
  delegates to the same guard binary.
- `rules/secrets-hygiene.md` — installed into each assistant so the model knows
  what to use instead of the blocked command, and registered where the assistant
  needs the file listed rather than merely present.
- `tests/test_guard.sh` — 47 cases, runnable against either port.

### Fixed during development

Most of these are defects the guard found in itself, by blocking work it should
not have. The last two were found by a reader asking what a sentence meant.

- **Words inside quotes were read as commands.** A `jq` filter containing
  `test("^(env|printenv|set)")` was split on `|` into the bare words `printenv`
  and `set`, and the guard blocked the command that was editing its own
  configuration. Quoted regions are now stripped before the split.
- **`.env` matched inside an identifier.** `jq -r '.permission.bash.env' … |
  head` was denied because `bash.env` contains `.env` and `head` is a reader.
  The pattern now requires a boundary to the left.
- **Prose was read as a command.** A commit message mentioning `cat .env` was
  denied, because pass B looked for the reading command in the raw text, where
  words inside a quoted argument are indistinguishable from a command. The
  reader is now looked for in the quote-stripped text, and only the path in the
  raw one.
- **A `key.signature` token printed in full.** A value shaped
  `<32 hex>.<16 chars>` matched none of the length-based fallbacks, because the
  dot broke every run. Added as its own pattern.
- **GitLab tokens were masked only by accident.** `glpat-` was absent from the
  list; a long suffix happened to trigger a generic rule. Now explicit.
- **The list of secret files was POSIX by assumption.** Three cloud stores
  accepted a backslash; everything else did not. `.netrc` was listed under the
  name it does not have on Windows, and the PowerShell profile — where a Windows
  user writes `$env:API_KEY = "..."`, exactly what `.bashrc` is used for
  elsewhere — was absent. Added, along with `.git-credentials`, `.npmrc`,
  `.pypirc`, `.pgpass`, `.my.cnf`, `.azure/` and `id_ecdsa`.
- **Opencode never read the rule file.** It reads an instruction file only when
  the file is listed in its `instructions` array; the installer copied the file
  and stopped. On an Opencode-only machine the rule was present, looked
  installed, and did nothing. Claude Code and Codex read their directories, so
  those two hid the problem.

### Documentation

- The opening example was a session asking which model was running — the
  situation this repository came out of, and one most developers never meet. It
  is now an app returning 401, where the assistant checks whether the key is set
  and the check prints the key.
- The demonstration of a too-wide match was an `awk` program containing the word
  `env` in a regular expression. Replaced with four commands people actually
  type, `source env/bin/activate` among them; all four are now test cases.
- The Russian version called the tool «запрет», the word for the act of
  forbidding rather than for a thing. Sentences about the program now name
  `secrets-guard`; the word stays where the sentence is about the act.
- A sample in `docs/patterns` was derived from a token pasted during
  development. Replaced with a synthetic one before the repository was
  published, and the mask length in the example corrected to the measured value.

### Known limits

- The guard inspects commands, not their output.
- It is a filter, not a sandbox.
- A key already in a running assistant's environment stays there until the
  assistant is restarted from a clean shell.
- `/proc/N/environ` is matched on Linux, where it exists; there is no equivalent
  to match on Windows or macOS.
