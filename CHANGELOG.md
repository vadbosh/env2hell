# Changelog

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
