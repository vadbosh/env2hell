# Changelog

## 0.1.0 — 2026-08-13

First release. Everything here came out of one incident and the session that
followed it, so the entries are written as what was learned rather than as a
feature list.

### Added

- `bin/secrets-guard` — denies commands that would print the environment or
  read a file holding credentials. Two passes: dump commands on quote-stripped
  text, secret-file reads on the raw text.
- `bin/safe-env` — prints the environment with credential-shaped values
  replaced by `<REDACTED:length>`.
- PowerShell ports of both, for Windows machines with neither Git Bash nor WSL.
- `install.sh` / `install.ps1` — wire Claude Code, Codex and Opencode; back up
  every file before changing it; idempotent on re-run.
- `uninstall.sh` — reverses all of it, keeping the backups.
- `lib/patch_config.py` — the JSON editing, kept in one place so the three
  assistants cannot drift apart.
- `plugins/opencode/secrets-guard.ts` — `tool.execute.before` plugin that
  delegates to the same guard binary.
- `rules/secrets-hygiene.md` — installed into each assistant so the model knows
  what to use instead of the blocked command.
- `tests/test_guard.sh` — 47 cases, runnable against either port.

### Fixed during development

Each of these was a real defect, caught by the guard blocking work it should
not have:

- **Words inside quotes were read as commands.** A `jq` filter containing
  `test("^(env|printenv|set)")` was split on `|` into the bare words `printenv`
  and `set`, and the guard blocked the command that was editing its own
  configuration. Quoted regions are now stripped before the split.
- **`.env` matched inside an identifier.** `jq -r '.permission.bash.env' … |
  head` was denied because `bash.env` contains `.env` and `head` is a reader.
  The pattern now requires a boundary to the left.
- **A `key.signature` token printed in full.** A value shaped
  `<32 hex>.<16 chars>` matched none of the length-based fallbacks, because the
  dot broke every run. Added as its own pattern.
- **GitLab tokens were masked only by accident.** `glpat-` was absent from the
  list; a long suffix happened to trigger a generic rule. Now explicit.
- **Prose was read as a command.** A commit message mentioning `cat .env` was
  denied, because pass B looked for the reading command in the raw text, where
  words inside a quoted argument are indistinguishable from a command. The
  reader is now looked for in the quote-stripped text, and only the path in the
  raw one.

### Known limits

- The guard inspects commands, not their output.
- It is a filter, not a sandbox.
- A key already in a running assistant's environment stays there until the
  assistant is restarted from a clean shell.
