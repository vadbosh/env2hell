# Installation in detail

## What the installer touches

Nothing outside your home directory. Concretely:

| Path | What happens |
|---|---|
| `~/.local/bin/secrets-guard` | the policy, copied |
| `~/.local/bin/safe-env` | the masking command, copied |
| `~/.claude/settings.json` | one `PreToolUse` entry added |
| `~/.codex/hooks.json` | one `PreToolUse` entry added |
| `~/.config/opencode/opencode.json` | plugin registered, permission rules written |
| `~/.config/opencode/plugins/secrets-guard.ts` | plugin, copied |
| `~/.claude/rules/`, `~/.config/opencode/instructions/`, `~/.codex/memories/` | the rule file |

Only assistants that already exist are written to. Creating a configuration
tree for an assistant you do not use would just litter your home directory.

Every file about to change is copied to `<file>.bak.<timestamp>` first. Running
the installer twice is a no-op: content that already matches is skipped, so you
do not accumulate identical backups.

## Choosing what gets installed

```bash
./install.sh --dry-run          # print the plan, change nothing
./install.sh --ide opencode     # one assistant
./install.sh --bin-dir ~/bin    # put the two commands somewhere else
./install.sh --no-rule          # wire the guard, skip the documentation rule
```

`--dry-run` is worth running first on a machine whose configuration you care
about. It prints the same lines the real run would, prefixed with `would`.

## Per assistant

### Claude Code

The entry added to `settings.json`:

```json
{
  "matcher": "Bash",
  "hooks": [{
    "type": "command",
    "command": "/home/you/.local/bin/secrets-guard",
    "timeout": 5,
    "statusMessage": "secrets-guard..."
  }]
}
```

A hook that exits 2 denies the call and hands its stderr to the model as
feedback. Any other exit code lets the command through.

Order matters only in that all `Bash` hooks run; if you already have a
destructive-command guard, the two are independent.

### Codex

Same shape, in `~/.codex/hooks.json`, with the matcher written as a regular
expression (`^Bash$`). Do not hand-edit `[hooks.state]` in `config.toml` — that
section is a cache Codex maintains itself.

### Opencode

Two layers, and both are needed:

1. **`permission.bash`** — declarative rules in `opencode.json`. Cheap, applied
   before anything loads. Matches on a command prefix, so it catches `env` but
   not `env | grep KEY`.
2. **`plugins/secrets-guard.ts`** — a `tool.execute.before` plugin that calls
   the same `secrets-guard` binary. This is where pipes, wrappers and compound
   commands are caught.

The installer also **overwrites** any existing `"env": "allow"` rule. That
combination — an explicit allow for a dump command — is the hole this tool
exists to close, and it is common in hand-tuned permission lists.

If `secrets-guard` is not on `PATH`, the plugin prints a warning and disables
itself rather than blocking everything. Check with `which secrets-guard`.

## Windows

The PowerShell installer needs neither Python nor Git Bash. It writes the same
configuration, with one difference: the hook is registered with
`"shell": "powershell"` and points at `secrets-guard.ps1`.

```powershell
.\install.ps1
.\install.ps1 -DryRun
.\install.ps1 -Ide codex
.\install.ps1 -BinDir "C:\tools\env2hell"
```

Commands go to `%LOCALAPPDATA%\Programs\env2hell` by default.

### If the script will not run

PowerShell refuses unsigned scripts under its default execution policy. Run the
installer through an explicit bypass, which applies to that one invocation and
changes no machine setting:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

If you would rather allow local scripts generally, that is a per-user setting:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### If you have Git Bash or WSL

Then the POSIX version works as well, and it is the better choice: one guard,
one behaviour, one set of test results. Install it from inside that shell with
`./install.sh`.

## Restart the assistant

Hooks, plugins and permission rules are read once, when the assistant starts.
Until you restart it, the guard is installed but nothing is enforced. This is
the single most common reason for "I installed it and it does nothing".

## Verifying the install

The installer ends with a check of its own: it feeds `env` and `echo hi` to the
guard and expects exit 2 and exit 0. To go further:

```bash
./tests/test_guard.sh                       # 36 cases, the POSIX guard
./tests/test_guard.sh --pwsh                # the same 36, the PowerShell port
./tests/test_guard.sh --guard ~/.local/bin/secrets-guard   # the installed copy
```

To see it work inside the assistant, ask it to run `env`. It should come back
with the denial message rather than a wall of variables.

## Troubleshooting

**Nothing is blocked.** The assistant was not restarted. If it was, check that
the hook is actually registered:

```bash
jq '.hooks.PreToolUse' ~/.claude/settings.json
jq '.plugin, .permission.bash.env' ~/.config/opencode/opencode.json
```

**Everything is blocked, including ordinary commands.** Run the test suite. If
it passes, the guard is behaving as designed and the command genuinely matches
— the message on stderr names which pass caught it. If a case is wrong, it
belongs in `tests/test_guard.sh` as a failing case before it is fixed.

**The installer says the configuration is not valid JSON.** It refuses to write
in that case, and touches nothing. Fix the file (a trailing comma is the usual
cause) and run it again.

**`secrets-guard` is not on PATH.** Add the directory to `PATH`, or reinstall
with `--bin-dir` pointing somewhere already on it. The assistants' hooks use an
absolute path and keep working either way; only the opencode plugin and manual
use need `PATH`.

## Removing it

```bash
./uninstall.sh --dry-run
./uninstall.sh
```

The hook entries, the plugin, the permission rules and the rule file are
removed. Backups are deliberately left behind — they are the only record of
what the configuration held before.
