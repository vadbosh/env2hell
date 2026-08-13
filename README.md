# env2hell

An assistant runs an ordinary command like `env` — and every key and token you
have is printed straight into the session, in plain text. Anyone with access to
that conversation can read them. And it does not go away: the session is saved
as a file on disk, indexed by memory tools, rolled into overnight digests. That
is how keys leak.

env2hell denies those commands and gives the assistant a safe replacement.
Works with Claude Code, Opencode and Codex, on Linux, macOS and Windows.

[Русская версия](README.RU.md)

## Why

An app fails with an authorisation error. The developer asks the assistant to
work out why the 401. It starts with the sensible thing — checking whether the
key is set at all:

```bash
env | grep -i api
```

The check was right. But `grep` filters *lines*, and a line is `NAME=value`, so
along with the answer "yes, it is set" the value itself is printed into the
session. `cat .env` while looking at configuration ends the same way, and so
does a plain `env` when comparing a local run against CI.

From there the line has a life of its own: the session is saved as a file on
disk (Claude Code writes `.jsonl`), memory tools index it, digests are written
overnight. One command like that costs a rotation of every key on the machine.

This is not hypothetical. It is where this repository came from: five tokens
(Z.ai, DeepSeek, OpenRouter, Tavily, plus the assistant's own auth token)
printed in full by a single command, in a session whose whole purpose was to
name a model version.

Telling the model "don't do that" does not hold. Instructions are advice; this
is a gate.

## What you get

| Command | Purpose |
|---|---|
| `secrets-guard` | Denies a command before it runs. Assistants call it automatically. |
| `safe-env` | Prints the environment with secret values masked. What the model uses instead. |

Plus a rule file (`rules/secrets-hygiene.md`) installed into each assistant, so
the model knows the replacement exists rather than fighting the block.

### What is denied

```
env                     printenv                export -p
set                     declare                 history
env | grep KEY          rtk env                 ls && env
cat .env                head ~/.bashrc          cat /proc/1/environ
cat ~/.ssh/id_rsa       head ~/.aws/credentials
```

### What still works

```
safe-env                        # every variable, secret values masked
safe-env | grep MODEL           # filter it — the values are already masked
echo "$ANTHROPIC_MODEL"         # one variable, by name
printenv PATH                   # one variable, explicit
env VAR=value some-command      # sets a variable, dumps nothing
source env/bin/activate         # here `env` is a directory name, not a command
git commit -m "fix env parsing" # and here it is just a word in some text
```

Those last two lines matter more than they look. A guard that cannot tell `env`
the command from the same word in a directory name or a commit message blocks
your ordinary work on day one, and then you switch it off.

## Install

### Linux and macOS

```bash
git clone <this-repo> env2hell && cd env2hell
./install.sh                 # every assistant found
./install.sh --dry-run       # print what would happen, change nothing
./install.sh --ide claude    # one assistant only
```

Requires Python 3.8+ (the assistants' configuration files are JSON).

### Windows

No Python and no Git Bash needed — the guard has a PowerShell port and the
installer is PowerShell too.

```powershell
.\install.ps1
.\install.ps1 -DryRun
.\install.ps1 -Ide claude
```

If the file will not run, PowerShell's execution policy is blocking it:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

**Restart the assistant afterwards.** Hooks and plugins are read once, at
start-up; until then nothing is enforced.

## Usage

Nothing to run by hand. The assistant calls the guard before every shell
command; a denied call returns a message telling the model what to use instead:

```
[secrets-guard] Blocked: bare env/printenv/export/set/declare leaks secrets to
the session. Use `safe-env` (values masked), or `echo "$VAR"` for one value.
```

Run `safe-env` yourself whenever you want to see the environment without
putting it in a log:

```
$ safe-env | grep -E 'TOKEN|MODEL'
ANTHROPIC_MODEL=glm-5.2
GITHUB_PERSONAL_ACCESS_TOKEN=<REDACTED:93>
TAVILY_API_KEY=<REDACTED:57>
```

The length is kept because it distinguishes two different keys and reveals
nothing usable.

## Verify

```bash
./tests/test_guard.sh          # 40 cases against the POSIX guard
./tests/test_guard.sh --pwsh   # the same 40 against the PowerShell port
```

Both report `passed 40, failed 0`.

## Uninstall

```bash
./uninstall.sh                 # unwire every assistant, remove both commands
./uninstall.sh --dry-run
./uninstall.sh --keep-bin      # unwire only, leave the commands on PATH
```

Backups made at install time are left in place: they hold whatever your
configuration looked like before, and removing them here would defeat the
purpose of having made them.

## How it is wired

| Assistant | Mechanism |
|---|---|
| Claude Code | `PreToolUse` hook, matcher `Bash`, in `settings.json` |
| Codex | `PreToolUse` hook, matcher `^Bash$`, in `hooks.json` |
| Opencode | `permission.bash` deny rules **and** a `tool.execute.before` plugin |

Opencode needs both layers. `permission.bash` matches on a command prefix, so
on its own it never sees `env | grep X`, `rtk env` or `a && env`. The plugin
runs the real policy by calling the same `secrets-guard`, so there is one
source of truth rather than two that drift.

## Documentation

- [How it works](docs/design.en.md) — the two passes, and why each exists
- [Installation in detail](docs/install.en.md) — per assistant, Windows, troubleshooting
- [What counts as a secret](docs/patterns.en.md) — the mask list, and how to extend it

## Limits

- The guard sees a command **before** it runs. It does not read output, so a
  program that prints a key on its own is not covered.
- It is a filter, not a sandbox. It raises the cost of the common accident; it
  is not a defence against someone deliberately extracting a value.
- A key already in the environment stays there. Assistants snapshot their
  environment at start-up, so removing a variable from `.bashrc` does not
  remove it from a running session — see [design](docs/design.en.md).

## Licence

MIT. See [LICENSE](LICENSE).
