# env2hell

An assistant runs an ordinary command like `env` — and every key and token you
have is printed straight into the session, in plain text. Anyone with access to
that conversation can read them. And it does not go away: the session is saved
as a file on disk, indexed by memory tools, rolled into overnight digests. That
is how keys leak.

env2hell denies those commands and gives the assistant a safe replacement.
Works with Claude Code, Opencode and Codex, on Linux, macOS and Windows.

[Русская версия](README.RU.md)

## Why env2hell exists

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
| `secrets-redact` | Masks a secret a command printed, before the model reads it. |
| `safe-env` | Prints the environment with secret values masked. What the model uses instead. |

Plus a rule file (`rules/secrets-hygiene.md`) installed into each assistant, so
the model knows the replacement exists rather than fighting the block.

### What is denied

```
env                     printenv                export -p
set                     declare                 history
env | grep KEY          rtk env                 ls && env
cat .env                head ~/.bashrc          cat /proc/1/environ
cat prod.env            grep . ~/.aws/credentials
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

### What is masked after the fact

The guard reads the command, so it cannot know what the command will print. A
program handed a password prints that password back:

```
$ croc send report.pdf
On the other computer, run:
  croc --relay relay.example:9009 --pass <REDACTED:32> quiet-otter-lamp
```

`secrets-redact` replaced that value after `croc` had already printed it, and
before the model read the result. What it masks:

```
--pass VALUE            password=VALUE          TOKEN: VALUE
--token VALUE           api_key=VALUE           Authorization: Bearer VALUE
ghp_… glpat-… AKIA…     eyJ….eyJ….              https://user:pw@host
CREATE USER app IDENTIFIED BY 'VALUE'
```

What it deliberately leaves alone:

```
md5sum   deadbeefdeadbeefdeadbeefdeadbeef  report.pdf
commit   feedfacefeedfacefeedfacefeedfacefeedface
```

An md5 is 32 characters and so was that relay password. Length cannot tell them
apart, so the label decides: a high-entropy run is masked only when something on
the same line calls it a password, a token, a key or a secret. Masking bare hex
everywhere would redact every checksum and commit hash in the session.

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

No Python and no Git Bash needed — the guard, the redactor and `safe-env` all
have PowerShell ports, and the installer is PowerShell too. Until 2026-09-14
only the guard did, so a Windows install had a gate and no net: whatever a
program printed back reached the model untouched. The three ports are held to
the same test suites as the POSIX originals, with `--pwsh`.

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

## What has already leaked

The hooks stop a secret from reaching the model. They can do nothing about the
ones already on disk. A transcript is written as the session runs and is never
rewritten. A value that leaked before the hook covered that case is still
sitting in it. Rotation is the only fix, and rotation needs a list.

```bash
./tools/scan-transcripts                    # every store this machine has
./tools/scan-transcripts --quiet            # per-file counts, no excerpts
./tools/scan-transcripts --files            # names only, for a pipeline
./tools/scan-transcripts --path DIR         # somewhere of your own
./tools/scan-transcripts --include-stores   # auth.json and friends too
```

```
/root/.claude/projects/-wp/dc1cc19c…jsonl  — 16 line(s) with a credential
  /root/.claude/projects/-wp/dc1cc19c…jsonl:214: …url":"https<REDACTED:41>@gitlab…

scanned 454 file(s); 35 with findings, 381 line(s) in total
2 token store(s) skipped — auth.json and the like hold a
credential by design. --include-stores to scan them too.
```

It reads Claude Code, Codex, Opencode and rtk's tee logs. Three things about
it are deliberate:

- **it never prints the value.** Every excerpt is cut from the *masked* copy of
  the line, so the report shows `<REDACTED:41>` and its surroundings. A tool
  that reports a leak by repeating it has made a second one, into the
  transcript of whoever ran the scan.
- **detection is `secrets-redact --filter`**, the same code path the hook uses.
  A copy of the patterns here would drift within a release, and a scanner that
  disagrees with the guard reports clean on exactly the values the guard has
  just learned to catch.
- **an assistant's own token store is skipped.** `auth.json` holds a credential
  because that is its job; a standing entry in every report is how a report
  stops being read. The skip is counted, not hidden.

Exit status is the interface — `0` nothing found, `1` findings, `2` could not
run — so it fits a cron line or a CI step with no output parsing.

The tool stays in the checkout. It is not installed onto `PATH`, because it is
something you run when you have a reason to, not something the assistant calls.

## Verify

```bash
./tests/test_guard.sh          # the POSIX guard
./tests/test_redact.sh         # the redactor: patterns, result shapes, size
./tests/test_safe_env.sh       # safe-env
./tests/test_scan.sh           # the transcript scanner
./tests/test_install.sh        # the installer, run three times over

./tests/test_guard.sh    --pwsh   # the same cases against the PowerShell ports
./tests/test_redact.sh   --pwsh
./tests/test_safe_env.sh --pwsh
```

All report `failed 0`.

Run the `--pwsh` half whenever either side changes. Two implementations of one
rule drift in silence otherwise. `secrets-guard.ps1` lost the
command-substitution pass the POSIX guard had and denied a working command.
Nothing ran to notice until the suite was pointed at it.

## Uninstall

```bash
./uninstall.sh                 # unwire every assistant, remove both commands
./uninstall.sh --dry-run
./uninstall.sh --keep-bin      # unwire only, leave the commands on PATH
```

Backups made at install time are left in place: they hold whatever your
configuration looked like before, and removing them here would defeat the
purpose of having made them.

## How env2hell is wired into an assistant

| Assistant | Mechanism |
|---|---|
| Claude Code | `PreToolUse` hook, matcher `Bash`, in `settings.json` |
| Claude Code | `PostToolUse` hook, matcher `Bash\|Read\|Grep`, in `settings.json` — the redactor |
| Windows | the same two hooks, registered with `"shell": "powershell"` and pointing at the `.ps1` ports |
| Codex | `PreToolUse` hook, matcher `^Bash$`, in `hooks.json` |
| Codex | `PostToolUse` hook, matcher `^Bash$` — the redactor, warning only |
| Opencode | `permission.bash` deny rules **and** a `tool.execute.before` plugin |
| Opencode | a `tool.execute.after` plugin — the redactor |

Opencode needs both layers. `permission.bash` matches on a command prefix, so
on its own it never sees `env | grep X`, `rtk env` or `a && env`. The plugin
runs the real policy by calling the same `secrets-guard`, so there is one
source of truth rather than two that drift.

**The two matchers differ on purpose.** The guard inspects a command line
before it runs, which has no meaning for a tool that is not a shell. The
redactor inspects a result, and a result carrying a credential need not have
come from a shell at all: `Read` on a `.env`, an `id_rsa` or a kubeconfig hands
the file over verbatim, and `Grep` returns the matching lines. Reading a secret
needs no shell, so for a while the most direct route to one was the only route
left uncovered.

`secrets-redact` reaches Claude Code and Opencode by different routes. Claude
Code replaces the result through `hookSpecificOutput.updatedToolOutput`;
Opencode hands a plugin a mutable `output`, so the masked string is written back
in place. Both call the same CLI, in `--filter` mode for the plugin.

**Codex cannot replace a result, and the reason is in its source.**
`PostToolUseOutcome` (`codex-rs/hooks/src/events/post_tool_use.rs`) carries
`should_block`, `additional_contexts` and `feedback_message` — and nothing that
replaces the output. So there the hook does the one thing left: it says a
credential is now in the transcript, through `additionalContext`.

```
[secrets-redact] This output contains 1 credential-shaped value(s). Hooks in
this assistant cannot remove it, so it is already in the transcript. Do not
repeat it, do not echo the command that produced it, and tell the user the
value has to be rotated.
```

The warning names no value and no command. Repeating either would put a second
copy in the transcript the warning is about. It does not undo the leak — it
turns a silent one into a rotation, which is the difference between finding out
now and finding out never.

## Documentation

- [How env2hell works](docs/design.en.md) — the two passes, and why each exists
- [Installation in detail](docs/install.en.md) — per assistant, Windows, troubleshooting
- [What counts as a secret](docs/patterns.en.md) — the mask list, and how to extend it

## Limits

- The guard sees a command **before** it runs, so it cannot know what the
  command will print. `secrets-redact` covers that case, but only afterwards:
  the command has already executed, and the telemetry the assistant sends
  records the original output. What the model reads is masked; what the vendor
  logged is not.
- **A command that fails is not masked at all, and cannot be.** In Claude Code a
  non-zero exit does not fire `PostToolUse`; it fires `PostToolUseFailure`,
  whose only documented return field is `additionalContext`. There is no slot
  for a replacement, so the output reaches the model and the transcript intact.
  env2hell wires a `--warn-only` hook there. It tells the model a credential
  just landed in the transcript and has to be rotated. A loud leak instead of a
  silent one — all that event allows.

  This is not a corner case. A failing command is where credentials surface: a
  URL carrying a password, an auth error quoting the token, a connection string
  in a stack trace. It is how the GitLab token that prompted this section
  reached a transcript in full, from a `git remote -v` that exited 1 because a
  later command in the same call failed. That class closes one way: keep the
  credential out of the command's output. A deploy key or a credential helper
  instead of a token written into a remote URL.
- The redactor needs a label. An unlabelled secret that looks like ordinary text
  — a passphrase of three English words, say — passes through untouched.
- It is a filter, not a sandbox. It raises the cost of the common accident; it
  is not a defence against someone deliberately extracting a value.
- A key already in the environment stays there. Assistants snapshot their
  environment at start-up, so removing a variable from `.bashrc` does not
  remove it from a running session — see [design](docs/design.en.md).

## Sending a change

Commit messages are written in English, body included. The history is the only
place the reason for a change survives, and whoever can read the code can read
the message.

Ten messages from 2026-09-18 were Russian and were rewritten in English on
2026-09-19. Three older ones quote Russian documentation and keep the
quotations, because there the Russian is the subject.

The documentation itself is bilingual and stays that way: `README.md` and
`README.RU.md`, `docs/*.en.md` and `docs/*.ru.md`, edited as pairs.

**A pattern is not added without a test naming the shape, and the shapes that
must not fire are tested too.** The SQL clause in 0.8.5 is the case that shows
why: `safe-env` had carried that rule since the first commit while the redactor
beside it had not, and nothing was going to notice — two implementations of one
policy drift in silence, which is also why `tools/scan-transcripts` calls
`secrets-redact --filter` instead of holding patterns of its own.

## Licence

MIT. See [LICENSE](LICENSE).
