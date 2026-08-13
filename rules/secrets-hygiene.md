# Secrets hygiene — never print an environment dump

A shell command that prints the whole environment puts every API key in the
session transcript verbatim. The transcript persists (CC `.jsonl`, memsearch
digests, qdrant), so one careless `env` costs a rotation of every key on the
box. This happened: `env | rg -i 'anthropic|model|api'` leaked five tokens at
once, because `rg` filters *lines*, and a line is `NAME=value`.

## Read the environment by name, never by dump

```bash
safe-env                      # whole environment, secret values masked
safe-env | grep MODEL         # filter it — values are already masked
echo "$ANTHROPIC_MODEL"       # one variable, when you know the name
printenv PATH                 # one variable, explicit
```

Never: bare `env`, `printenv`, `export -p`, bare `set`, bare `declare`,
`history`, or `cat` of `~/.bashrc` / `.env` / `*.pem` / `/proc/*/environ`.

`env VAR=value some-command` is fine — that *sets* a variable for one command,
it does not dump anything.

## The guard is mechanical, not a matter of memory

`secrets-guard` (`~/.local/bin/secrets-guard`) denies the dump commands before
they run, in all three IDEs:

| IDE | Wiring |
|-----|--------|
| Claude Code | `PreToolUse` hook, matcher `Bash`, in `settings.json` |
| Codex | `PreToolUse` hook, matcher `^Bash$`, in `~/.codex/hooks.json` |
| Opencode | `permission.bash` deny rules + `plugins/secrets-guard.ts` (`tool.execute.before`) |

Opencode needs both layers: `permission.bash` matches on a command prefix, so
it alone would miss `env | grep X`, `rtk env`, and `a && env`. The plugin
delegates to the same CLI, so the policy has one source of truth.

`safe-env` (`~/.local/bin/safe-env`) masks AWS, GitHub (classic + fine-grained),
GitLab, Slack, Google, Stripe, OpenAI-family, Atlassian, Tavily, JWTs, private
key blocks and URL-embedded passwords, plus generic high-entropy fallbacks
(32+ hex, `key.signature`, 40+ character runs) that catch un-prefixed tokens.

## When a key does leak

Rotate it. Do not reason about who might have seen it — the transcript is on
disk and may already be in a digest. Grep the memory stores for the prefix to
learn the blast radius, then rotate regardless of what the grep says.

## Keys arrive from the parent shell, not only from dotfiles

Claude Code snapshots its environment at startup, so a key exported in the
shell that launched it stays in every Bash call for the life of the session —
even after it is removed from `.bashrc`. Verified via `/proc/<pid>/environ` of
the parent. To actually clear one: exit, start a clean login shell, confirm the
variable is gone, then relaunch.
