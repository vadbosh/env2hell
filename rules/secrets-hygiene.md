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
echo "$ANTHROPIC_MODEL"       # one variable, when the NAME is not a credential
printenv PATH                 # one variable, explicit
```

Never: bare `env`, `printenv`, `export -p`, bare `set`, bare `declare`,
`history`, or `cat` of `~/.bashrc` / `.env` / `*.pem` / `/proc/*/environ`.

**And never print a variable whose name says "credential"** — `echo
"$HW_SECRET_KEY"`, `printf '%s' "$GITHUB_TOKEN"`. This is denied too, and the
reason differs from the dump case. The value arrives alone on its line with no
label beside it, so redaction has nothing to work with: its labelled tier needs
a name on the same line, and its provider tier needs a recognisable prefix. A
Huawei access key is 20 characters of uppercase and digits, its secret 40 of
base62 — shapes that equally describe a git SHA or a build identifier, so no
pattern can take them without masking half of ordinary output. Shape cannot
decide it. The name can, which is why the refusal happens here rather than
after the fact.

To check whether such a variable is set, ask without printing it:

```bash
safe-env | grep HW_SECRET_KEY   # shows the name, masks the value
```

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
