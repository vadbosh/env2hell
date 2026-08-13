# How it works

## The shape of the problem

A hook sees one thing: the command string, before it runs. It has to answer a
single question — would running this print a credential? — and it has to answer
it without a shell parser. And answer it quickly: it runs before every command,
so whatever it takes is added to every command the assistant issues.

Two obvious approaches both fail:

**Too narrow — match the start of the string.** The check then sees only the
first word. It catches `env`, but not `rtk env`, which starts with `rtk`, and
not `ls && env`, where `env` comes second.

**Too wide — match the word anywhere in the string.** Both of those are caught
now. So is ordinary work, because the word `env` turns up in commands all the
time:

```bash
source env/bin/activate          # a Python virtualenv in a directory named env
python -m venv env               # creating it
git commit -m "fix env parsing"  # the word in a commit message
grep -rn "env" src/              # searching the code
```

In none of them is `env` the command: it is a directory name, a word in a
message, a search string. A developer who is refused permission to activate a
virtualenv will switch the guard off the same day.

So the guard runs two passes over the same string, each looking at a different
version of it.

## Pass A — commands that dump the environment

The text is first stripped of quoted regions:

```
jq -r '.a | select(.k|test("^(env|set)"))' f.json
    ↓ single- and double-quoted spans replaced by Q
jq -r Q f.json
```

Only then is it split on shell separators (`|`, `||`, `&&`, `;`, `&`), and the
first word of each piece is examined. A word inside a quoted program is gone by
that point, so it cannot be mistaken for a command.

This split is not theoretical. Before it existed, `secrets-guard` blocked the very
command that was editing its own configuration, because a `jq` filter contained
`test("^(env|printenv|set)")` — split on `|`, that yields the bare words
`printenv` and `set`.

Wrappers are stepped over before the name is read, so `sudo env`, `rtk env` and
`time env` are all recognised:

```
sudo rtk env    →  skip sudo, skip rtk, examine env
```

A fragment that does not look like a command name at all — one starting with
`"`, `=`, `{`, `[`, `$` or `*` — is skipped rather than guessed at.

### Where the line is drawn

| Denied | Allowed | Why |
|---|---|---|
| `env` | `env VAR=1 cmd` | The second form sets a variable for one command; it prints nothing. |
| `printenv` | `printenv PATH` | Naming one variable is the behaviour we want to encourage. |
| `export -p` | `export PATH=/x` | `-p` lists everything; an assignment lists nothing. |
| `set` | `set -e` | Bare `set` prints every shell variable. |
| `declare` | `declare X=1` | Same. |
| `history` | `helm history`, `docker history` | The wrapper check makes the first word decide. |

## Pass B — files that hold credentials

Pass B requires two things at once: a reading command (`cat`, `head`, `tail`,
`less`, `strings`, and PowerShell's `type` and `gc`) and a path that looks like
a secret store.

One list covers every system, and either path separator is accepted, because a
Git Bash or WSL shell is handed one spelling one moment and the other the next:

| What | Where |
|---|---|
| `.env`, `*.pem`, `*.p12`, `*.pfx` | everywhere |
| `id_rsa`, `id_ed25519`, `id_ecdsa` | everywhere |
| `.aws/credentials`, `.kube/config`, `.docker/config.json`, `.azure/` | everywhere, backslashed on Windows |
| `.git-credentials`, `.npmrc`, `.pypirc`, `.pgpass`, `.my.cnf` | everywhere |
| `.bashrc`, `.zshrc`, `.profile`, `.netrc` | POSIX |
| `_netrc` | Windows, where that is what `.netrc` is called |
| `Microsoft.PowerShell_profile.ps1` | Windows, where `$env:API_KEY = "..."` is written |
| `/proc/N/environ` | Linux only; no such file elsewhere |

The last two rows are what stops the list being half a list. On Windows the
PowerShell profile plays the part `.bashrc` plays elsewhere, and a key sits in
it just as plainly.

The two are looked for in different versions of the string, and the split is
the whole trick:

- **the reader, in the quote-stripped text** — it has to be a real command
- **the path, in the raw text** — it is often quoted, and pass A would have
  erased it

Requiring both keeps the false-positive rate low: `cat README.md` mentions no
secret path, and `ls ~/.aws/credentials` reads nothing.

Looking for the reader in the stripped text is what keeps prose out of the
decision. This commit message —

```bash
git commit -m "docs: cat .env ends the same way"
```

— contains a reader and a secret path, and an earlier version denied it. The
words are an argument, not a command; stripping the quotes removes them before
the reader is ever found.

The `.env` pattern needs a boundary on its left, or it fires on ordinary text.
A real example from this repository's own development:

```bash
jq -r '.permission.bash.env' opencode.json | head
```

`bash.env` contains the substring `.env`, and `head` is a reader — so an
unbounded pattern denied a perfectly safe command. The pattern now requires the
`.env` to be preceded by a space, a quote, a slash or an `=`.

## Failing open

If the payload is not JSON, or `jq` is missing, or the command field is empty,
the guard exits 0 and the call proceeds. A guard that breaks the assistant when
something unexpected arrives gets uninstalled, and an uninstalled guard blocks
nothing at all.

The blocking path is the narrow one: exit 2, with a message on stderr that the
assistant shows to the model. Everything else lets the work continue.

## Why a rule file ships with it

Blocking a command the model believes it needs produces retries — a different
spelling, then another, until it gives up or finds a gap. The rule installed
next to `secrets-guard` says what to use instead, so the first denial ends the
matter:

```
safe-env                      # whole environment, secret values masked
echo "$ANTHROPIC_MODEL"       # one variable, when you know the name
```

The guard is the gate; the rule is the sign next to it. Neither replaces the
other.

## Keys arrive from the parent shell

Worth knowing, because it explains a puzzling case: a key that is in the
assistant's environment while being absent from every dotfile.

Assistants snapshot their environment once, at start-up. A variable exported in
the shell that launched the assistant stays in every command it runs for the
life of the session — even after the export is removed from `.bashrc`. This was
confirmed by reading `/proc/<pid>/environ` of the parent process.

To actually clear one: exit the assistant, start a clean login shell, confirm
the variable is gone (`safe-env | grep NAME`), then start the assistant again.

## What this does not do

- It does not read command **output**. A program that prints its own
  configuration, keys included, is outside its reach.
- It is not a sandbox. Someone determined to read a value can encode it,
  reverse it, or write it to a file first. The target is the ordinary accident,
  which is what actually happens.
- It does not rotate anything. Once a key reaches a transcript, the only fix is
  a new key.
