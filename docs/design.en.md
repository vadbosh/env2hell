# How env2hell works

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

Three things are peeled off before the first token is read as a command name,
because each of them used to make the whole sub-command unreadable rather than
just that token:

- **leading assignments** — `FOO=bar env` sets a variable for `env`, and the
  `=` is not part of the name
- **a leading backslash** — `\env` is the ordinary way to bypass an alias
- **a directory** — `/usr/bin/env` is the ordinary way to bypass `PATH`, and the
  basename is what names the program

What remains and still does not look like a command name — a fragment starting
with `"`, `{`, `[`, `$` or `*`, or containing a character outside
`[A-Za-z0-9_.-]` — is skipped rather than guessed at. `"env"` is the one shape
in that list that really is a command. Pass A works on quote-stripped text, so
the quotes are gone by the time it is read. Recovering that case would mean
giving up the stripping that keeps a commit message out of the decision.

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

Pass B requires two things at once: a reading command and a path that looks like
a secret store.

Reading commands come in two kinds. **Pagers** print the whole file: `cat`,
`bat`, `batcat`, `tac`, `nl`, `head`, `tail`, `less`, `more`, `view`, `od`,
`xxd`, `strings`, plus PowerShell's `type` and `gc`. **Extractors** take a part
of it: `grep`, `egrep`, `fgrep`, `rg`, `ag`, `ack`, `sed`, `awk`, `gawk`,
`mawk`, `sort`, `uniq`, `cut`, `rev`, `column`, `jq`, `yq`.

The second list arrived in 0.7.0, and before it `grep . ~/.aws/credentials`
printed the file while the guard said nothing. A pager is how a file gets read
whole; a part of a file is read with an extractor, and the standing rules on
this machine tell an assistant to prefer `rg` or `grep`. The open path was the
recommended one.

Extractors carry two qualifications, without which they would deny ordinary
work:

- **an in-place edit is not a read**, and the exception is **per command**:
  `-i` is `--in-place` for `sed` and `perl`, `--ignore-case` for `grep`, `rg`,
  `ag` and `ack`, and `--ignore-nonprinting` for `sort`. Applied globally in
  0.7.0 it let `grep -i TOKEN ~/.env` through — the spelling this repository
  was founded on. Allowed: `sed -i`, `sed -i.bak`, `sed --in-place`,
  `awk -i inplace`, `perl -i -pe`;
- **the first quoted argument is the search pattern, not a path.**
  `grep -rn "cat .env" docs/` searches for the words and must stay allowed. That
  span is dropped only when nothing but flags precedes it, so
  `grep KEY "$HOME/.env"` is still denied. One exception inside the exception:
  `-f` and `--file` take a **file** of patterns, so a quoted span after either
  is a path and is checked.

One list covers every system, and either path separator is accepted, because a
Git Bash or WSL shell is handed one spelling one moment and the other the next:

| What | Where |
|---|---|
| `.env`, `<name>.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx` | everywhere |
| `id_rsa`, `id_ed25519`, `id_ecdsa` | everywhere |
| `.aws/credentials`, `.kube/config`, `.docker/config.json`, `.azure/` | everywhere, backslashed on Windows |
| `.git-credentials`, `.npmrc`, `.pypirc`, `.pgpass`, `.my.cnf` | everywhere |
| `.bashrc`, `.zshrc`, `.profile`, `.netrc`, `.envrc` | POSIX |
| `_netrc` | Windows, where that is what `.netrc` is called |
| `Microsoft.PowerShell_profile.ps1` | Windows, where `$env:API_KEY = "..."` is written |
| `/proc/N/environ`, `/proc/self/environ` | Linux only; no such file elsewhere |

The last two rows are what stops the list being half a list. On Windows the
PowerShell profile plays the part `.bashrc` plays elsewhere, and a key sits in
it just as plainly.

The two are looked for in different versions of the string, and the split is
the whole trick:

- **the reader, in the quote-stripped text** — it has to be a real command
- **the path, in the raw text** — it is often quoted, and pass A would have
  erased it

The body of a `$( … )` substitution is checked on its own, before the
sub-command around it. The split into sub-commands happens on `;`, `&` and `|`
outside quotes, so `echo "$(cat ~/.env)"` arrives as one sub-command with its
reader inside a quoted span — exactly where pass B cannot see it. Each body is
tested as a command of its own and then collapsed to `CMDSUB`.

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

A file named `prod.env` or `config/production.env` is denied too — the component
before `.env` may not contain a dot. That is what separates a filename from a
config key: in `'.permission.bash.env'` the character before `bash` is a dot.

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

## After the fact — secrets-redact

Everything above happens before a command runs, which fixes the whole class of
accident where the assistant *reads* a secret. It cannot touch the other class:
a command that *prints* one. There is nothing in the command line to inspect —

```bash
croc send report.pdf
```

— and the password appears only in the answer, because `croc` echoes the
options a receiver will need. The same shape turns up in `docker login`
transcripts, in verbose `curl`, in any tool that reports the arguments it was
handed.

`secrets-redact` gets in front of the model by whichever route the assistant
offers. Claude Code: a `PostToolUse` hook that replaces the result through
`hookSpecificOutput.updatedToolOutput`. Opencode: a `tool.execute.after` plugin,
whose `output` is mutable by design, so the masked string is assigned back in
place. One policy either way — the plugin shells out to the same CLI in
`--filter` mode, which is plain text in and masked text out with no JSON and no
`jq`.

Codex is the exception, and not for lack of trying. Its `PostToolUseOutcome`
(`codex-rs/hooks/src/events/post_tool_use.rs`) is

```rust
pub struct PostToolUseOutcome {
    pub hook_events: Vec<HookCompletedEvent>,
    pub should_block: bool,
    pub additional_contexts: Vec<String>,
    pub feedback_message: Option<String>,
}
```

— block, add context, say something. Nothing replaces the result.

So Codex gets `--warn-only`, which does the one thing that contract allows: it
reports through `additionalContext` that a credential-shaped value is in the
output, and says how many. It names no value and no command, because either
would put a second copy in the transcript being warned about.

That is not redaction and the mode name says so. What it buys is that the leak
stops being silent: the model is told the value is compromised, which is what
starts a rotation. Finding out now beats finding out never, and Codex keeps the
guard either way.

Two tiers decide what to mask — and in `safe-env` there are three: a third one
decides by the **name** of the variable, documented in
[`patterns.en.md`](patterns.en.md). The label on the line, below, plays the part
for `secrets-redact` that the name plays for `safe-env`.

**Tier 1, provider shapes.** `ghp_`, `glpat-`, `AKIA`, a JWT, a private key
header, credentials inside a URL. These are unambiguous, so they are masked
wherever they appear. The pattern list is character-for-character the one in
`safe-env`; `tests/test_redact.sh` diffs the two files and fails if they drift.

**Tier 2, labelled values.** A high-entropy run is masked only when something
on the same line calls it a secret — `--pass`, `--token`, `password=`,
`api_key=`, `Authorization: Bearer`, and since 0.8.5 the SQL spelling
`IDENTIFIED BY '…'`, which `safe-env` had from the first commit and the
redactor did not. The label is doing real work here. The
password this hook was written for was 32 hex characters, and so is every md5
in the session:

```
croc --relay host:9009 --pass deadbeefdeadbeefdeadbeefdeadbeef code-word
md5sum: deadbeefdeadbeefdeadbeefdeadbeef  report.pdf
```

Identical strings, opposite verdicts. Masking bare hex would redact every
checksum and commit hash the model needs to reason about, and a redactor that
destroys ordinary output gets uninstalled exactly like a guard that blocks
ordinary commands.

The mask keeps the length — `<REDACTED:32>` — because the model usually needs
to know *that* something was removed and how long it was, not what it was.

### What the masking costs

The hook fires after the tool has already run. The command executed, any side
effect it had stands, and the assistant's telemetry records the original output.
What is prevented is narrower and still worth having: the secret does not enter
the model's context, and so does not enter the transcript the model writes, the
summary it produces, or the memory store that indexes them.

It also fails open, on the same reasoning as the guard. No `jq`, unparsable
input, a tool result with no `stdout`/`stderr` — all three mean exit 0 with no
output, which leaves the result untouched.

## Why a rule file ships with it

A denial on its own is not enough, and here is why.

The assistant needs to know whether a key is set. It is refused — and since the
task has not gone away, it tries another way:

```bash
env | grep API          # denied
printenv | grep API     # denied
sh -c 'env'             # denied
```

Every attempt is a wasted round: your time, and one more chance of stumbling on
a spelling the check does not take apart.

The installer puts `rules/secrets-hygiene.md` where the assistant reads its
standing instructions:

- Claude Code — `~/.claude/rules/`;
- Codex — `~/.codex/memories/`;
- Opencode — `~/.config/opencode/instructions/`, where the installer also adds
  the file to the `instructions` list, without which Opencode never reads it.

The file says what to use instead:

```bash
safe-env                      # whole environment, secret values masked
echo "$ANTHROPIC_MODEL"       # one variable, when you know the name
```

After the first denial the assistant reaches for `safe-env`, gets the answer it
needed, and moves on.

So: `secrets-guard` stops the key being printed, and the rule says how to answer
the original question another way. Without the rule the protection still works —
it just costs several wasted attempts every time.

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

- The guard does not read command **output**; `secrets-redact` does, but only
  after the command has run, and only for values a label identifies. An
  unlabelled secret that reads as ordinary text — a three-word passphrase, say
  — passes through both.
- It is not a sandbox. Someone determined to read a value can encode it,
  reverse it, or write it to a file first. The target is the ordinary accident,
  which is what actually happens.
- It does not rotate anything. Once a key reaches a transcript, the only fix is
  a new key.
- **The lists for a command run by another command are partial on purpose.**
  `bash -c env`, `eval env`, `$(env)` and the environment-dumping idiom of
  Python, Node, Perl and Ruby are denied, because those are what an assistant
  writes by habit. The test is that the payload IS the dump command, so
  `bash -c "echo env"` and `sh -c "set -e; make"` keep working — and so does
  anything that reaches the same place by another route. Parsing an arbitrary
  program to find out what it does is the sandbox this is not.
- **An interpreter will read anything.** `python3 -c 'print(open(".env").read())'`,
  `perl -pe '' .env` and any three-line program print a store and pass. The
  payload there is arbitrary code, and parsing it would mean building the
  sandbox this is not. The reader lists above close a habit, not an intent.
- **Only `echo`, `printf`, `cat` and `tee` count as printing a
  credential-named variable.** `awk -v k="$API_KEY" …` hands the value to a
  program, and what that program does with it is not decidable here.
- **`_FILE` and `_PATH` suffixes are not exempt, and that is a decision.**
  `echo "$API_KEY_FILE"` is denied even though the Docker and systemd
  convention is that such a variable holds the path to a secret rather than the
  secret. The guard has only the name: `safe-env` can look at the value and let
  a path through, and the guard cannot. Exempting the suffix would trade one
  visible false denial for a silent miss whenever `$TOKEN_PATH` does hold a
  token, and this project's own rule file says the name is what decides.
