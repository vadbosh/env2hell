# Changelog

## 0.7.1 — 2026-09-18

### Fixed

- **`grep -i TOKEN ~/.env` passed, because the guard read `-i` as "in-place".**
  0.7.0 added extracting readers with one exception: an in-place edit is not a
  read. The exception matched `-i` for every reader, and `-i` is `--ignore-case`
  for `grep`, `rg`, `ag` and `ack`, and `--ignore-nonprinting` for `sort` — so
  the commonest spelling of a search disabled the check. The command in this
  repository's own founding story is `env | grep -i api`.

  The exception is per command now: `sed` and `perl` with `-i`/`--in-place`,
  `awk` with `-i inplace`. Everything else keeps `-i` as an ordinary flag.
  Found by a re-audit of the guard the same afternoon 0.7.0 shipped —
  `review-2026-09-18-secrets-guard.md`, item A12.

- **`grep -f "$HOME/.env" list.txt` passed.** The first quoted argument of a
  grep-like command is its search pattern and is skipped when looking for a
  path — but `-f` and `--file` take a *file* of patterns, so after either of
  them the span is a path. Both implementations check it now.

### Added

- **`.envrc` is a credential store.** direnv exports variables the way a shell
  profile does, and the name is specific enough to cost nothing in false
  positives. Denied in the two hooks, the PowerShell port and the Opencode
  rules.

### Tests

- `tests/test_guard.sh`: 159 → 171 cases. Eight denied — the five ignore-case
  spellings, `-f` with a store, and `.envrc` two ways — and four that must stay
  allowed: `sed --in-place`, `awk -i inplace`, `perl -i -pe`, `grep -i` on an
  ordinary file. Both implementations report 171.

## 0.7.0 — 2026-09-18

Behaviour change in all four implementations: the guard denies more than it did.
Both items come from `review-2026-09-18-design-docs.md` and
`review-2026-09-18-patterns-docs.md`.

### Fixed

- **The reader list was pagers only, so `grep` read a store freely.** `cat`,
  `less`, `xxd` and eleven more were denied; `grep . ~/.aws/credentials`,
  `sed -n 1,5p ~/.env`, `awk '{print}' ~/.env`, `sort`, `uniq`, `cut` and `rev`
  printed the file and the guard said nothing. The standing rules on a machine
  like this one tell an assistant to reach for `rg`/`grep` when it needs file
  content, so the one open path was also the recommended one. Seventeen
  extracting readers are denied now, in the two hooks, in the PowerShell port
  and in the Opencode rules.

  Two qualifications keep ordinary work working, and both are tested: an
  in-place edit is not a read (`sed -i`, `sed -i.bak`, `awk -i inplace`), and
  the first quoted argument of a grep-like command is its search pattern, not a
  path — `grep -rn "cat .env" docs/` searches for the words, while
  `grep KEY "$HOME/.env"` is denied, because there the quoted span is a path and
  an unquoted pattern precedes it.

- **A file named `prod.env` was not a store.** Only a bare `.env` was denied,
  while the documented list said `*.env` — and Opencode, whose rules are globs,
  denied it all along. All four implementations now deny a filename ending in
  `.env` when the component before it holds no dot. That condition is what keeps
  `jq -r '.permission.bash.env' opencode.json | head` working: there the
  character before `bash` is a dot, and the token is a config key rather than a
  filename.

### Documentation

- Both pages list the readers in full, in two kinds — pagers and extractors —
  with the two qualifications named.
- `docs/design.*` gained `*.key` and `<name>.env` in the store table, a pointer
  to the third masking tier in `docs/patterns.*`, and one more entry under what
  this does not do: an interpreter reads anything, and closing that would mean
  parsing arbitrary code.
- The `*.env` split between implementations is gone, so both pages describe one
  behaviour again.

### Tests

- `tests/test_guard.sh`: 138 → 159 cases. Ten denied reads through extractors,
  three denied `<name>.env` spellings, and eight that must keep passing —
  including `grep -rn "cat .env" docs/`, `sed -i`, and `cat prod.env.example`.
  Both implementations run the same set: `--pwsh` reports the same 159.

## 0.6.4 — 2026-09-18

### Documentation

- **The store list said `*.env`, and only `.env` is denied.** Every other glob
  on that line is a real glob — `cat server.pem`, `cat deploy.key` and
  `cat cert.p12` are all refused — so the entry read as one. The hooks need a
  boundary to the left of `.env`, which is why `cat prod.env`,
  `cat secrets.env` and `head config/production.env` go through while
  `cat .env`, `cat /srv/app/.env` and `cat .env.local` are refused. Both
  languages now write `.env`, list which spellings are covered, and name the
  reason the boundary exists.
- **And the implementations disagree about it.** `SECRET_FILES` in
  `lib/patch_config.py` carries a real `*.env` glob, so Opencode denies
  `cat prod.env` while both hooks allow it. Measured, not inferred:
  `tests/test_policy.sh` reports it as soon as `prod.env` joins the shared
  list. Written into both versions of the page as an open split, with the
  advice to treat only a file named `.env` as covered until it is resolved.
- **A whole masking tier was undocumented** — the one that decides by the
  *name* of a variable. `HW_SECRET_KEY` and `BUILD_ID` holding the same value
  come back differently, and nothing on the page said why. The name list, the
  whole-component rule and the three exemptions are now a section of their own
  in both languages.
- `ATATT…` ships in both implementations and had no row in the format table.
- "Adding a format" named two files; a rule can belong to four places, and
  which one depends on whether it is a prefix, a shape, a name, or something
  the redactor must not have. Plus the parity table, which is what makes "add
  it to both" enforceable.

### Tests

- `tests/test_policy.sh` pins `~/srv/app/.env` as denied — the spelling that
  proves the boundary rule covers a path, not just a bare filename.

## 0.6.3 — 2026-09-18

### Documentation

- Three headings named the subject the reader had to reconstruct from the
  section above: "How it is wired" → "Как env2hell встраивается в ассистента"
  and its English pair, and "Чем от этого отличается запрет команд" → "Чем
  запрет команд отличается от маскирования" with the English side moved the
  same way. Found by a heading check that reads the table of contents as the
  reader does, with no previous line in view. No anchor pointed at the old
  text.

## 0.6.2 — 2026-09-18

### Documentation

- **Long sentences cut by count, not by ear.** A sentence past thirty words is
  nearly always a list joined by semicolons, and the reader reaches its end
  without its beginning. Both READMEs and both manuals were measured and cut in
  pairs: what the hooks cannot do about a transcript already on disk, why the
  PowerShell half of the suite has to run, why `"env"` inside quotes is not
  recoverable, the `--warn-only` hook on a failed command, and the two
  concurrent Windows installers. Two enumerations became lists — where the
  installer puts the rule file for each assistant, and the three conditions
  under which the redaction hook fails open.
- **Four headings opened with a pronoun** and left the subject to be
  reconstructed from the section above: "Зачем это нужно", "Как этим
  пользоваться", "Как это устроено", "Чем за это приходится платить". They name
  env2hell and the masking now, in both languages; the two README links to the
  renamed design document were updated with them.

### Repository

- The audit reviews produced against `bin/` stay out of the repository, and the
  comment that used to point at one names its reason instead.

## 0.6.1 — 2026-09-17

### Fixed

- **`release.sh check` watches the installed commands without being asked.**
  `ENV2HELL_MIRRORS` was the only source of copies to compare, so an unset
  variable meant the commands `install.sh` actually put on this machine went
  unwatched — and `check` said "none configured", which reads as nothing to
  report rather than as nothing looked at.

  Found the way these things are found: at 0.6.0's release the installed guard
  was one commit behind and did not have the sub-command limit, while the check
  reported everything in agreement. The three shipped commands in
  `${ENV2HELL_BIN_DIR:-$HOME/.local/bin}` are compared now whether or not
  anything is set; `install.sh` derives that directory the same way.
  `ENV2HELL_MIRRORS` keeps its job — copies only the machine knows about, such
  as the rule file as a config canon redistributes it, or a second checkout.

## 0.6.0 — 2026-09-17

Four cold reviews — `bin/secrets-guard`, `bin/safe-env` and a parity pass over
each PowerShell port — and every item they raised. The reviews are kept
alongside the checkout as `review-2026-09-17-*.md` rather than committed; what
follows is what changed for someone who uses this.

The headline is not a pattern. **The guard was failing open**, and it was
measured rather than guessed: past roughly 520 sub-commands it was killed by its
own hook timeout, and a killed `PreToolUse` hook does not deny — the command
runs and nothing anywhere says the check never happened. A command of 1208 bytes
was enough. A heredoc writing a file of 550 lines is the ordinary way to reach
that number.

### Fixed

- **The guard finishes.** Its two shell loops forked `sed` and `grep` once per
  sub-command, about 13 ms each; they are one `awk` program now. Two thousand
  sub-commands went from 26.6 s to 0.48 s, fifty thousand take 8.2 s. The hook
  timeout went from 5 s to 30 s in the same change.

- **And when it cannot finish, it denies.** Failing open is right for an
  unexpected payload and stays; a command too large to check is not that. Past
  50 000 sub-commands the guard refuses with a message naming the count, in
  under a second. The limit is a count rather than a clock, so it answers the
  same on every machine and needs no `timeout` binary.

- **`safe-env` printed the body of a multi-line value.** A private key in an
  environment variable came back as a masked header followed by its own base64,
  and the number in `<REDACTED:31>` was the length of that header rather than of
  the value. Values are read as NUL-separated pairs now, so a value containing a
  newline is one record. The PowerShell port never had this; the fix is copied
  from it.

- **A credential name is a whole component, not a substring.** `PASS` matched
  inside `BYPASS_CACHE`, `PASSENGER_ROOT` and `$passed` — so `printf 'passed %d,
  failed %d\n' "$pass" "$fail"` was denied, which is this project's own test
  harness reporting its results. `DB_PASS` and `PASS_FILE` are still denied;
  `PASSWORD`, `PASSWD` and `PASSPHRASE` say it on their own.

- **`.env.example` and its siblings are readable.** `.env.sample`,
  `.env.template`, `.env.dist` and `.env.defaults` too. They are committed
  precisely because they hold no values, and reading one is the first thing
  anybody does in an unfamiliar repository. `.env.production` is still denied.

- **A heredoc body is data, not a list of commands.** Writing a file whose text
  mentions `env` or `cat .env` was denied, which is how this repository came to
  document a workaround for its own guard. `<<<` is untouched.

- **`sk-` needs a boundary.** Unanchored, it masked
  `ANTHROPIC_MODEL=zai-sk-glm-4-6-turbo-preview` — the one variable the
  documentation uses as its example of a value that prints. The boundary counts
  `-` as part of a word, because a plain word boundary changes nothing here: the
  character before `sk-` in that name is a hyphen.

- **Standard base64 is masked.** `+`, `/` and `=` sit outside the alphabet every
  generic fallback used, and any one of them broke a run long enough to match. A
  32-byte secret in base64 is 44 characters and almost always carries one. A
  path is excluded, because `/` is in that alphabet too.

- **Windows: a newline separates sub-commands.** The port split on `;`, `&` and
  `|` and nothing else, so `ls -la` followed by `env` on the next line printed
  the environment there and was denied everywhere else — and, in the other
  direction, a reader on one line with a secret path on another counted as one
  sub-command, which denied ordinary two-line commands.

### Added

- **Fourteen more credential stores are denied**: `gh/hosts.yml`,
  `.terraformrc`, `credentials.tfrc.json`, the three gcloud files,
  `.cargo/credentials`, `.gem/credentials`, `.m2/settings.xml` and
  `settings-security.xml`, `rclone.conf`, `.vault-token`, `.databrickscfg`,
  `.snowflake/config`, `containers/auth.json`, `helm/registry/config.json` —
  and `*.key`. `gh/hosts.yml` is the sharp one: `gh` keeps a token there in
  plain text.

- **`/proc/self/environ`** and `/proc/thread-self/environ`, which are not
  digits and were not matched.

- **A dump reached through something that runs commands.** `bash -c env`,
  `eval env`, `$(env)` and the environment-dumping idiom of Python, Node, Perl
  and Ruby. The payload has to *be* the dump command, so `bash -c "echo env"`
  and `sh -c "set -e; make"` keep working.

- **`FOO=bar env`, `\env` and `/usr/bin/env`.** A leading assignment, an escaped
  name or a directory used to make the guard skip the whole sub-command rather
  than that one token.

- **`printenv -0`** and `--null`, which change the separator and not the scope.

- **A here-string prints its text**, so `cat <<< "$GITHUB_TOKEN"` is denied
  while `grep foo <<< "$line"` is not.

### Changed

- **One policy, asked of every implementation.** The list of credential stores
  lived in four files and disagreed: `cat server.key` was denied in Opencode and
  allowed in Claude Code and Codex, on the same machine, with nothing saying so.
  The credential-name list lived in four more. `tests/test_policy.sh` asks all
  of them the same questions — regular expressions and globs cannot be diffed as
  text, but they can be asked.

- **Two absences are decisions with tests behind them.** `~/.ssh/config` stays
  readable: it holds hostnames and `IdentityFile` paths, not keys. `_FILE` and
  `_PATH` suffixes stay unexempt: the guard has only the name, and exempting
  them would trade a visible false denial for a silent miss.

- **`*credentials*` and `*secrets*` are enforced by Opencode alone**, where they
  ask rather than refuse. As a hard deny in the hooks they would block
  `cat credentials-design.md`.

- **The tests know their own constants.** The rule count and the hook timeouts
  are read from `lib/patch_config.py` rather than written out, after four
  assertions failed for the only reason a test must never fail. The PowerShell
  suites run against one `pwsh` process instead of one per case: the guard's
  suite went from 115 s to 11 s, the redactor's from 72 s to 6 s, the new parity
  run from 380 s to 53 s.

## 0.5.3 — 2026-09-16

Three cold reviews — `lib/patch_config.py`, `bin/secrets-redact` and its
PowerShell port — and the fixes they asked for. The reviews are kept
alongside the checkout as `review-2026-09-1*.md` rather than committed; what
follows is what changed for someone who uses this.

### Added

- **A private key is masked as a block.** Tier 1 matched the `BEGIN … PRIVATE
  KEY` line and nothing else, so a key read through `Read` came back with
  `-----<REDACTED:25>-----` on top and the body intact underneath — which reads
  as handled. The header starts the block, the footer ends it, and the body is
  replaced line for line so a diff against the file still lines up.

- **Three shapes a labelled secret takes and was missed in.** An HTTP header
  (`Authorization: Bearer …`, with the scheme word left readable), a quoted
  password carrying punctuation (`password = "S3cr3t!Pass#2026"` — inside
  quotes the writer has already said where the value ends, so the floor there
  is eight characters rather than sixteen), and the JSON spelling
  (`{"password": "…"}`, where a closing quote sits between the label and the
  colon).

- **`patch_config.py --print`** writes the wiring to stdout for a configuration
  this installer must not rewrite.

- **Four test suites where there were three.** `tests/test_parity.sh` runs the
  same bytes through both redactors and diffs the answers — it exists because
  doing that by hand found three defects no single-port test could have caught.
  `tests/test_release.sh` checks that everything `install.sh` ships is a name
  `release.sh` knows. And `tests/test_install.sh` now runs both installers and
  the uninstaller end to end rather than only driving the patcher.

### Fixed

- **The redactor was slow enough to be switched off by its own timeout.**
  `scrub_labelled` was called twice per line with different separators, which
  misses gawk's compiled-regex cache and recompiles the whole label alternation
  for every line: 10.5 s per megabyte. A killed `PostToolUse` hook replaces
  nothing, so every tool result over about a megabyte reached the model
  unmasked and unannounced. Both separators are one pattern now — 0.4 s per
  megabyte — and the installer gives the hook 60 s rather than 10.

- **The warning under-reported credentials.** `--warn-only` counted matching
  *lines*, so four values on two lines were announced as two, in the one
  message a person reads to decide whether to rotate a key.

- **`--filter` added a byte that was not in the input.** awk terminates every
  line; the hook path had repaired that since it was written and this mode
  never did — and this mode is what the Opencode plugin calls to replace a tool
  result.

- **A killed hook left the whole tool result in `/tmp`.** 74 MB from one kill,
  measured. Everything goes under one directory now, `chmod 700`, swept of
  anything older than an hour by the next run.

- **The installer claimed hooks it did not own.** Ownership was a substring of
  the command, so a user's own `wrap-secrets-guard` was silently repointed at
  this installation and their `secrets-redact-audit` hook was deleted by
  `--remove`. It is the program being run — argv[0] — that says whose entry it
  is.

- **An Opencode `opencode.jsonc` is read now**, comments and all. It is still
  not rewritten while it carries them, because a dump would drop every one:
  the run says so, names the file and offers `--print`. And `install.sh` stops
  discarding the patcher's exit code, so an assistant left unwired is reported
  and the run finishes non-zero.

- **Four ways a patch damaged the file it was patching.** A symlinked
  configuration was replaced by a regular file, detaching a dotfiles
  repository; a 600 file came back 644; a crash between the write and the
  rename left a world-readable copy of the whole configuration beside it; and
  two installers at once shared one temporary filename, so one of them died on
  the rename with its change lost.

- **Backups no longer accumulate without limit** — the three newest are kept —
  **and a patch keeps the file's own indentation**, which was 68 changed lines
  on a configuration of three keys.

- **The Windows installer.** It died on a configuration holding `{}` with
  "The property 'Name' cannot be found on this object" — strict mode treats
  member enumeration over an empty collection as an error — which is what a
  fresh install meets. It was also missing the `Edit|Write|mcp__.*` warning
  entry and had a narrower failure matcher than the POSIX side; the three
  matchers and the timeout are now compared against `lib/patch_config.py` by a
  test rather than by a comment.

- **An installation kept its old timeouts for ever.** Re-running the installer
  repointed the command and widened the matcher of an entry it found, and never
  touched its `timeout` — so the machine this was found on still had every
  redactor entry at 10 s hours after the installer had started writing 60, which
  is exactly the window that number was raised to close. Both installers now
  bring an existing entry up to the current numbers, and say so.

- **`release.sh` could not see the file this repository changes most.**
  `secrets-redact` was shipped on 2026-09-14 and was still not in its list of
  known names, so the mirror check answered "no file of that name is shipped"
  and reported zero recognised mirrors as agreement.

## 0.5.2 — 2026-09-09

### Added

- **Atlassian API tokens are masked.** `ATATT…` — the prefix Jira and
  Confluence Cloud issue — followed by a base64url body and a trailing
  checksum. The generic fallbacks missed it: the body carries `-`, `_` and `=`,
  so it matched neither the hex rule nor the `[A-Za-z0-9_-]{40,}` one. Added to
  `safe-env`, `secrets-redact` and the PowerShell port.

- **`safe-env` masks by variable name when the value's shape says nothing.** A
  classic Atlassian token is 24 characters of letters and digits — the shape of
  a build id, a short hash, a bucket name — so no pattern can claim it without
  masking half an ordinary environment. The name can, and it is visible. Three
  exemptions keep the output readable: a path is configuration
  (`TOKEN_FILE=/etc/creds/jira`), so is a flag
  (`TOKENIZERS_PARALLELISM=false`), and nothing under eight characters is worth
  hiding. Shape still decides first; the name only rules on what is left.

### Fixed

- **A credential handed to another command is no longer read as printing it.**
  `printf "%s" "$(curl -u "$user:$API_TOKEN" …)"` was denied: the guard saw a
  printing command and a credential-named variable on the same line, though
  what reaches the output is curl's response. Command substitutions are now
  peeled innermost-first and each body judged on its own, so the case above
  passes while `echo "$(printf %s "$API_TOKEN")"` stays denied.

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
