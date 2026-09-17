#!/usr/bin/env python3
"""Wire (or unwire) secrets-guard into one assistant's configuration file.

Each assistant stores the same intent in a different place:

    claude    ~/.claude/settings.json      hooks.PreToolUse[] entry, matcher "Bash"
                                           hooks.PostToolUse[] entry, matcher "Bash"
    codex     ~/.codex/hooks.json          hooks.PreToolUse[] entry, matcher "^Bash$"
    opencode  ~/.config/opencode/opencode.json  (or .jsonc — whichever exists)
                                           plugin[] entry + permission.bash deny rules

secrets-redact reaches each of them differently, because their hook contracts
differ:

    claude    replaces the result via hookSpecificOutput.updatedToolOutput
    codex     cannot replace anything, so it warns instead (--warn-only)
    opencode  a tool.execute.after plugin, installed as a file, not wired here

Codex's PostToolUseOutcome (codex-rs/hooks/src/events/post_tool_use.rs) has
should_block, additional_contexts and feedback_message and no field that
replaces output. The warning names no value and no command — repeating either
would put a second copy in the transcript the warning is about.

Opencode needs the two layers together. `permission.bash` matches on a command
prefix, so on its own it never sees `env | grep X`, `rtk env` or `a && env`;
the plugin runs the real policy. The permission rules are still worth having
because they deny the common spellings before a plugin is even loaded.

Idempotent: an entry that is already present is left alone. A file that is
about to change is copied to <file>.bak.<timestamp> first, keeps its own mode,
and — when it is a symlink — is edited through the link rather than replaced.

Usage:
    patch_config.py <ide> --guard PATH [--redact PATH] [--with-rule]
                          [--remove] [--dry-run] [--print]

Exit codes, and they mean the same thing to a person and to install.sh:

    0  wired, or already current
    1  this assistant was NOT wired — a configuration that is not JSON, not an
       object, or a .jsonc carrying comments, which cannot be rewritten without
       dropping them. install.sh reports it and finishes non-zero.
    3  no configuration file for this assistant. Not an error: it means the
       assistant is not installed here.

Every diagnostic goes to stderr; only the running commentary goes to stdout.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shlex
import shutil
import sys
import tempfile
import time

HOME = os.path.expanduser("~")

# How old a leftover temp file has to be before a later run removes it. Long
# enough that a patcher running concurrently is never touched, short enough
# that the litter of a crash does not outlive the next install.
STALE_TEMP_SECONDS = 60

# What the redactor's hook entries are given. It is not a guess: the masking
# pass runs at roughly 90 KB/s here, Claude Code kills a hook at its timeout,
# and a killed PostToolUse hook replaces nothing — so the number is the size of
# tool result that still gets masked. 10 s covered under 1 MB and dropped
# everything above it silently; 60 s covers about 5 MB. The real repair is the
# redactor's throughput, and this number is what holds until that lands.
REDACT_TIMEOUT = 60

# The guard reads a command line, and length is not what it costs: a 1 MB
# single-token command comes back in 0.83 s. The cost is per SUB-COMMAND —
# pass B and the credential pass fork sed and grep once per one, about 13 ms
# each — and a heredoc contributes one sub-command per line of its body. At
# five seconds the guard was killed at roughly 520 sub-commands, and a killed
# PreToolUse hook does not deny: the command runs unguarded, silently.
# Measured 2026-09-17, review-2026-09-17-secrets-guard.md item A1. Thirty
# seconds moves that threshold to roughly 3100. It does not fix the shape;
# A1 does.
GUARD_TIMEOUT = 30

# How many timestamped backups of one configuration file to keep. Every changing
# run writes one and nothing ever removed them: 21 copies of settings.json were
# found in one live ~/.claude, each carrying whatever the `env` block holds.
# Three is enough to undo a bad install and small enough not to be a pile.
BACKUPS_KEPT = 3

def _opencode_config() -> str:
    """Whichever config file Opencode reads here, in the order it reads them.

    Opencode accepts more than one filename and loads the first that exists —
    its own startup log shows it trying opencode.json and then opencode.jsonc.
    Hardcoding the first meant that on a machine using the second, this script
    reported "config not found" and silently installed nothing: the plugin got
    written, the permission rules never did, and the installer said so in a
    line that reads like a note rather than a failure.

    When neither exists, the first is the one to create.
    """
    d = os.path.join(HOME, ".config", "opencode")
    for name in ("opencode.json", "opencode.jsonc"):
        candidate = os.path.join(d, name)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(d, "opencode.json")


CONFIG = {
    "claude": os.path.join(HOME, ".claude", "settings.json"),
    "codex": os.path.join(HOME, ".codex", "hooks.json"),
    "opencode": _opencode_config(),
}

# The guard inspects a command line before it runs, so it only has meaning for
# the shell tool. The redactor inspects a result after the fact, and a result
# carrying a credential does not have to have come from a shell: `Read` on a
# .env, an id_rsa or a kubeconfig hands the file over verbatim, and `Grep`
# returns matching lines. Measured 2026-09-14: a Read of a file holding a
# GitLab token put the token in the transcript untouched, because the hook was
# wired for Bash alone.
GUARD_MATCHER = {"claude": "Bash", "codex": "^Bash$"}
REDACT_MATCHER = {"claude": "Bash|Read|Grep", "codex": "^Bash$"}

# Assistants whose hook contract can replace a tool result once it exists, and
# those that can only be told about it. Codex's PostToolUseOutcome carries
# should_block, additional_contexts and feedback_message and nothing that
# replaces output, so there it warns instead — which is what turns a silent leak
# into a rotation.
REDACT_IDES = {"claude"}
WARN_IDES = {"codex"}


def is_ours(command, tool: str) -> bool:
    """Does this hook entry run our program, rather than merely mention it?

    Ownership used to be a substring test, and a substring is not a name. A
    user's own `/home/me/bin/wrap-secrets-guard --audit` was read as ours and
    silently repointed at this installation; their `secrets-redact-audit` hook
    was deleted by `--remove`. What says whose entry it is is the program being
    run — argv[0], as a bare name.
    """
    try:
        parts = shlex.split(str(command))
    except ValueError:                 # an unbalanced quote is not our entry
        return False
    return bool(parts) and os.path.basename(parts[0]) == tool


def redact_command(ide: str, redact: str) -> str:
    return redact if ide in REDACT_IDES else redact + " --warn-only"


# Commands that print the whole environment, and the readers that would print a
# file full of secrets. Kept here so the installer and the docs cannot drift.
DUMP_RULES = {
    "env": "deny",
    "printenv": "deny",
    "printenv *": "ask",
    "export -p*": "deny",
    "set": "deny",
    "declare": "deny",
    "typeset": "deny",
    "history": "deny",
    "safe-env": "allow",
    "safe-env *": "allow",
}

READERS = ["cat", "head", "tail", "less", "more", "strings",
           "xxd", "od", "nl", "tac", "bat", "batcat"]

SECRET_FILES = [
    "*.env", "*.env.*", "*/.env", "*.pem", "*.key", "*.p12", "*.pfx",
    "*id_rsa*", "*id_ed25519*", "*id_ecdsa*",
    "*/.bashrc*", "*/.zshrc*", "*/.profile*", "*/.bash_profile*",
    "*/.zshenv*", "*/.netrc*", "*_netrc*",
    "~/.bashrc*", "~/.zshrc*", "~/.profile*",
    # Credential stores of everyday tools; the same paths on Windows.
    "*.git-credentials*", "*.npmrc*", "*.pypirc*", "*.pgpass*", "*.my.cnf*",
    "*.azure/*", "*.kube/config*", "*.docker/config.json*",
    # Where a Windows user writes `$env:API_KEY = "..."`.
    "*Microsoft.PowerShell_profile.ps1*",
    "/proc/*/environ*", "*credentials*", "*secrets*",
]

PLUGIN_ENTRY = "./plugins/secrets-guard.ts"

# Opencode reads an instruction file only if it is listed here — dropping the
# file into instructions/ is not enough, and a rule nobody reads is worse than
# none, because it looks installed.
INSTRUCTION_ENTRY = "~/.config/opencode/instructions/secrets-hygiene.md"


def file_rules() -> dict:
    return {f"{r} {p}": "deny" for r in READERS for p in SECRET_FILES}


def strip_jsonc(text: str) -> str:
    """JSONC minus its comments, with strings left alone.

    A character at a time rather than a regular expression, because the only
    hard part is telling a comment from `"https://example"` and from a `\\"`
    inside a string — which is exactly what a regular expression gets wrong.
    Comments become spaces rather than nothing, so a column in an error message
    still points where the reader is looking.
    """
    out = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:      # an escaped quote is not the end
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif text.startswith("/*", i):
            while i < n and not text.startswith("*/", i):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def has_comments(path: str) -> bool:
    """A .jsonc that is only JSON can be rewritten; one with comments cannot."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return strip_jsonc(text) != text


def detect_indent(text: str):
    """The indent this file already uses, as json.dump wants it.

    A patch used to rewrite every line of the file with `indent=2`: 68 changed
    lines on a configuration of three keys, where four lines were the actual
    change. Harmless in meaning, expensive for anyone keeping their dotfiles in
    git — which is exactly the reader who also keeps them as a symlink.
    """
    for line in text.splitlines():
        body = line.lstrip(" \t")
        if not body or body == line:
            continue                      # blank, or not indented
        lead = line[: len(line) - len(body)]
        return "\t" if "\t" in lead else len(lead)
    return 2                              # nothing to learn from; the old default


def load(path: str):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # Opencode reads opencode.jsonc as well, and a file earns that extension by
    # carrying comments. Reading one was the whole reason _opencode_config
    # exists, and json.load refused it: the installer then said nothing useful
    # and left Opencode with no permission rules at all.
    if path.endswith(".jsonc"):
        return json.loads(strip_jsonc(text))
    return json.loads(text)


def save(path: str, data, dry_run: bool) -> None:
    if dry_run:
        return
    # A configuration under version control is usually a symlink into a dotfiles
    # repository. Renaming over the link replaces it with a regular file: the
    # repository keeps the old text, the live file holds the wiring, and every
    # later pull silently stops reaching the assistant. Follow the link and edit
    # what it points at.
    path = os.path.realpath(path)
    with open(path, encoding="utf-8") as fh:
        indent = detect_indent(fh.read())

    stamp = time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(path, f"{path}.bak.{stamp}")
    # The names carry %Y%m%d-%H%M%S, so sorting them as text sorts them by age.
    for stale in sorted(glob.glob(f"{path}.bak.*"), reverse=True)[BACKUPS_KEPT:]:
        os.unlink(stale)

    # A process killed with SIGKILL runs no `finally`, so the sweep is what
    # actually clears the litter of an earlier crash: same directory, same
    # suffix, and only for this configuration file.
    #
    # Only files that have been sitting there a while. A second patcher running
    # right now has a temp file of its own, seconds old, and deleting it is the
    # very race the unique name was introduced to end — measured, on the first
    # version of this sweep: the other run died on the rename with
    # FileNotFoundError.
    for stale in glob.glob(f"{path}.*.env2hell.tmp"):
        if time.time() - os.path.getmtime(stale) > STALE_TEMP_SECONDS:
            os.unlink(stale)

    # Unique by construction, and in the target's own directory so the rename
    # stays atomic. A fixed name is shared by two installers running at once,
    # and whoever renames first leaves the other with nothing to rename.
    mode = os.stat(path).st_mode & 0o7777
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                               prefix=os.path.basename(path) + ".",
                               suffix=".env2hell.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            # The temp file holds the whole configuration, including the `env`
            # block where an API key lives. mkstemp opens it 0600; this keeps
            # the original's mode instead of the umask's, which is also what
            # stops a 600 config from coming back 644 after the rename.
            os.fchmod(fh.fileno(), mode)
            json.dump(data, fh, indent=indent, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    finally:
        # A crash or a signal between the write and the rename used to leave the
        # whole configuration lying next to it, and nothing ever removed it.
        if os.path.exists(tmp):
            os.unlink(tmp)


def refresh_timeout(entry: dict, tool: str, timeout: int) -> list[str]:
    """Bring an entry that is already wired up to the current timeout.

    Re-running the installer repointed the command and widened the matcher of
    an entry it found, and never touched its timeout — so a machine wired
    before the number changed kept the old one for ever. Measured 2026-09-16 on
    this one: every redactor entry still said 10 while the installer had been
    writing 60 for hours, which is exactly the window the number was raised to
    close.
    """
    changed = []
    for h in entry.get("hooks", []):
        if is_ours(h.get("command", ""), tool) and h.get("timeout") != timeout:
            h["timeout"] = timeout
            changed.append(f"timeout set to {timeout}")
    return changed


def hook_entry(ide: str, guard: str) -> dict:
    return {
        "matcher": GUARD_MATCHER[ide],
        "hooks": [{
            "type": "command",
            "command": guard,
            "timeout": GUARD_TIMEOUT,
            "statusMessage": "secrets-guard...",
        }],
    }


def patch_hooks(ide: str, data: dict, guard: str, remove: bool) -> list[str]:
    """Claude Code and Codex share this shape."""
    changed = []
    hooks = data.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])

    present = [
        e for e in pre
        if any(is_ours(h.get("command", ""), "secrets-guard")
               for h in e.get("hooks", []))
    ]

    if remove:
        for entry in present:
            pre.remove(entry)
            changed.append("hook removed")
        return changed

    if present:
        # Already wired — make sure it points at this installation, and that it
        # carries the timeout this version writes.
        for entry in present:
            changed += refresh_timeout(entry, "secrets-guard", GUARD_TIMEOUT)
            for h in entry.get("hooks", []):
                if is_ours(h.get("command", ""), "secrets-guard") and h["command"] != guard:
                    h["command"] = guard
                    changed.append(f"hook repointed to {guard}")
        return changed

    pre.append(hook_entry(ide, guard))
    changed.append("hook added")
    return changed


def patch_post_hooks(ide: str, data: dict, redact: str, remove: bool) -> list[str]:
    """The PostToolUse half: same shape as patch_hooks, different event.

    Kept as its own function rather than a flag on patch_hooks because the two
    are independent — an installation can carry the guard and not the redactor
    (an assistant that cannot replace output), and removing one must not
    disturb the other.
    """
    changed = []
    hooks = data.setdefault("hooks", {})
    post = hooks.setdefault("PostToolUse", [])

    # The notice entry below is also a secrets-redact command on PostToolUse,
    # and it is not this one: it warns rather than replaces, and carries its own
    # matcher. Telling them apart by the flag keeps each idempotent.
    def _is_replace(entry):
        cmds = [str(h.get("command", "")) for h in entry.get("hooks", [])
                if is_ours(h.get("command", ""), "secrets-redact")]
        if not cmds:
            return False
        # Only Claude Code has a second, warn-only entry to tell this one from.
        # Everywhere else the redactor's own command *is* the warn-only one, and
        # reading the flag as "not mine" made the entry invisible to its own
        # patcher: every run appended another copy. Measured 2026-09-14 on
        # Codex, three identical PostToolUse entries after two runs.
        if ide != "claude":
            return True
        return not all(c.endswith("--warn-only") for c in cmds)

    present = [e for e in post if _is_replace(e)]

    if remove:
        for entry in list(post):
            if any(is_ours(h.get("command", ""), "secrets-redact")
                   for h in entry.get("hooks", [])):
                post.remove(entry)
                changed.append("post-hook removed")
        if not post:
            hooks.pop("PostToolUse", None)
        return changed

    if present:
        for entry in present:
            # An install made before the matcher widened is still wired for Bash
            # alone, and re-running the installer is the only thing that will
            # ever look at it. Widening it here is what makes the Read and Grep
            # coverage reach a machine that already had the hook.
            changed += refresh_timeout(entry, "secrets-redact", REDACT_TIMEOUT)
            if entry.get("matcher") != REDACT_MATCHER[ide]:
                entry["matcher"] = REDACT_MATCHER[ide]
                changed.append(f"post-hook matcher set to {REDACT_MATCHER[ide]}")
            for h in entry.get("hooks", []):
                if is_ours(h.get("command", ""), "secrets-redact") and h["command"] != redact:
                    h["command"] = redact
                    changed.append(f"post-hook repointed to {redact}")
        return changed

    post.append({
        "matcher": REDACT_MATCHER[ide],
        "hooks": [{
            "type": "command",
            "command": redact,
            "timeout": REDACT_TIMEOUT,
            "statusMessage": "secrets-redact...",
        }],
    })
    changed.append("post-hook added")
    return changed


NOTICE_MATCHER = "Edit|Write|mcp__.*"

# A failure carries its output in one `error` string whatever the tool, and
# nothing is rebuilt from it, so there is no reason to narrow this one: a failed
# `Edit` on a .env or a failed MCP call quotes the same credentials a failed
# shell command does.
FAILURE_MATCHER = "Bash|Read|Grep|Edit|Write|mcp__.*"


def patch_notice_hooks(ide: str, data: dict, redact: str, remove: bool) -> list[str]:
    """Tools whose result carries a secret in a shape not worth rewriting.

    `Read` and `Grep` hand over one string, and the hook replaces it. `Edit`
    does not: its result carries the file in four places — `originalFile`,
    `oldString`, `newString` and every line of `structuredPatch[].lines` — and
    `Write` adds `content` beside `originalFile`. An MCP result is an array of
    content blocks whose schema belongs to the server, not to Claude Code.

    Masking one of those fields and leaving the next would read as coverage
    while the same secret sits one key along, and rebuilding all of them means
    guessing at schemas this hook does not own. A mangled tool result is worse
    than an unmasked one — it is wrong in a way nothing downstream can detect.

    So this entry only warns. Detection runs recursive descent over every string
    in the result, which is safe precisely because nothing is rebuilt: an
    unfamiliar schema costs a false positive at worst.

    Editing a `.env` is ordinary work, and it is the case this covers.
    """
    if ide != "claude":
        return []

    changed = []
    hooks = data.setdefault("hooks", {})
    post = hooks.setdefault("PostToolUse", [])
    wanted = f"{redact} --warn-only"

    present = [
        e for e in post
        if any(str(h.get("command", "")).endswith("--warn-only")
               and is_ours(h.get("command", ""), "secrets-redact")
               for h in e.get("hooks", []))
    ]

    if remove:
        for entry in present:
            post.remove(entry)
            changed.append("notice-hook removed")
        if not post:
            hooks.pop("PostToolUse", None)
        return changed

    if present:
        for entry in present:
            changed += refresh_timeout(entry, "secrets-redact", REDACT_TIMEOUT)
            if entry.get("matcher") != NOTICE_MATCHER:
                entry["matcher"] = NOTICE_MATCHER
                changed.append(f"notice-hook matcher set to {NOTICE_MATCHER}")
            for h in entry.get("hooks", []):
                if is_ours(h.get("command", ""), "secrets-redact") and h["command"] != wanted:
                    h["command"] = wanted
                    changed.append("notice-hook repointed")
        return changed

    post.append({
        "matcher": NOTICE_MATCHER,
        "hooks": [{
            "type": "command",
            "command": wanted,
            "timeout": REDACT_TIMEOUT,
            "statusMessage": "secrets-redact...",
        }],
    })
    changed.append("notice-hook added")
    return changed


def patch_failure_hooks(ide: str, data: dict, redact: str, remove: bool) -> list[str]:
    """Claude Code's PostToolUseFailure: the event a non-zero exit fires.

    A command that fails does not reach PostToolUse at all, so the redactor
    never ran for one — which is how a GitLab token reached a transcript in
    full on 2026-09-14, from a `git remote -v` that exited 1 because a later
    command in the same call failed.

    Wiring it here does not mask that output: PostToolUseFailure documents
    `additionalContext` and no field that replaces a result, so the value is
    already in the transcript by the time any hook sees it. What this buys is
    that the model is told, in the same turn, that a credential just landed
    there and has to be rotated. A silent leak becomes a loud one, which is the
    whole difference between a key that gets rotated and a key that does not.

    A failing command is also where credentials surface most: a URL carrying a
    password, an auth error quoting the token, a connection string in a stack
    trace.
    """
    if ide != "claude":
        return []                      # the event is Claude Code's

    changed = []
    hooks = data.setdefault("hooks", {})
    fail = hooks.setdefault("PostToolUseFailure", [])

    present = [
        e for e in fail
        if any(is_ours(h.get("command", ""), "secrets-redact")
               for h in e.get("hooks", []))
    ]

    wanted = f"{redact} --warn-only"

    if remove:
        for entry in present:
            fail.remove(entry)
            changed.append("failure-hook removed")
        if not fail:
            hooks.pop("PostToolUseFailure", None)
        return changed

    if present:
        for entry in present:
            changed += refresh_timeout(entry, "secrets-redact", REDACT_TIMEOUT)
            if entry.get("matcher") != FAILURE_MATCHER:
                entry["matcher"] = FAILURE_MATCHER
                changed.append(f"failure-hook matcher set to {FAILURE_MATCHER}")
            for h in entry.get("hooks", []):
                if is_ours(h.get("command", ""), "secrets-redact") and h["command"] != wanted:
                    h["command"] = wanted
                    changed.append("failure-hook repointed")
        return changed

    fail.append({
        "matcher": FAILURE_MATCHER,
        "hooks": [{
            "type": "command",
            "command": wanted,
            "timeout": REDACT_TIMEOUT,
            "statusMessage": "secrets-redact...",
        }],
    })
    changed.append("failure-hook added")
    return changed


def patch_opencode(data: dict, remove: bool, with_rule: bool = False) -> list[str]:
    changed = []
    instructions = data.setdefault("instructions", [])
    if remove:
        if INSTRUCTION_ENTRY in instructions:
            instructions.remove(INSTRUCTION_ENTRY)
            changed.append("rule unregistered")
    elif with_rule and INSTRUCTION_ENTRY not in instructions:
        instructions.append(INSTRUCTION_ENTRY)
        changed.append("rule registered")

    plugins = data.setdefault("plugin", [])
    perm = data.setdefault("permission", {}).setdefault("bash", {})
    wanted = dict(DUMP_RULES)
    wanted.update(file_rules())

    if remove:
        if PLUGIN_ENTRY in plugins:
            plugins.remove(PLUGIN_ENTRY)
            changed.append("plugin unregistered")
        gone = 0
        for key, value in wanted.items():
            if perm.get(key) == value:
                del perm[key]
                gone += 1
        if gone:
            changed.append(f"{gone} permission rules removed")
        return changed

    if PLUGIN_ENTRY not in plugins:
        plugins.append(PLUGIN_ENTRY)
        changed.append("plugin registered")

    # An explicit allow for a dump command is the hole this tool exists to
    # close, so it is overwritten rather than preserved.
    added = 0
    for key, value in wanted.items():
        if perm.get(key) != value:
            perm[key] = value
            added += 1
    if added:
        changed.append(f"{added} permission rules written")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("ide", choices=sorted(CONFIG))
    ap.add_argument("--guard", default="", help="absolute path to the secrets-guard CLI")
    ap.add_argument("--redact", default="",
                    help="absolute path to the secrets-redact CLI (Claude Code only)")
    ap.add_argument("--remove", action="store_true")
    ap.add_argument("--with-rule", action="store_true",
                    help="also register the rule file (opencode needs it listed)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--print", dest="print_wiring", action="store_true",
                    help="print the wiring as JSON and change nothing "
                         "(for a config this patcher must not rewrite)")
    args = ap.parse_args()

    if args.print_wiring:
        wanted = {}
        if args.ide == "opencode":
            patch_opencode(wanted, remove=False, with_rule=args.with_rule)
        else:
            patch_hooks(args.ide, wanted, args.guard or "<path>/secrets-guard", False)
            patch_post_hooks(args.ide, wanted,
                             redact_command(args.ide, args.redact or "<path>/secrets-redact"),
                             False)
            patch_failure_hooks(args.ide, wanted, args.redact or "<path>/secrets-redact", False)
            patch_notice_hooks(args.ide, wanted, args.redact or "<path>/secrets-redact", False)
        print(json.dumps(wanted, indent=2, ensure_ascii=False))
        return 0

    path = CONFIG[args.ide]
    if not os.path.exists(path):
        print(f"    config not found: {path}", file=sys.stderr)
        return 3

    if args.ide in GUARD_MATCHER and not args.guard and not args.remove:
        print("    --guard is required", file=sys.stderr)
        return 1

    try:
        data = load(path)
    except json.JSONDecodeError as exc:
        print(f"    {path} is not valid JSON ({exc}) — left untouched", file=sys.stderr)
        return 1

    # Valid JSON that is not an object: every patcher below starts with
    # `data.setdefault`, so a list or a bare string reached the user as an
    # AttributeError traceback instead of a sentence.
    if not isinstance(data, dict):
        print(f"    {path} is not a JSON object — left untouched", file=sys.stderr)
        return 1

    if args.ide == "opencode":
        changed = patch_opencode(data, args.remove, args.with_rule)
    else:
        changed = patch_hooks(args.ide, data, args.guard, args.remove)
        if args.ide in (REDACT_IDES | WARN_IDES) and (args.redact or args.remove):
            command = redact_command(args.ide, args.redact) if args.redact else ""
            changed += patch_post_hooks(args.ide, data, command, args.remove)
            # Always --warn-only there, whatever this assistant does on the
            # success path: the failure event has no field that replaces a
            # result, so `args.redact` unadorned would be a hook that produces
            # a reply the harness throws away.
            changed += patch_failure_hooks(
                args.ide, data, args.redact or "", args.remove)
            changed += patch_notice_hooks(
                args.ide, data, args.redact or "", args.remove)

    if not changed:
        print("    = already current")
        return 0

    # A JSONC file that actually carries comments cannot be written back: the
    # dump would drop every one of them, and a mangled configuration is worse
    # than an unwired one. Reading it is still worth doing — that is how
    # "already current" above can answer truthfully — but a change has to be
    # made by hand or the file renamed.
    if path.endswith(".jsonc") and has_comments(path):
        print(f"    {path} carries comments; rewriting it would drop them",
              file=sys.stderr)
        print("    rename it to opencode.json (Opencode reads both) and re-run,",
              file=sys.stderr)
        print(f"    or merge this in by hand: {sys.argv[0]} {args.ide} --print",
              file=sys.stderr)
        for line in changed:
            print(f"    would have: {line}", file=sys.stderr)
        return 1

    save(path, data, args.dry_run)
    prefix = "    would " if args.dry_run else "    "
    for line in changed:
        print(f"{prefix}{line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
