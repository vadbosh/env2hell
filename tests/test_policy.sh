#!/usr/bin/env bash
# tests/test_policy.sh — two lists, four implementations, one question each.
#
#   bash tests/test_policy.sh
#
# The paths treated as credential stores live in four places: SECRET_PATHS in
# bin/secrets-guard, $secrets in bin/secrets-guard.ps1, SECRET_FILES in
# lib/patch_config.py and $SecretFiles in install.ps1 — the last two become
# Opencode's permission.bash rules. The first two are regular expressions and
# the others are globs, so they cannot be diffed as text. They can be asked the
# same question.
#
# The credential NAMES are the second such list, in four more places, and the
# second half of this file asks those.
#
# Why this exists: on 2026-09-17 `cat server.key`, `cat credentials.json` and
# `cat secrets.yaml` were denied by Opencode and allowed by Claude Code and
# Codex, on the same machine, with nothing anywhere saying the two differed.
#
# The list below is the policy. Adding a store means adding one line here and
# then making all three sides agree.
#
# Nothing here writes outside its own temporary directory.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$SRC/bin/secrets-guard"
PORT="$SRC/bin/secrets-guard.ps1"
PATCH="$SRC/lib/patch_config.py"

for f in "$GUARD" "$PORT" "$PATCH"; do
    [ -e "$f" ] || { echo "not found: $f" >&2; exit 2; }
done

pass=0
fail=0
ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "${tmp:?}"' EXIT

# deny <path>   — every implementation must refuse to print this file
# allow <path>  — every implementation must let it through, on purpose
cat > "$tmp/stores.txt" <<'STORES'
deny  ~/.env
deny  ~/.aws/credentials
deny  ~/.docker/config.json
deny  ~/.kube/config
deny  ~/.azure/msal_token_cache.json
deny  ~/.netrc
deny  ~/.pgpass
deny  ~/.npmrc
deny  ~/.pypirc
deny  ~/.my.cnf
deny  ~/.git-credentials
deny  ~/.ssh/id_rsa
deny  ~/.ssh/id_ed25519
deny  ~/server.pem
deny  ~/server.key
deny  ~/.config/gh/hosts.yml
deny  ~/.terraformrc
deny  ~/.terraform.d/credentials.tfrc.json
deny  ~/.config/gcloud/credentials.db
deny  ~/.config/gcloud/application_default_credentials.json
deny  ~/.cargo/credentials.toml
deny  ~/.gem/credentials
deny  ~/.m2/settings.xml
deny  ~/.m2/settings-security.xml
deny  ~/.config/rclone/rclone.conf
deny  ~/.rclone.conf
deny  ~/.vault-token
deny  ~/.databrickscfg
deny  ~/.snowflake/config
deny  ~/.config/containers/auth.json
deny  ~/.config/helm/registry/config.json
allow ~/.ssh/config
allow ~/README.md
allow ~/.env.example
allow ~/docker-compose.yml
STORES
# Not in the list above, and that is the decision: `*credentials*` and
# `*secrets*` are enforced by Opencode alone. As a hard deny in the hooks they
# would refuse `cat credentials-design.md` and `cat notes-about-secrets.md`,
# which is the A7 failure in a new place. The table in docs/patterns.md says
# which engine enforces which row.
#
# The reader below takes two fields per line, so a comment inside the heredoc
# would arrive as a case with `#` for a verb.

# ── the two hooks: ask them ─────────────────────────────────────────────────
# The port goes through tests/pwsh_batch.ps1 — one pwsh process for the whole
# list rather than one per path, which is a second of startup either way instead
# of thirty. tests/test_parity_guard.sh is what proves the batched route agrees
# with a plain `pwsh -File` run; this file assumes it.
have_pwsh=0
command -v pwsh >/dev/null 2>&1 && have_pwsh=1
BATCH="$SRC/tests/pwsh_batch.ps1"
[ -e "$BATCH" ] || { echo "not found: $BATCH" >&2; exit 2; }

labels=()
wants=()
: > "$tmp/payloads.txt"
while read -r verb path; do
    [ -z "${verb:-}" ] && continue
    labels+=("$verb $path")
    if [ "$verb" = allow ]; then wants+=(0); else wants+=(2); fi
    # shellcheck disable=SC2016
    printf 'cat %s' "$path" | python3 -c \
        'import json,sys; print(json.dumps({"tool_input":{"command":sys.stdin.read()}}))' \
        >> "$tmp/payloads.txt"
done < "$tmp/stores.txt"

posix_rc=()
while IFS= read -r p; do
    [ -z "$p" ] && continue
    printf '%s' "$p" | "$GUARD" >/dev/null 2>&1
    posix_rc+=($?)
done < "$tmp/payloads.txt"

port_rc=()
if [ "$have_pwsh" = 1 ]; then
    mapfile -t port_rc < <(pwsh -NoProfile -File "$BATCH" "$PORT" "$tmp/payloads.txt" 2>/dev/null)
fi

for i in "${!labels[@]}"; do
    want="${wants[$i]}"
    got="${posix_rc[$i]:-<none>}"
    if [ "$got" = "$want" ]; then
        ok "posix guard: ${labels[$i]}"
    else
        no "posix guard: ${labels[$i]}" "exit=$got, wanted $want"
    fi

    if [ "$have_pwsh" = 1 ]; then
        got="${port_rc[$i]:-<none>}"
        if [ "$got" = "$want" ]; then
            ok "port: ${labels[$i]}"
        else
            no "port: ${labels[$i]}" "exit=$got, wanted $want"
        fi
    fi
done

[ "$have_pwsh" = 1 ] || echo "  (pwsh is not installed — the port was not asked)"

# ── the installer's list: ask it the same question ──────────────────────────
# file_rules() is "<reader> <glob>": deny, so a store is covered when some glob
# matches the path. Checked against both the ~ form and an expanded one, because
# the list carries both spellings.
# shellcheck disable=SC2016
python3 - "$PATCH" "$tmp/stores.txt" <<'PY' > "$tmp/patch.out" 2>&1
import fnmatch, runpy, sys

mod = runpy.run_path(sys.argv[1])
rules = mod["file_rules"]()
deny = sorted({r.split(" ", 1)[1] for r, a in rules.items() if a == "deny"})
allow = sorted({r.split(" ", 1)[1] for r, a in rules.items() if a == "allow"})

def covered(path: str) -> bool:
    """Denied by the glob list, with a more specific allow able to win.

    Opencode resolves the more specific pattern first — the same assumption
    `printenv *`: ask already rests on, beside `printenv`: deny.
    """
    forms = {path, path.replace("~", "/home/u", 1), path.replace("~/", "", 1)}
    if any(fnmatch.fnmatch(f, g) for f in forms for g in allow):
        return False
    return any(fnmatch.fnmatch(f, g) for f in forms for g in deny)

for line in open(sys.argv[2]):
    line = line.strip()
    if not line:
        continue
    verb, path = line.split(None, 1)
    want = verb == "deny"
    got = covered(path)
    print(f"{'ok' if got == want else 'FAIL'}\t{verb} {path}")
PY

while IFS=$'\t' read -r status label; do
    [ -z "${status:-}" ] && continue
    if [ "$status" = ok ]; then
        ok "patch_config SECRET_FILES: $label"
    else
        no "patch_config SECRET_FILES: $label" "the glob list disagrees with the hooks"
    fi
done < "$tmp/patch.out"

# ── the other list that lives in four places: credential NAMES ──────────────
# CRED_VAR in bin/secrets-guard, $credVar in its port, CRED in bin/safe-env and
# $credVar in its port. The guard denies printing such a variable; safe-env
# masks its value. Different acts, one list — and it had the same defect in all
# four at once, because PASS was matched as a substring: $passed, $bypass_cache
# and PASSENGER_ROOT were all treated as credentials.
#
# `mask` means safe-env must hide the value and the guard must deny `echo`;
# `show` means neither.
cat > "$tmp/names.txt" <<'NAMES'
mask DB_PASSWORD
mask db_password
mask MY_PASSWORD
mask DB_PASS
mask PASS_FILE
mask GITHUB_TOKEN
mask JIRA_API_TOKEN
mask AWS_SECRET_ACCESS_KEY
mask HW_SECRET_KEY
mask CLIENT_SECRET
mask MY_CREDENTIAL
show PASS
show PASSED
show BYPASS_CACHE
show COMPASS_DIR
show PASSENGER_ROOT
show TOKENIZERS_PARALLELISM
show HOME_DIR
show ANTHROPIC_MODEL
NAMES

# One value for every name: long enough to clear the eight-character floor,
# shapeless enough that only the name can decide it. Invented.
NAME_VALUE='correct-horse-battery'

# The guard: `echo "$NAME"` — denied for a credential name, allowed otherwise.
labels=(); wants=()
: > "$tmp/name-payloads.txt"
while read -r verb name; do
    [ -z "${verb:-}" ] && continue
    labels+=("$verb \$$name")
    if [ "$verb" = mask ]; then wants+=(2); else wants+=(0); fi
    # shellcheck disable=SC2016
    printf 'echo "$%s"' "$name" | python3 -c \
        'import json,sys; print(json.dumps({"tool_input":{"command":sys.stdin.read()}}))' \
        >> "$tmp/name-payloads.txt"
done < "$tmp/names.txt"

posix_rc=()
while IFS= read -r p; do
    [ -z "$p" ] && continue
    printf '%s' "$p" | "$GUARD" >/dev/null 2>&1
    posix_rc+=($?)
done < "$tmp/name-payloads.txt"
port_rc=()
if [ "$have_pwsh" = 1 ]; then
    mapfile -t port_rc < <(pwsh -NoProfile -File "$BATCH" "$PORT" "$tmp/name-payloads.txt" 2>/dev/null)
fi

for i in "${!labels[@]}"; do
    want="${wants[$i]}"
    got="${posix_rc[$i]:-<none>}"
    if [ "$got" = "$want" ]; then
        ok "posix guard: ${labels[$i]}"
    else
        no "posix guard: ${labels[$i]}" "exit=$got, wanted $want"
    fi
    if [ "$have_pwsh" = 1 ]; then
        got="${port_rc[$i]:-<none>}"
        if [ "$got" = "$want" ]; then
            ok "port: ${labels[$i]}"
        else
            no "port: ${labels[$i]}" "exit=$got, wanted $want"
        fi
    fi
done

# safe-env: the same names, one process per implementation.
SAFE="$SRC/bin/safe-env"
SAFE_PORT="$SRC/bin/safe-env.ps1"
env_args=()
while read -r _verb name; do
    [ -z "${name:-}" ] && continue
    env_args+=("$name=$NAME_VALUE")
done < "$tmp/names.txt"
env -i "${env_args[@]}" "$SAFE" 2>/dev/null | sort > "$tmp/safe-posix.txt"

if [ "$have_pwsh" = 1 ]; then
    {
        echo '$ErrorActionPreference = "Stop"'
        while read -r _verb name; do
            [ -z "${name:-}" ] && continue
            printf '$env:%s = %s\n' "$name" "'$NAME_VALUE'"
        done < "$tmp/names.txt"
        printf '& "%s"\n' "$SAFE_PORT"
    } > "$tmp/safe-driver.ps1"
    pwsh -NoProfile -File "$tmp/safe-driver.ps1" 2>/dev/null | sort > "$tmp/safe-port.txt"
fi

while read -r verb name; do
    [ -z "${verb:-}" ] && continue
    for impl in posix port; do
        [ "$impl" = port ] && [ "$have_pwsh" != 1 ] && continue
        out="$tmp/safe-$impl.txt"
        line="$(grep "^$name=" "$out" || true)"
        masked=no
        case "$line" in *"<REDACTED:"*) masked=yes ;; esac
        wantm=no
        [ "$verb" = mask ] && wantm=yes
        if [ -z "$line" ]; then
            no "safe-env $impl: $verb $name" "no line at all"
        elif [ "$masked" = "$wantm" ]; then
            ok "safe-env $impl: $verb $name"
        else
            no "safe-env $impl: $verb $name" "masked=$masked, wanted $wantm"
        fi
    done
done < "$tmp/names.txt"

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
