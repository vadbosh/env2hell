#!/usr/bin/env bash
# tests/test_policy.sh — one policy, three implementations, one list.
#
#   bash tests/test_policy.sh
#
# The paths treated as credential stores live in three places: SECRET_PATHS in
# bin/secrets-guard, $secrets in bin/secrets-guard.ps1, and SECRET_FILES in
# lib/patch_config.py, which becomes Opencode's permission.bash deny rules.
# The first two are regular expressions and the third is a list of globs, so
# they cannot be diffed as text. They can be asked the same question.
#
# Why this exists: on 2026-09-17 `cat server.key`, `cat credentials.json` and
# `cat secrets.yaml` were denied by Opencode and allowed by Claude Code and
# Codex, on the same machine, with nothing anywhere saying the two differed.
# review-2026-09-17-secrets-guard.md items A9 and A11.
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

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
