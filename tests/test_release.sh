#!/usr/bin/env bash
# tests/test_release.sh — the release check has to be able to see what ships.
#
#   bash tests/test_release.sh
#
# release.sh compares the changelog, the git tag and the installed copies. It
# matches a copy to its source by basename, from a list written by hand — and
# that list is what goes stale: secrets-redact was shipped on 2026-09-14 and
# still unknown to it on 2026-09-16, so the check answered "no file of that
# name is shipped" about the file this repository changes most, and reported
# zero mirrors as if they all agreed.
#
# Everything here runs against a copy of the checkout in a temporary directory,
# with its own git repository. The real one is never tagged or touched.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -e "$SRC/release.sh" ] || { echo "release.sh not found" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "these tests need git" >&2; exit 2; }

pass=0
fail=0
ok () { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
no () { fail=$((fail + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "${tmp:?}"' EXIT

# A checkout of its own: the shipped files, the changelog, and a commit to tag.
repo="$tmp/repo"
mkdir -p "$repo/bin" "$repo/rules"
cp "$SRC"/bin/* "$repo/bin/"
cp "$SRC"/rules/*.md "$repo/rules/"
cp "$SRC/release.sh" "$repo/"
printf '# Changelog\n\n## 9.9.9 — 2026-09-16\n\n- a release that exists only here\n' \
    > "$repo/CHANGELOG.md"
git -C "$repo" init -q
git -C "$repo" -c user.email=t@t -c user.name=t add -A
git -C "$repo" -c user.email=t@t -c user.name=t commit -qm "the state under test"

run_check () {                  # run_check [mirrors] — prints output, returns rc
    ENV2HELL_MIRRORS="${1:-}" bash "$repo/release.sh" check 2>&1
}

# ── the version, and the tag that is not there yet ──────────────────────────
out="$(run_check)"; rc=$?
case "$out" in
    *"changelog version: 9.9.9"*) ok "the version comes from the changelog" ;;
    *) no "the version comes from the changelog" "$out" ;;
esac
if [ "$rc" -eq 3 ]; then
    ok "a missing tag is a problem, and 3 says so"
else
    no "a missing tag is a problem, and 3 says so" "exit $rc"
fi

# ── every shipped file must be a name the mirror check knows ────────────────
# The list in source_for is compared against what install.sh actually installs,
# because that is the pair that drifted.
# shellcheck disable=SC2016  # $SRC belongs to install.sh's text, matched here
                            # literally; expanding it would search for a path
shipped="$(grep -oE 'install_file "\$SRC/(bin|rules)/[^"]+"' "$SRC/install.sh" |
           sed 's|.*/||; s|"$||' | sort -u)"
unknown=""
for name in $shipped; do
    cp "$repo/bin/$name" "$tmp/$name" 2>/dev/null || cp "$repo/rules/$name" "$tmp/$name" 2>/dev/null || continue
    if run_check "$tmp/$name" | grep -q 'mirror ignored'; then
        unknown="$unknown $name"
    fi
done
if [ -z "$unknown" ]; then
    ok "every file install.sh ships is a name release.sh knows"
else
    no "every file install.sh ships is a name release.sh knows" \
       "unknown to source_for:$unknown"
fi

# ── a copy that is behind has to be reported ────────────────────────────────
cp "$repo/bin/secrets-redact" "$tmp/mirror-secrets-redact-ok"
mv "$tmp/mirror-secrets-redact-ok" "$tmp/secrets-redact"
out="$(run_check "$tmp/secrets-redact")"
case "$out" in
    *"all identical to this checkout"*) ok "an up-to-date copy is reported as identical" ;;
    *) no "an up-to-date copy is reported as identical" "$out" ;;
esac

printf '# changed\n' >> "$tmp/secrets-redact"
out="$(run_check "$tmp/secrets-redact")"
case "$out" in
    *"mirrors behind"*) ok "a copy that drifted is reported as behind" ;;
    *) no "a copy that drifted is reported as behind" "$out" ;;
esac

# ── a path nobody ships is not a pass ───────────────────────────────────────
: > "$tmp/not-ours"
out="$(run_check "$tmp/not-ours")"
case "$out" in
    *"none recognised"*) ok "a path that matches nothing does not read as agreement" ;;
    *) no "a path that matches nothing does not read as agreement" "$out" ;;
esac

# ── tag, in the copy, never in the real repository ──────────────────────────
if bash "$repo/release.sh" tag >"$tmp/tag.out" 2>&1; then
    ok "tag creates the missing tag"
else
    no "tag creates the missing tag" "$(tail -3 "$tmp/tag.out")"
fi
if git -C "$repo" rev-parse v9.9.9 >/dev/null 2>&1; then
    ok "the tag is really there afterwards"
else
    no "the tag is really there afterwards" "v9.9.9 not found"
fi
if git -C "$SRC" rev-parse v9.9.9 >/dev/null 2>&1; then
    no "the real repository is untouched" "v9.9.9 landed in $SRC"
else
    ok "the real repository is untouched"
fi

printf '\npassed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
