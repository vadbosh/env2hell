#!/usr/bin/env bash
# release.sh — keep the changelog, the tag and the installed copies in agreement.
#
#   ./release.sh check     verify they agree; exit 3 if they do not
#   ./release.sh tag       create the missing tag for the current version
#
# Two things drift here on their own. The version: CHANGELOG.md is what a reader
# looks at, a git tag is what `git checkout v0.1.0` needs, and a release where
# they disagree is worse than an untagged one, because each looks authoritative.
# And the copies: install.sh writes the guard, the masking command and the house
# rule into places outside this checkout, and a copy that is behind is the copy
# that actually runs.
#
# ENV2HELL_MIRRORS is a colon-separated list of FILES holding a copy of
# something this repository ships — the installed commands, the rule as it lands
# in each assistant, a config canon that redistributes it. Machine-specific
# paths belong to the machine, so nothing is hardcoded here:
#
#   ENV2HELL_MIRRORS="$HOME/.local/bin/secrets-guard:$HOME/.local/bin/safe-env"
#   ENV2HELL_MIRRORS="$ENV2HELL_MIRRORS:$HOME/.claude/rules/secrets-hygiene.md"
#   ./release.sh check
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SRC/CHANGELOG.md"

# The newest section heading in the changelog is the current version. There is
# no version string in the shipped files themselves, so this is the only record.
version() {
	sed -n 's/^## \([0-9][0-9.]*\).*/\1/p' "$LOG" | head -1
}

# The file in this checkout that a mirror is a copy of, matched by name. The
# shipped names are unique, which is what makes matching by basename honest
# here rather than merely convenient.
source_for() {
	case "$(basename "$1")" in
		secrets-guard) printf '%s\n' "$SRC/bin/secrets-guard" ;;
		secrets-guard.ps1) printf '%s\n' "$SRC/bin/secrets-guard.ps1" ;;
		safe-env) printf '%s\n' "$SRC/bin/safe-env" ;;
		safe-env.ps1) printf '%s\n' "$SRC/bin/safe-env.ps1" ;;
		secrets-hygiene.md) printf '%s\n' "$SRC/rules/secrets-hygiene.md" ;;
		*) return 1 ;;
	esac
}

check_mirrors() {
	local f src behind=0 n=0 unknown=0
	while read -r f; do
		[ -n "$f" ] || continue
		if ! src="$(source_for "$f")"; then
			echo "  mirror ignored:    ${f/#$HOME/\~} — no file of that name is shipped"
			unknown=$((unknown + 1))
			continue
		fi
		if [ ! -e "$f" ]; then
			echo "  mirror missing:    ${f/#$HOME/\~} — listed but not there"
			behind=$((behind + 1))
			continue
		fi
		n=$((n + 1))
		if ! cmp -s "$src" "$f"; then
			[ "$behind" -eq 0 ] && echo "  mirrors behind:"
			behind=$((behind + 1))
			echo "    ${f/#$HOME/\~}  differs from ${src#"$SRC"/}"
		fi
	done <<-EOF
	$(printf '%s\n' "${ENV2HELL_MIRRORS:-}" | tr ':' '\n')
	EOF

	if [ "$behind" -gt 0 ]; then
		echo "                     ./install.sh refreshes what it installed;"
		echo "                     anything else is refreshed by whoever owns it"
		return 1
	fi
	if [ "$n" -eq 0 ] && [ "$unknown" -eq 0 ]; then
		echo "  mirrors:           none configured — set ENV2HELL_MIRRORS to compare copies"
		return 0
	fi
	echo "  mirrors:           $n, all identical to this checkout"
}

check() {
	local v problems=0
	v="$(version)"
	if [ -z "$v" ]; then
		echo "no version heading in CHANGELOG.md" >&2
		return 3
	fi
	echo "  changelog version: $v"

	if git -C "$SRC" rev-parse "v$v" >/dev/null 2>&1; then
		echo "  git tag:           v$v exists"
		# Commits after the tag are the normal state between releases, not a
		# fault — reported, never counted as a problem. A check that is always
		# red stops being read, which costs more than what it was watching for.
		local ahead
		ahead="$(git -C "$SRC" rev-list --count "v$v..HEAD")"
		if [ "$ahead" -gt 0 ]; then
			echo "  unreleased:        $ahead commit(s) since v$v — bump the version to release them"
		else
			echo "  unreleased:        nothing since v$v"
		fi
	else
		echo "  git tag:           v$v is missing — ./release.sh tag creates it"
		problems=$((problems + 1))
	fi

	check_mirrors || problems=$((problems + 1))

	if [ "$problems" -eq 0 ]; then
		echo "  everything agrees on $v"
		return 0
	fi
	return 3
}

make_tag() {
	local v
	v="$(version)"
	[ -n "$v" ] || { echo "no version heading in CHANGELOG.md" >&2; exit 3; }

	if git -C "$SRC" rev-parse "v$v" >/dev/null 2>&1; then
		echo "v$v already exists" >&2
		exit 3
	fi
	if [ -n "$(git -C "$SRC" status --porcelain)" ]; then
		echo "working tree is dirty — commit first, so the tag points at something real" >&2
		exit 3
	fi

	git -C "$SRC" tag -a "v$v" -m "v$v"
	echo "created v$v at $(git -C "$SRC" rev-parse --short HEAD)"
	echo "push it with:  git push origin v$v"
}

case "${1:-check}" in
	check) check ;;
	tag) make_tag ;;
	-h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
	*) echo "usage: $0 [check|tag]" >&2; exit 2 ;;
esac
