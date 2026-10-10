#!/usr/bin/env bash
# run_all.sh — every suite at once, one summary at the end.
#
#   tests/run_all.sh                   every suite, plus the --pwsh halves when
#                                      pwsh is installed
#   tests/run_all.sh guard redact      only the suites whose name contains one
#                                      of the words
#   ONLY='UUID|200 KB' tests/run_all.sh redact
#                                      only the cases whose label matches, in
#                                      the suites that support it (guard, redact)
#
# One after another the suites took several minutes, most of it waiting on
# process start-up, and a run was easy to abandon half-way. Each suite already
# works in its own temporary directory, so they run side by side; the slowest
# one sets the time. Logs stay in the directory printed at the end.
#
# At most JOBS suites at once (default: the number of CPUs), the longest first.
# All thirteen at once on four CPUs made the guard's own 10-second size cases
# time out under the port — those cases measure the guard, so the machine has
# to be left free enough for them to mean something.
#
# Exit 0 when every suite reports `failed 0`, 1 when one does not.
# SUITE_TIMEOUT (seconds, default 600) bounds each suite where `timeout` exists.
set -u
cd "$(dirname "$0")/.." || exit 2
logs="$(mktemp -d "${TMPDIR:-/tmp}/env2hell-tests.XXXXXX")"
limit=""
command -v timeout >/dev/null 2>&1 && limit="timeout ${SUITE_TIMEOUT:-600}"

jobs_max="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

# Longest first, by the times measured 2026-10-10; a suite not named here runs
# after them.
order=(parity_guard install guard-pwsh guard parity redact redact-pwsh
       safe_env-pwsh policy parity_safe_env scan release safe_env)
found=()
for f in tests/test_*.sh; do n="${f#tests/test_}"; found+=("${n%.sh}|$f"); done
if command -v pwsh >/dev/null 2>&1; then
    for n in guard redact safe_env; do found+=("$n-pwsh|tests/test_$n.sh --pwsh"); done
fi
all=()
for n in "${order[@]}"; do
    for s in "${found[@]}"; do [ "${s%%|*}" = "$n" ] && all+=("$s"); done
done
for s in "${found[@]}"; do
    known=0
    for n in "${order[@]}"; do [ "${s%%|*}" = "$n" ] && known=1; done
    [ "$known" = 0 ] && all+=("$s")
done

picked=()
for s in "${all[@]}"; do
    [ $# -eq 0 ] && { picked+=("$s"); continue; }
    for w in "$@"; do
        case "${s%%|*}" in *"$w"*) picked+=("$s"); break ;; esac
    done
done
[ ${#picked[@]} -gt 0 ] || { echo "no suite matches: $*" >&2; exit 2; }

start=$(date +%s)
for s in "${picked[@]}"; do
    name="${s%%|*}" cmd="${s#*|}"
    # bash 3.2 has no `wait -n`: poll the running count instead.
    while [ "$(jobs -rp | wc -l)" -ge "$jobs_max" ]; do sleep 0.2; done
    (
        t=$(date +%s)
        # $limit and $cmd are a command plus its flags and have to split.
        # shellcheck disable=SC2086
        $limit bash $cmd > "$logs/$name.log" 2>&1
        echo "$? $(( $(date +%s) - t ))" > "$logs/$name.rc"
    ) &
done
wait

bad=0
for s in "${picked[@]}"; do
    name="${s%%|*}"
    read -r rc secs < "$logs/$name.rc"
    result="$(grep -Eo 'passed [0-9]+, failed [0-9]+' "$logs/$name.log" | tail -n 1)"
    case "$rc:$result" in
        0:*", failed 0") mark="ok  " ;;
        124:*)           mark="FAIL"; result="timed out"; bad=1 ;;
        *)               mark="FAIL"; result="${result:-no result line} (exit $rc)"; bad=1 ;;
    esac
    printf '%s  %-16s %4ss  %s\n' "$mark" "$name" "$secs" "$result"
    [ "$mark" = "FAIL" ] && grep -E '^ *FAIL' "$logs/$name.log" | head -n 5 | sed 's/^/        /'
done
printf '\n%d suites in %ss, %s at a time, logs in %s\n' \
    "${#picked[@]}" "$(( $(date +%s) - start ))" "$jobs_max" "$logs"
exit "$bad"
