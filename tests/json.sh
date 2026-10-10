# shellcheck shell=bash
# json.sh — sourced by the suites: the hook payload for one command string.
#
#   cmd_payload <command-string>   prints {"tool_input":{"command":"…"}}
#
# Built in the shell. A python3 start per case cost about 50 ms, and the guard
# suites build some 800 payloads per run. Quotes, backslashes, newlines, tabs
# and carriage returns are escaped here; a string with any other control
# character goes through jq, which is rare and correct.

cmd_payload () {
    local s="$1"
    case "$s" in
        *[$'\001'-$'\010'$'\013'$'\014'$'\016'-$'\037'$'\177']*)
            jq -cn --arg c "$s" '{tool_input:{command:$c}}'
            return ;;
    esac
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '{"tool_input":{"command":"%s"}}\n' "$s"
}
