import type { Plugin } from "@opencode-ai/plugin"

// secrets-guard OpenCode plugin — blocks shell commands that would dump secrets
// (API keys / tokens) into the session transcript: bare env/printenv/export -p/
// set/declare/history, and reads of dotfiles, .env, private keys, /proc/*/environ.
//
// Thin delegating plugin: the decision policy lives in the `secrets-guard` CLI
// (single source of truth, shared with the Claude Code hook and Codex).
// Same pattern as read-guard.ts. Finds the CLI on PATH, or at the install
// directory when a plugin shell does not carry it (see below).
//
// This is the second layer. The first is `permission.bash` in opencode.json,
// which denies the common spellings declaratively; the plugin catches what
// prefix matching cannot — pipes (`env | grep`), wrappers (`rtk env`), and
// compound commands (`a && env`).

export const SecretsGuardPlugin: Plugin = async ({ $ }) => {
  // Resolve once, and fall back to the install directory.
  //
  // PATH is the trap. A plugin shell does not read the login profile, so the
  // directory the installer writes to — ~/.local/bin by default — need not be
  // on PATH at all. Measured on a machine where the guard was installed and
  // working: a bare environment carried /usr/local/sbin:/usr/local/bin:
  // /usr/sbin:/usr/bin:/sbin:/bin and nothing else.
  //
  // On `which` alone the plugin then disabled itself with a console.warn
  // nobody reads, leaving a guard that looks installed and enforces nothing.
  // For a secrets guard that failure is worse than not installing it: the
  // absence would at least be visible.
  const fallback = `${process.env.HOME ?? ""}/.local/bin/secrets-guard`
  let guard = "secrets-guard"
  try {
    await $`which secrets-guard`.quiet()
  } catch {
    const probe = await $`test -x ${fallback}`.quiet().nothrow()
    if (probe.exitCode !== 0) {
      console.warn(`[secrets-guard] not found in PATH nor at ${fallback} — plugin disabled`)
      return {}
    }
    guard = fallback
  }

  return {
    "tool.execute.before": async (input, output) => {
      const tool = String(input?.tool ?? "").toLowerCase()
      if (tool !== "bash") return
      const args = output?.args as Record<string, unknown> | undefined
      if (!args || typeof args !== "object") return

      const command = args.command as unknown
      if (typeof command !== "string" || !command) return

      // The CLI reads the Claude Code hook payload shape on stdin.
      const payload = JSON.stringify({ tool_input: { command } })
      // Single-value interpolation only (same safe pattern as read-guard.ts).
      const res = await $`printf %s ${payload} | ${guard}`.quiet().nothrow()

      if (res.exitCode === 2) {
        const reason = String(res.stderr).trim()
        // Throwing aborts the tool call; the message is surfaced to the agent.
        throw new Error(reason || "secrets-guard: blocked a command that would leak secrets.")
      }
    },
  }
}
