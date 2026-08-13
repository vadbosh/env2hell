import type { Plugin } from "@opencode-ai/plugin"

// secrets-guard OpenCode plugin — blocks shell commands that would dump secrets
// (API keys / tokens) into the session transcript: bare env/printenv/export -p/
// set/declare/history, and reads of dotfiles, .env, private keys, /proc/*/environ.
//
// Thin delegating plugin: the decision policy lives in the `secrets-guard` CLI
// (single source of truth, shared with the Claude Code hook and Codex).
// Same pattern as read-guard.ts. Requires `secrets-guard` in PATH.
//
// This is the second layer. The first is `permission.bash` in opencode.json,
// which denies the common spellings declaratively; the plugin catches what
// prefix matching cannot — pipes (`env | grep`), wrappers (`rtk env`), and
// compound commands (`a && env`).

export const SecretsGuardPlugin: Plugin = async ({ $ }) => {
  try {
    await $`which secrets-guard`.quiet()
  } catch {
    console.warn("[secrets-guard] binary not found in PATH — plugin disabled")
    return {}
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
      const res = await $`printf %s ${payload} | secrets-guard`.quiet().nothrow()

      if (res.exitCode === 2) {
        const reason = String(res.stderr).trim()
        // Throwing aborts the tool call; the message is surfaced to the agent.
        throw new Error(reason || "secrets-guard: blocked a command that would leak secrets.")
      }
    },
  }
}
