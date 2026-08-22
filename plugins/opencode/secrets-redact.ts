import type { Plugin } from "@opencode-ai/plugin"

// secrets-redact OpenCode plugin — masks a secret that a shell command printed,
// before the model reads the result.
//
// secrets-guard is the other half and runs earlier: it refuses a command that
// would *read* a secret. It cannot help with a command that *prints* one,
// because at `tool.execute.before` there is nothing to inspect —
//
//     croc send report.pdf
//
// and the password appears only in the answer, where croc echoes the options a
// receiver will need.
//
// Thin delegating plugin, same shape as secrets-guard.ts: the policy lives in
// the `secrets-redact` CLI and is shared with the Claude Code hook, so the two
// assistants cannot drift apart. `--filter` is the plain-text mode — text in,
// masked text out, exit 0 when something changed. Requires `secrets-redact` in
// PATH.
//
// Only `bash` is covered, matching the Claude Code hook's `Bash` matcher and
// the guard above. A tool that reads a file is the guard's business; a tool
// that runs a program is this one's.

export const SecretsRedactPlugin: Plugin = async ({ $ }) => {
  try {
    await $`which secrets-redact`.quiet()
  } catch {
    console.warn("[secrets-redact] binary not found in PATH — plugin disabled")
    return {}
  }

  // Hooks receive an immutable input and a mutable output, so the masked text
  // is written back onto `output` in place. Exit 1 means nothing matched —
  // then the string is left alone rather than reassigned to itself.
  const mask = async (text: unknown): Promise<string | undefined> => {
    if (typeof text !== "string" || text === "") return undefined
    const res = await $`printf %s ${text} | secrets-redact --filter`.quiet().nothrow()
    if (res.exitCode !== 0) return undefined
    return String(res.stdout)
  }

  return {
    "tool.execute.after": async (input, output) => {
      const tool = String(input?.tool ?? "").toLowerCase()
      if (tool !== "bash") return

      const masked = await mask(output?.output)
      if (masked !== undefined) output.output = masked

      // The bash tool also reports the streams separately in its metadata, and
      // a value masked in one place but not the other is not masked at all.
      const meta = output?.metadata as Record<string, unknown> | undefined
      if (!meta || typeof meta !== "object") return
      for (const field of ["stdout", "stderr", "output"]) {
        const maskedField = await mask(meta[field])
        if (maskedField !== undefined) meta[field] = maskedField
      }
    },
  }
}
