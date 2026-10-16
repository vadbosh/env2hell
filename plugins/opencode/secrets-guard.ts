import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { delimiter, join } from "node:path"
import type { Plugin } from "@opencode-ai/plugin"

// secrets-guard OpenCode plugin — blocks shell commands that would dump secrets
// (API keys / tokens) into the session transcript: bare env/printenv/export -p/
// set/declare/history, and reads of dotfiles, .env, private keys, /proc/*/environ.
//
// Thin delegating plugin: the decision policy lives in the `secrets-guard` CLI
// (single source of truth, shared with the Claude Code hook and Codex).
// Same pattern as read-guard.ts.
//
// This is the second layer. The first is `permission.bash` in opencode.json,
// which denies the common spellings declaratively; the plugin catches what
// prefix matching cannot — pipes (`env | grep`), wrappers (`rtk env`), and
// compound commands (`a && env`).
//
// Dual-shape, like rtk.ts: OpenCode 2.x loads the default export and calls
// setup(); 1.x calls server(). The 2.x loader accepts only that default object —
// the old `export const X: Plugin` alone fails with "Plugin must export a
// default definition", which left this guard dead. The 2.x tools are `shell`,
// `read` (argument `path`); the 1.x ones are `bash`, `read` (`filePath`).
// No Bun `$`: node:child_process runs under both.

// PATH is the trap. A plugin shell does not read the login profile, so the
// directory the installer writes to — ~/.local/bin by default — need not be on
// PATH at all. On a PATH-only lookup the plugin would disable itself with a
// console.warn nobody reads, leaving a guard that looks installed and enforces
// nothing. For a secrets guard that failure is worse than not installing it.
function findBin(name: string): string | null {
  const dirs = [...(process.env.PATH ?? "").split(delimiter), join(process.env.HOME ?? "/root", ".local/bin")]
  for (const d of dirs) if (d && existsSync(join(d, name))) return join(d, name)
  return null
}

function run(bin: string, stdin: string, timeout = 10000): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve) => {
    const p = spawn(bin, [], { stdio: ["pipe", "ignore", "pipe"] })
    let stderr = ""
    const t = setTimeout(() => p.kill(), timeout)
    p.stderr.on("data", (d) => (stderr += d))
    p.on("error", () => (clearTimeout(t), resolve({ code: 127, stderr })))
    p.on("close", (c) => (clearTimeout(t), resolve({ code: c ?? 1, stderr })))
    p.stdin.on("error", () => {})
    p.stdin.end(stdin)
  })
}

// Throws when the CLI refuses; the message is surfaced to the agent.
async function guard(bin: string, tool: unknown, args: any): Promise<void> {
  const t = String(tool ?? "").toLowerCase()
  if (t !== "bash" && t !== "shell" && t !== "read") return
  if (!args || typeof args !== "object") return

  // The CLI reads the Claude Code hook payload shape on stdin. A read is judged
  // by its path alone (a known credential store is denied), so it is sent in
  // the shape Claude Code's Read tool uses.
  let payload: string
  if (t === "read") {
    const filePath = args.path ?? args.filePath
    if (typeof filePath !== "string" || !filePath) return
    payload = JSON.stringify({ tool_name: "Read", tool_input: { file_path: filePath } })
  } else {
    const command = args.command
    if (typeof command !== "string" || !command) return
    payload = JSON.stringify({ tool_input: { command } })
  }
  const res = await run(bin, payload)
  if (res.code === 2) throw new Error(res.stderr.trim() || "secrets-guard: blocked a command that would leak secrets.")
}

function resolveBin(): string | null {
  const bin = findBin("secrets-guard")
  if (!bin) console.warn("[secrets-guard] not found in PATH nor ~/.local/bin — plugin disabled")
  return bin
}

export const SecretsGuardPlugin: Plugin = async () => {
  const bin = resolveBin()
  if (!bin) return {}
  return {
    "tool.execute.before": async (input: any, output: any) => guard(bin, input?.tool, output?.args),
  }
}

export default {
  id: "secrets-guard",
  async setup(ctx: any) {
    const bin = resolveBin()
    if (!bin) return
    await ctx.tool.hook("execute.before", (e: any) => guard(bin, e?.tool, e?.input))
  },
  server: SecretsGuardPlugin,
}
