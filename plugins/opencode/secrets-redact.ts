import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { delimiter, join } from "node:path"
import type { Plugin } from "@opencode-ai/plugin"

// secrets-redact OpenCode plugin — masks a secret that a shell command printed,
// before the model reads the result.
//
// secrets-guard is the other half and runs earlier: it refuses a command that
// would *read* a secret. It cannot help with a command that *prints* one,
// because at tool.execute.before there is nothing to inspect —
//
//     croc send report.pdf
//
// and the password appears only in the answer, where croc echoes the options a
// receiver will need.
//
// Thin delegating plugin, same shape as secrets-guard.ts: the policy lives in
// the `secrets-redact` CLI and is shared with the Claude Code hook, so the two
// assistants cannot drift apart. `--filter` is the plain-text mode — text in,
// masked text out, exit 0 when something changed, 1 when nothing matched.
//
// Dual-shape, like rtk.ts: OpenCode 2.x calls setup() and the result is
// `event.result` ({content[], output, metadata}); 1.x calls server() and the
// result is `output.output` / `output.metadata`. Among tools only the shell is
// covered (`shell` in 2.x, `bash` in 1.x), matching the Claude Code hook's
// `Bash` matcher and the guard.
//
// A file attached to a prompt with `@` is masked too. 1.x hands it over as a
// synthetic part in chat.message. 2.x reads it in the server itself
// (SessionPrompt.materializeAttachment), so no tool hook sees it, and the
// `prompt` hook runs before it is read. It reaches the model as a text part
// with metadata.attachment in the messages of each request, and the session
// `context` hook may change those messages before they are sent — verified on
// 2.0.30 from the binary and with a request captured at http.request.

// Same PATH trap as in secrets-guard.ts: a plugin shell does not read the login
// profile, so ~/.local/bin need not be on PATH even where the CLI is installed.
function findBin(name: string): string | null {
  const dirs = [...(process.env.PATH ?? "").split(delimiter), join(process.env.HOME ?? "/root", ".local/bin")]
  for (const d of dirs) if (d && existsSync(join(d, name))) return join(d, name)
  return null
}

// Masked text, or undefined when nothing matched or the CLI failed.
function mask(bin: string, text: unknown, timeout = 10000): Promise<string | undefined> {
  if (typeof text !== "string" || text === "") return Promise.resolve(undefined)
  return new Promise((resolve) => {
    const p = spawn(bin, ["--filter"], { stdio: ["pipe", "pipe", "ignore"] })
    let out = ""
    const t = setTimeout(() => p.kill(), timeout)
    p.stdout.on("data", (d) => (out += d))
    p.on("error", () => (clearTimeout(t), resolve(undefined)))
    p.on("close", (c) => (clearTimeout(t), resolve(c === 0 ? out : undefined)))
    p.stdin.on("error", () => {})
    p.stdin.end(text)
  })
}

const isShell = (tool: unknown) => ["bash", "shell"].includes(String(tool ?? "").toLowerCase())

function resolveBin(): string | null {
  const bin = findBin("secrets-redact")
  if (!bin) console.warn("[secrets-redact] not found in PATH nor ~/.local/bin — plugin disabled")
  return bin
}

export const SecretsRedactPlugin: Plugin = async () => {
  const bin = resolveBin()
  if (!bin) return {}
  return {
    // 1.x only: a file attached with `@path` arrives as a synthetic text part
    // that no tool hook sees. Only synthetic parts: what the user typed is
    // theirs to see.
    "chat.message": async (_input: any, output: any) => {
      const parts = output?.parts
      if (!Array.isArray(parts)) return
      for (const part of parts) {
        if (part?.type !== "text" || part?.synthetic !== true) continue
        const m = await mask(bin, part.text)
        if (m !== undefined) part.text = m
      }
    },

    "tool.execute.after": async (input: any, output: any) => {
      if (!isShell(input?.tool)) return
      const masked = await mask(bin, output?.output)
      if (masked !== undefined) output.output = masked

      // The bash tool also reports the streams separately in its metadata, and
      // a value masked in one place but not the other is not masked at all.
      const meta = output?.metadata
      if (!meta || typeof meta !== "object") return
      for (const field of ["stdout", "stderr", "output"]) {
        const m = await mask(bin, meta[field])
        if (m !== undefined) meta[field] = m
      }
    },
  }
}

export default {
  id: "secrets-redact",
  async setup(ctx: any) {
    const bin = resolveBin()
    if (!bin) return

    // Every request carries the whole history, attachments included, so the
    // same text comes back on each turn: one CLI run per distinct attachment.
    const done = new Map<string, string | undefined>()
    const cached = async (text: string) => {
      if (!done.has(text)) {
        if (done.size > 256) done.clear()
        done.set(text, await mask(bin, text))
      }
      return done.get(text)
    }
    // A text file comes in one of two shapes. The server's own attachment is a
    // part of its own with metadata.attachment, masked whole. The client may
    // instead put the file into the text the user typed, as
    // <file name="…">…</file> (`opencode run -f` does, seen on 2.0.30): only
    // what is inside such a block is masked, the typed text is left as it is.
    const FILE_BLOCK = /(<file name="[^"]*">\n?)([\s\S]*?)(\n?<\/file>)/g
    const maskAttachments = async (e: any) => {
      for (const msg of Array.isArray(e?.messages) ? e.messages : []) {
        if (msg?.role !== "user" || !Array.isArray(msg.content)) continue
        for (const part of msg.content) {
          if (part?.type !== "text" || typeof part.text !== "string") continue
          if (part.metadata?.attachment) {
            const m = await cached(part.text)
            if (m !== undefined) part.text = m
            continue
          }
          if (!part.text.includes("<file name=")) continue
          let out = "", last = 0
          for (const b of part.text.matchAll(FILE_BLOCK)) {
            const m = await cached(b[2])
            out += part.text.slice(last, b.index) + b[1] + (m ?? b[2]) + b[3]
            last = b.index! + b[0].length
          }
          if (last > 0) part.text = out + part.text.slice(last)
        }
      }
    }
    // The three request kinds the built-in plugins hook together: a turn, the
    // summary of a compaction, and a generation such as a title.
    for (const kind of ["context", "compaction", "generate"]) await ctx.session?.hook?.(kind, maskAttachments)

    await ctx.tool.hook("execute.after", async (e: any) => {
      if (!isShell(e?.tool) || e?.status !== "completed" || !e?.result) return
      const result = e.result
      const next: any = { ...result }

      if (Array.isArray(result.content)) {
        next.content = await Promise.all(
          result.content.map(async (part: any) => {
            if (part?.type !== "text") return part
            const m = await mask(bin, part.text)
            return m === undefined ? part : { ...part, text: m }
          }),
        )
      }
      // The same text again, structured: a value masked in one place but not
      // the other is not masked at all.
      const o = result.output
      if (typeof o === "string") {
        const m = await mask(bin, o)
        if (m !== undefined) next.output = m
      } else if (o && typeof o === "object") {
        const copy: any = { ...o }
        for (const field of ["output", "stdout", "stderr"]) {
          const m = await mask(bin, copy[field])
          if (m !== undefined) copy[field] = m
        }
        next.output = copy
      }
      e.result = next
    })
  },
  server: SecretsRedactPlugin,
}
