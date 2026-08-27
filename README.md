# mcp-armor

**Your MCP client is burning 300 KB of tokens per session. This fixes it in 6 lines.**

Drop-in proxy for MCP (Model Context Protocol) clients. Three things it does that nobody else does in one package:

1. **Lazy-loads tool schemas** — sends a minimal name+one-liner list to the LLM every turn, and only expands the full JSON Schema when the model actually picks a tool. **60–95% token reduction** on typical sessions.
2. **Scans tool defs and runtime arguments for injection attacks** — SSRF (metadata service + private IPs + localhost), command injection (shell metacharacters, `child_process` hints), path traversal, SQL tautology, prompt-injection markers. Blocks high-severity by default.
3. **Zod-first tool definitions** — write your tool once with a Zod schema, get a type-safe handler + auto-generated JSON Schema. No hand-writing schemas twice.

```bash
npm i mcp-armor
```

## Why this exists

An [arxiv paper from Nov 2026](https://arxiv.org/html/2511.20920v1) audited the MCP server registry and found **36.7% of servers had SSRF-friendly designs** and **43% had unsafe command execution**. Meanwhile, [Builder Radar](https://buttondown.com/Builder-Radar/archive/builder-radar-week-of-august-16-2026/) tracked the "MCP tool overhead" problem: 15,000 tokens of tool defs per turn × 20 turns = **300,000 tokens burned before your model does any actual work**.

`mcp-armor` sits between your MCP client and your tools and solves both.

## 30-second example

```ts
import { MCPProxy, defineTool } from "mcp-armor";
import { z } from "zod";

const searchTool = defineTool({
  name: "search",
  description: "Full-text search over the corpus.",
  input: z.object({
    query: z.string().min(1),
    limit: z.number().int().max(100).default(10),
  }),
  handler: async ({ query, limit }) => {
    const rows = await db.query(query, limit);
    return { rows };
  },
});

const proxy = new MCPProxy(
  [searchTool],
  { search: searchTool.handler },
  { onHighSeverity: "block" }
);

// Wire into your MCP server's list_tools handler:
server.setRequestHandler(ListToolsRequestSchema, () => proxy.listTools());
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const r = await proxy.callTool(req.params.name, req.params.arguments);
  if (!r.ok) throw new Error(r.blockReason);
  return { content: [{ type: "text", text: JSON.stringify(r.data) }] };
});
```

## What you get

### Token compression (`lazyLoadTools`)

Given 20 tools with ~800-char schemas each, the compression stats look like this:

```ts
const stats = proxy.metrics();
// { totalTools: 20,
//   fullSchemaTokenEstimate: 4200,
//   minimalTokenEstimate: 260,
//   compressionSavingsPercent: 94 }
```

The trick: MCP tool schemas are fat (`inputSchema` is verbose JSON Schema), but every model turn only needs to know **which tools exist and roughly what each does**. Full schemas are only sent when the model actually picks a tool via `getFullSchema(name)`.

### Security scan (`scanTool`, `scanToolInput`)

Static scan runs at proxy construction and flags:

- SSRF gadgets (cloud metadata endpoints, private-IP references in descriptions)
- Command-injection hints (`child_process`, `exec`, `os.system` mentions)
- Suspicious property names (`command`, `shell`, `sql`, `query` accepting free-form strings)

Runtime scan runs on every `callTool` and catches:

- SSRF attempts (metadata IPs, RFC 1918 private ranges, `localhost`, `0.0.0.0`)
- Unsafe URL schemes (`file://`, `ftp://`, `data://`, `gopher://`)
- Shell metacharacters (`;`, `&`, `|`, backticks, `$(`, `&&`, `||`)
- Path traversal sequences (`../`)
- Classic SQL injection tautologies (`' OR '1'='1`)
- Prompt-injection markers ("ignore previous instructions" et al.)

You choose the reaction with `onHighSeverity: "block" | "warn" | "ignore"`.

### Type-safe handlers (`defineTool`, `validateInput`)

```ts
const tool = defineTool({
  name: "book_flight",
  input: z.object({
    from: z.string().length(3),
    to: z.string().length(3),
    date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  }),
  handler: async ({ from, to, date }) => {
    // TypeScript already knows the shape here — no manual type assertion.
    return { pnr: await amadeus.book(from, to, date) };
  },
});
```

The Zod schema is auto-converted to JSON Schema for MCP compatibility. On the boundary, `validateInput` runs the raw argument object through Zod's `safeParse` and returns a discriminated union — no try/catch dance.

## API

- `lazyLoadTools(tools)` → `LazyToolset` with `.minimal`, `.getFullSchema()`, `.stats()`
- `scanTool(tool)` → static security scan of a tool definition
- `scanToolInput(tool, args)` → runtime security scan of arguments
- `defineTool({ name, input, handler })` → typed tool with auto-generated inputSchema
- `validateInput(tool, args)` → `{ ok: true, data } | { ok: false, issues }`
- `zodToJsonSchema(schema)` → standalone converter (covers 80% of MCP shapes)
- `class MCPProxy(tools, handlers, opts)` → the drop-in wrapper

## Design choices

- **Zero runtime deps besides `zod`.** `zod` is already the standard for MCP tool input validation; adding it doesn't cost you anything.
- **Node 20+.** Uses native `AbortController`, no polyfills.
- **Works with any MCP transport.** stdio, SSE, or WebSocket — the proxy sits above transport concerns.
- **Sane defaults.** Blocks high-severity findings by default. Change with `onHighSeverity: "warn"` if you'd rather log and continue.

## Related

- [`vercel-armor`](https://www.npmjs.com/package/vercel-armor) — 4-layer armor for Vercel serverless APIs. Same author, same DNA, different layer.

## License

MIT — Carlos F. Vernova
