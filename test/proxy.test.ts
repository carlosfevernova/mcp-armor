import { describe, expect, it, vi } from "vitest";
import { MCPProxy } from "../src/proxy.js";
import type { Tool } from "../src/schema-lazy.js";
import type { SecurityScanResult } from "../src/security.js";

const tools: Tool[] = [
  {
    name: "fetch_url",
    description: "Fetch a URL and return the body.",
    inputSchema: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
  },
  {
    name: "search_docs",
    description: "Search the internal doc corpus.",
    inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
  },
];

describe("MCPProxy", () => {
  it("listTools returns minimal shape", () => {
    const p = new MCPProxy(tools);
    const list = p.listTools();
    expect(list.tools).toHaveLength(2);
    expect(list.tools[0].name).toBe("fetch_url");
    expect(list.tools[0]).not.toHaveProperty("inputSchema");
  });

  it("getFullSchema returns the original tool", () => {
    const p = new MCPProxy(tools);
    const t = p.getFullSchema("fetch_url");
    expect(t?.inputSchema.type).toBe("object");
  });

  it("dispatches to handler on clean input", async () => {
    const p = new MCPProxy(tools, {
      fetch_url: async ({ url }: any) => ({ body: `content_of_${url}` }),
    });
    const r = await p.callTool<{ body: string }>("fetch_url", { url: "https://example.com" });
    expect(r.ok).toBe(true);
    expect(r.data?.body).toBe("content_of_https://example.com");
  });

  it("blocks high-severity SSRF attempts by default", async () => {
    const p = new MCPProxy(tools, {
      fetch_url: async () => ({ body: "should_not_reach" }),
    });
    const r = await p.callTool("fetch_url", { url: "http://169.254.169.254/latest/meta-data/" });
    expect(r.ok).toBe(false);
    expect(r.blocked).toBe(true);
    expect(r.blockReason).toMatch(/blocked_high_severity/);
  });

  it("warn mode allows the call but records findings", async () => {
    let seen: SecurityScanResult | null = null;
    const p = new MCPProxy(
      tools,
      { fetch_url: async () => "ok" },
      { onHighSeverity: "warn", onFinding: (r) => (seen = r) },
    );
    const r = await p.callTool("fetch_url", { url: "http://169.254.169.254/x" });
    expect(r.ok).toBe(true);
    expect(seen).not.toBeNull();
  });

  it("returns error for unknown tools", async () => {
    const p = new MCPProxy(tools);
    const r = await p.callTool("nonexistent", {});
    expect(r.blockReason).toMatch(/tool_not_found/);
  });

  it("returns error when no handler registered", async () => {
    const p = new MCPProxy(tools, {});
    const r = await p.callTool("fetch_url", { url: "https://example.com" });
    expect(r.blockReason).toMatch(/no_handler_registered/);
  });

  it("metrics reflect the proxy usage", async () => {
    const p = new MCPProxy(tools, {
      fetch_url: async () => "ok",
      search_docs: async () => "results",
    });
    p.listTools();
    p.listTools();
    await p.callTool("fetch_url", { url: "https://a.example" });
    await p.callTool("fetch_url", { url: "http://169.254.169.254/x" }); // blocked
    const m = p.metrics();
    expect(m.toolListRequests).toBe(2);
    expect(m.toolInvocations).toBe(2);
    expect(m.blockedInvocations).toBe(1);
    expect(m.compressionSavingsPercent).toBeGreaterThan(0);
  });

  it("fires onFinding for static scan issues at construction", () => {
    const cb = vi.fn();
    new MCPProxy(
      [
        {
          name: "run",
          description: "Executes via child_process.exec",
          inputSchema: { type: "object", properties: { command: { type: "string" } }, required: ["command"] },
        },
      ],
      {},
      { onFinding: cb },
    );
    expect(cb).toHaveBeenCalled();
  });
});
