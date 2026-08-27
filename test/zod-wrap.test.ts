import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineTool, toMCPTool, validateInput, zodToJsonSchema } from "../src/zod-wrap.js";

describe("zodToJsonSchema", () => {
  it("converts primitive types", () => {
    expect(zodToJsonSchema(z.string()).type).toBe("string");
    expect(zodToJsonSchema(z.number()).type).toBe("number");
    expect(zodToJsonSchema(z.boolean()).type).toBe("boolean");
    expect(zodToJsonSchema(z.number().int()).type).toBe("integer");
  });

  it("converts objects with required + optional fields", () => {
    const schema = z.object({
      query: z.string(),
      limit: z.number().int().min(1).max(100).optional(),
    });
    const json = zodToJsonSchema(schema);
    expect(json.type).toBe("object");
    expect(json.required).toEqual(["query"]);
    expect((json.properties as Record<string, { type?: string }>).limit.type).toBe("integer");
  });

  it("handles enums, arrays, and defaults", () => {
    const schema = z.object({
      mode: z.enum(["fast", "slow"]).default("fast"),
      tags: z.array(z.string()),
    });
    const json = zodToJsonSchema(schema);
    expect((json.properties as any).mode.enum).toEqual(["fast", "slow"]);
    expect((json.properties as any).mode.default).toBe("fast");
    expect((json.properties as any).tags.type).toBe("array");
  });

  it("emits string formats for email/url/uuid", () => {
    expect(zodToJsonSchema(z.string().email()).format).toBe("email");
    expect(zodToJsonSchema(z.string().url()).format).toBe("uri");
    expect(zodToJsonSchema(z.string().uuid()).format).toBe("uuid");
  });
});

describe("defineTool", () => {
  it("wraps a Zod schema into a MCP-compatible tool", () => {
    const tool = defineTool({
      name: "search",
      description: "Search the corpus.",
      input: z.object({ query: z.string(), limit: z.number().int().default(10) }),
      handler: async ({ query, limit }) => ({ query, count: limit }),
    });
    const mcp = toMCPTool(tool);
    expect(mcp.name).toBe("search");
    expect(mcp.inputSchema.type).toBe("object");
  });
});

describe("validateInput", () => {
  const tool = defineTool({
    name: "search",
    input: z.object({ query: z.string().min(1), limit: z.number().int().max(100) }),
    handler: async () => null,
  });

  it("returns ok=true for valid input", () => {
    const r = validateInput(tool, { query: "hi", limit: 10 });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.query).toBe("hi");
  });

  it("returns ok=false + issues for invalid input", () => {
    const r = validateInput(tool, { query: "", limit: 999 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.issues.length).toBeGreaterThan(0);
  });
});
