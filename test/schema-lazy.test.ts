import { describe, expect, it } from "vitest";
import { extractOneLiner, lazyLoadTools, type Tool } from "../src/schema-lazy.js";

const bigSchema = {
  type: "object",
  properties: {
    query: { type: "string", description: "The full-text search query. Supports lucene-style operators like AND, OR, NOT, and range queries with square brackets." },
    limit: { type: "integer", minimum: 1, maximum: 500, default: 50, description: "How many results to return, between 1 and 500." },
    offset: { type: "integer", minimum: 0, default: 0 },
    filters: {
      type: "object",
      properties: { dateFrom: { type: "string", format: "date" }, dateTo: { type: "string", format: "date" }, category: { type: "string" } },
    },
  },
  required: ["query"],
} as const;

function makeTool(name: string): Tool {
  return {
    name,
    description: `Perform a ${name} operation against the corpus. Returns a paginated result set with detailed metadata. Supports advanced filters.`,
    inputSchema: bigSchema as unknown as Record<string, unknown>,
  };
}

describe("lazyLoadTools", () => {
  it("preserves tool count and order", () => {
    const tools = [makeTool("search"), makeTool("suggest"), makeTool("summarize")];
    const lazy = lazyLoadTools(tools);
    expect(lazy.names).toEqual(["search", "suggest", "summarize"]);
    expect(lazy.minimal.length).toBe(3);
  });

  it("deduplicates by tool name", () => {
    const tools = [makeTool("search"), makeTool("search")];
    const lazy = lazyLoadTools(tools);
    expect(lazy.names).toEqual(["search"]);
  });

  it("returns full schema on-demand", () => {
    const tools = [makeTool("search")];
    const lazy = lazyLoadTools(tools);
    const full = lazy.getFullSchema("search");
    expect(full).toBeDefined();
    expect((full as Tool).inputSchema).toEqual(bigSchema);
  });

  it("returns undefined for unknown tool", () => {
    expect(lazyLoadTools([]).getFullSchema("nope")).toBeUndefined();
  });

  it("reports ≥50% savings on realistic tool sets", () => {
    const tools = Array.from({ length: 20 }, (_, i) => makeTool(`tool_${i}`));
    const stats = lazyLoadTools(tools).stats();
    expect(stats.totalTools).toBe(20);
    expect(stats.savingsPercent).toBeGreaterThanOrEqual(50);
    expect(stats.minimalTokenEstimate).toBeLessThan(stats.fullSchemaTokenEstimate);
  });

  it("handles empty toolset without dividing by zero", () => {
    const stats = lazyLoadTools([]).stats();
    expect(stats.savingsPercent).toBe(0);
    expect(stats.fullSchemaTokenEstimate).toBeGreaterThanOrEqual(0);
  });
});

describe("extractOneLiner", () => {
  it("returns the first sentence when present", () => {
    expect(extractOneLiner("Fetch a resource. Then decode it.")).toBe("Fetch a resource.");
  });
  it("truncates long text without a sentence terminator", () => {
    const long = "a".repeat(200);
    const one = extractOneLiner(long);
    expect(one.endsWith("…")).toBe(true);
    expect(one.length).toBeLessThanOrEqual(121);
  });
  it("returns empty string for undefined", () => {
    expect(extractOneLiner(undefined)).toBe("");
  });
});
