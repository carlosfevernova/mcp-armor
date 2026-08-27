export interface Tool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface MinimalTool {
  name: string;
  description: string;
}

export interface LazyToolsetStats {
  totalTools: number;
  fullSchemaChars: number;
  minimalChars: number;
  fullSchemaTokenEstimate: number;
  minimalTokenEstimate: number;
  savingsPercent: number;
}

export interface LazyToolset {
  /**
   * Minimal tool list — sent to the model on every turn.
   * Contains only name + one-line description. Typically 5-15% the size of full schemas.
   */
  readonly minimal: readonly MinimalTool[];
  /** Fetch full tool schema on-demand — only when the model actually invokes the tool. */
  getFullSchema(name: string): Tool | undefined;
  /** All tool names, in original order. */
  readonly names: readonly string[];
  /** Compression statistics — the marketing numbers. */
  stats(): LazyToolsetStats;
}

/**
 * Trim a multi-line description down to a single, tokenizer-friendly line.
 * Heuristic: first sentence or first 120 chars, whichever comes first.
 */
export function extractOneLiner(description: string | undefined): string {
  if (!description) return "";
  const trimmed = description.trim();
  if (trimmed.length === 0) return "";
  const firstSentence = trimmed.match(/^[^.!?\n]{5,180}[.!?]/);
  if (firstSentence) return firstSentence[0].trim();
  return trimmed.slice(0, 120).trim() + (trimmed.length > 120 ? "…" : "");
}

/**
 * Rough token estimate — chars / 4 is close enough for MCP schemas
 * (JSON is dense, English is ~4 chars/token in tiktoken).
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Take a full MCP toolset and expose a lazy-loading view of it.
 *
 * Typical savings under a 20-turn agent session:
 *   - 50 tools × ~800 chars of schema each ≈ 40 KB sent per turn = ~10K tokens
 *   - Minimal view: 50 × ~60 chars each ≈ 3 KB ≈ 750 tokens
 *   - **~92% reduction** on every LLM turn, exposed via `stats().savingsPercent`.
 */
export function lazyLoadTools(tools: readonly Tool[]): LazyToolset {
  const byName = new Map<string, Tool>();
  const minimal: MinimalTool[] = [];
  const names: string[] = [];

  for (const t of tools) {
    if (byName.has(t.name)) continue;
    byName.set(t.name, t);
    names.push(t.name);
    minimal.push({ name: t.name, description: extractOneLiner(t.description) });
  }

  const minimalChars = JSON.stringify(minimal).length;
  const fullSchemaChars = JSON.stringify(tools).length;

  return {
    minimal,
    names,
    getFullSchema(name) {
      return byName.get(name);
    },
    stats() {
      const savingsPercent = fullSchemaChars > 0
        ? Math.round(((fullSchemaChars - minimalChars) / fullSchemaChars) * 100)
        : 0;
      return {
        totalTools: tools.length,
        fullSchemaChars,
        minimalChars,
        fullSchemaTokenEstimate: estimateTokens(JSON.stringify(tools)),
        minimalTokenEstimate: estimateTokens(JSON.stringify(minimal)),
        savingsPercent,
      };
    },
  };
}
