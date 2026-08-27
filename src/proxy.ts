import { lazyLoadTools, type LazyToolset, type Tool } from "./schema-lazy.js";
import { scanTool, scanToolInput, type SecurityScanResult } from "./security.js";

export interface ProxyMetrics {
  toolListRequests: number;
  toolInvocations: number;
  blockedInvocations: number;
  compressionSavingsPercent: number;
  cumulativeTokenSavings: number;
}

export interface MCPProxyOptions {
  /**
   * How to react when a runtime input scan finds `high`-severity issues.
   *  - `"block"`  → refuse the tool call, return an error the model can read
   *  - `"warn"`   → allow but log
   *  - `"ignore"` → do nothing
   * Default: `"block"`.
   */
  onHighSeverity?: "block" | "warn" | "ignore";
  /** Called when any finding lands. Wire to your telemetry. */
  onFinding?: (result: SecurityScanResult) => void;
  /** If true, skip runtime input scans (only static tool scans at construction). Default false. */
  skipInputScan?: boolean;
}

export interface ToolCallResult<T = unknown> {
  ok: boolean;
  data?: T;
  blocked?: true;
  blockReason?: string;
  findings?: SecurityScanResult;
}

/**
 * Thin proxy that sits between an MCP client and a set of tools.
 *
 * - Exposes `listTools()` that returns a lazy, token-minimal view.
 * - Exposes `getFullSchema(name)` for on-demand expansion.
 * - Wraps `callTool(name, args)` with a runtime security scan.
 * - Tracks metrics for a `/api/telemetry` endpoint.
 */
export class MCPProxy {
  private readonly toolset: LazyToolset;
  private readonly toolMap: Map<string, Tool>;
  private readonly handlers: Map<string, (args: unknown) => Promise<unknown> | unknown>;
  private readonly onHighSeverity: NonNullable<MCPProxyOptions["onHighSeverity"]>;
  private readonly onFinding?: MCPProxyOptions["onFinding"];
  private readonly skipInputScan: boolean;
  private toolListRequests = 0;
  private toolInvocations = 0;
  private blockedInvocations = 0;

  constructor(
    tools: readonly Tool[],
    handlers: Record<string, (args: unknown) => Promise<unknown> | unknown> = {},
    opts: MCPProxyOptions = {},
  ) {
    this.toolset = lazyLoadTools(tools);
    this.toolMap = new Map(tools.map((t) => [t.name, t]));
    this.handlers = new Map(Object.entries(handlers));
    this.onHighSeverity = opts.onHighSeverity ?? "block";
    this.onFinding = opts.onFinding;
    this.skipInputScan = opts.skipInputScan ?? false;

    // Static scan at construction so consumers get warnings up-front.
    for (const t of tools) {
      const r = scanTool(t);
      if (!r.passed && this.onFinding) this.onFinding(r);
    }
  }

  /** Minimal tool list — sent to the LLM on every turn. */
  listTools() {
    this.toolListRequests++;
    return { tools: this.toolset.minimal.map((m) => ({ name: m.name, description: m.description })) };
  }

  /** On-demand full schema — send only when the LLM decides to invoke a tool. */
  getFullSchema(name: string): Tool | undefined {
    return this.toolset.getFullSchema(name);
  }

  /** Invoke a tool with runtime security scan + optional block-on-high. */
  async callTool<T = unknown>(name: string, args: unknown): Promise<ToolCallResult<T>> {
    this.toolInvocations++;
    const tool = this.toolMap.get(name);
    if (!tool) {
      return { ok: false, blocked: true, blockReason: `tool_not_found: ${name}` };
    }

    let findings: SecurityScanResult | undefined;
    if (!this.skipInputScan) {
      findings = scanToolInput(tool, args);
      if (findings.findings.length > 0 && this.onFinding) this.onFinding(findings);
      if (findings.highCount > 0 && this.onHighSeverity === "block") {
        this.blockedInvocations++;
        return {
          ok: false,
          blocked: true,
          blockReason: `blocked_high_severity: ${findings.findings[0]?.detail ?? "unknown"}`,
          findings,
        };
      }
    }

    const handler = this.handlers.get(name);
    if (!handler) {
      return {
        ok: false,
        blocked: true,
        blockReason: `no_handler_registered: ${name}`,
        findings,
      };
    }

    const data = (await handler(args)) as T;
    return { ok: true, data, findings };
  }

  metrics(): ProxyMetrics {
    const s = this.toolset.stats();
    return {
      toolListRequests: this.toolListRequests,
      toolInvocations: this.toolInvocations,
      blockedInvocations: this.blockedInvocations,
      compressionSavingsPercent: s.savingsPercent,
      cumulativeTokenSavings:
        this.toolListRequests * (s.fullSchemaTokenEstimate - s.minimalTokenEstimate),
    };
  }
}
