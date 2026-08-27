export { lazyLoadTools, extractOneLiner, estimateTokens } from "./schema-lazy.js";
export type { Tool, MinimalTool, LazyToolset, LazyToolsetStats } from "./schema-lazy.js";

export { scanTool, scanToolInput } from "./security.js";
export type { SecurityFinding, SecurityScanResult, SecuritySeverity } from "./security.js";

export { defineTool, toMCPTool, validateInput, zodToJsonSchema } from "./zod-wrap.js";
export type { TypedTool, TypedToolSpec } from "./zod-wrap.js";

export { MCPProxy } from "./proxy.js";
export type { MCPProxyOptions, ProxyMetrics, ToolCallResult } from "./proxy.js";

export const VERSION = "0.1.0";
