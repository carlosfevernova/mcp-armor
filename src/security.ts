import type { Tool } from "./schema-lazy.js";

export type SecuritySeverity = "high" | "medium" | "low" | "info";

export interface SecurityFinding {
  type:
    | "ssrf_metadata_service"
    | "ssrf_private_ip"
    | "ssrf_localhost"
    | "cmd_injection_shell_meta"
    | "cmd_injection_arg_forwarding"
    | "path_traversal"
    | "unsafe_url_scheme"
    | "sql_injection_meta"
    | "prompt_injection_marker";
  severity: SecuritySeverity;
  toolName?: string;
  detail: string;
  /** Optional matched value that triggered the finding. Redacted for logs. */
  matched?: string;
}

export interface SecurityScanResult {
  toolName?: string;
  findings: SecurityFinding[];
  passed: boolean;
  highCount: number;
  mediumCount: number;
}

/** IPs and hostnames that indicate an SSRF attempt against cloud metadata services. */
const CLOUD_METADATA_HOSTS = [
  "169.254.169.254", // AWS/Azure/GCP metadata
  "metadata.google.internal",
  "metadata.internal",
  "instance-data",
  "100.100.100.200", // Alibaba
];

/** Private / loopback IPv4 ranges as regex fragments. */
const PRIVATE_IP_PATTERNS = [
  /\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
  /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
  /\b192\.168\.\d{1,3}\.\d{1,3}\b/,
  /\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b/,
];

/** Shell metacharacters that indicate potential command injection. */
const SHELL_METACHAR_PATTERN = /[;&|`$><\\]|\$\(|\|\||&&/;

/** Common command-injection markers inside tool descriptions or schema examples. */
const CMD_FORWARDING_HINTS = [
  /shell\s*=\s*true/i,
  /child_process/i,
  /exec\s*\(/i,
  /system\s*\(/i,
  /os\.system/i,
  /Runtime\.getRuntime\(\)\.exec/i,
];

/** URL schemes that should never appear in tool arguments unless explicitly whitelisted. */
const UNSAFE_URL_SCHEMES = [/^\s*file:/i, /^\s*ftp:/i, /^\s*gopher:/i, /^\s*data:/i];

/**
 * Static scan of a tool definition (not runtime input). Catches red flags in
 * the shape and description of the tool itself — the arxiv 2511.20920 paper
 * on MCP security found 36.7% of registry servers had SSRF-friendly designs.
 */
export function scanTool(tool: Tool): SecurityScanResult {
  const findings: SecurityFinding[] = [];
  const jsonString = JSON.stringify(tool);
  const description = tool.description ?? "";

  for (const host of CLOUD_METADATA_HOSTS) {
    if (jsonString.includes(host)) {
      findings.push({
        type: "ssrf_metadata_service",
        severity: "high",
        toolName: tool.name,
        detail: `Tool references cloud metadata endpoint (${host}) — likely SSRF gadget`,
        matched: host,
      });
    }
  }

  for (const cmdHint of CMD_FORWARDING_HINTS) {
    if (cmdHint.test(description)) {
      findings.push({
        type: "cmd_injection_arg_forwarding",
        severity: "high",
        toolName: tool.name,
        detail: `Tool description hints at shell/exec forwarding (${cmdHint.source}) — high-risk pattern`,
      });
    }
  }

  // Detect input schemas that accept `command` / `shell` / `script` string args.
  const suspiciousFieldNames = ["command", "cmd", "shell", "script", "exec", "sql", "query"];
  const props = extractSchemaProperties(tool.inputSchema);
  for (const [propName, propSchema] of Object.entries(props)) {
    const nameLower = propName.toLowerCase();
    if (suspiciousFieldNames.includes(nameLower) && (propSchema as { type?: string }).type === "string") {
      findings.push({
        type: "cmd_injection_shell_meta",
        severity: "medium",
        toolName: tool.name,
        detail: `Input property "${propName}" accepts free-form string — validate & sanitize before forwarding`,
      });
    }
  }

  return summarize(tool.name, findings);
}

/**
 * Runtime scan of the actual arguments a model wants to pass to a tool.
 * This is the second line of defense — catches concrete injection attempts.
 */
export function scanToolInput(tool: Tool, args: unknown): SecurityScanResult {
  const findings: SecurityFinding[] = [];
  const flatten = flattenStringValues(args);

  for (const { path, value } of flatten) {
    for (const host of CLOUD_METADATA_HOSTS) {
      if (value.includes(host)) {
        findings.push({
          type: "ssrf_metadata_service",
          severity: "high",
          toolName: tool.name,
          detail: `Argument at ${path} targets metadata service`,
          matched: host,
        });
      }
    }
    for (const pat of PRIVATE_IP_PATTERNS) {
      if (pat.test(value)) {
        findings.push({
          type: "ssrf_private_ip",
          severity: "medium",
          toolName: tool.name,
          detail: `Argument at ${path} contains private IP — possible SSRF`,
        });
      }
    }
    if (/(^|[^a-z0-9])(localhost|0\.0\.0\.0)([^a-z0-9]|$)/i.test(value)) {
      findings.push({
        type: "ssrf_localhost",
        severity: "medium",
        toolName: tool.name,
        detail: `Argument at ${path} targets localhost`,
      });
    }
    for (const scheme of UNSAFE_URL_SCHEMES) {
      if (scheme.test(value)) {
        findings.push({
          type: "unsafe_url_scheme",
          severity: "high",
          toolName: tool.name,
          detail: `Argument at ${path} uses unsafe URL scheme`,
        });
      }
    }
    if (SHELL_METACHAR_PATTERN.test(value)) {
      findings.push({
        type: "cmd_injection_shell_meta",
        severity: "medium",
        toolName: tool.name,
        detail: `Argument at ${path} contains shell metacharacters`,
      });
    }
    if (/\.\.[\\/]/.test(value)) {
      findings.push({
        type: "path_traversal",
        severity: "medium",
        toolName: tool.name,
        detail: `Argument at ${path} contains path traversal sequence`,
      });
    }
    if (/(?:'|")\s*(?:or|and)\s*['"]?\s*(\d+)\s*['"]?\s*=\s*['"]?\s*\1\b/i.test(value)) {
      findings.push({
        type: "sql_injection_meta",
        severity: "medium",
        toolName: tool.name,
        detail: `Argument at ${path} matches classic SQL injection tautology`,
      });
    }
    if (/(ignore|forget|disregard).{0,20}(previous|prior|above).{0,20}(instruction|prompt)/i.test(value)) {
      findings.push({
        type: "prompt_injection_marker",
        severity: "low",
        toolName: tool.name,
        detail: `Argument at ${path} contains a prompt-injection marker`,
      });
    }
  }

  return summarize(tool.name, findings);
}

function summarize(toolName: string | undefined, findings: SecurityFinding[]): SecurityScanResult {
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  return {
    toolName,
    findings,
    passed: highCount === 0 && mediumCount === 0,
    highCount,
    mediumCount,
  };
}

function extractSchemaProperties(schema: Record<string, unknown>): Record<string, unknown> {
  const props = (schema as { properties?: unknown }).properties;
  if (props && typeof props === "object" && !Array.isArray(props)) {
    return props as Record<string, unknown>;
  }
  return {};
}

function flattenStringValues(input: unknown, path = "$"): Array<{ path: string; value: string }> {
  const out: Array<{ path: string; value: string }> = [];
  const visit = (v: unknown, p: string) => {
    if (v === null || v === undefined) return;
    if (typeof v === "string") {
      out.push({ path: p, value: v });
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((item, i) => visit(item, `${p}[${i}]`));
      return;
    }
    if (typeof v === "object") {
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        visit(val, `${p}.${k}`);
      }
    }
  };
  visit(input, path);
  return out;
}
