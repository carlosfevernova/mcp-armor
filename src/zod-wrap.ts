import { z } from "zod";
import type { Tool } from "./schema-lazy.js";

export interface TypedTool<TInput, TOutput> {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  input: z.ZodType<TInput>;
  handler: (args: TInput) => Promise<TOutput> | TOutput;
}

export interface TypedToolSpec<TInput, TOutput> {
  name: string;
  description?: string;
  input: z.ZodType<TInput>;
  handler: (args: TInput) => Promise<TOutput> | TOutput;
}

/**
 * Take a Zod schema + a typed handler and produce an MCP-compatible Tool
 * definition. Handles JSON-schema generation and runtime argument validation
 * so the tool implementer never has to hand-write the schema twice.
 */
export function defineTool<TInput, TOutput>(
  spec: TypedToolSpec<TInput, TOutput>,
): TypedTool<TInput, TOutput> {
  const inputSchema = zodToJsonSchema(spec.input);
  return {
    name: spec.name,
    description: spec.description,
    inputSchema,
    input: spec.input,
    handler: spec.handler,
  };
}

/**
 * Convert a typed tool into a plain MCP tool definition (JSON-Schema only).
 * Use for interoperability with clients that don't know about Zod.
 */
export function toMCPTool<TInput, TOutput>(tool: TypedTool<TInput, TOutput>): Tool {
  return {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
  };
}

/**
 * Validate raw arguments (as they arrive from the model) against the tool's
 * Zod schema. Returns a discriminated union so callers can react without try/catch.
 */
export function validateInput<TInput, TOutput>(
  tool: TypedTool<TInput, TOutput>,
  args: unknown,
):
  | { ok: true; data: TInput }
  | { ok: false; issues: readonly z.ZodIssue[] } {
  const result = tool.input.safeParse(args);
  if (result.success) return { ok: true, data: result.data };
  return { ok: false, issues: result.error.issues };
}

/**
 * Minimal Zod-to-JSON-Schema converter — MCP only accepts a subset of JSON
 * Schema (draft 2020-12), and pulling in a full converter (~50 KB) is
 * overkill for the common shapes: objects, strings, numbers, arrays, enums.
 *
 * For complex schemas users can install `zod-to-json-schema` themselves and
 * pass the output directly to `defineTool` via a wrapper. This built-in
 * handler covers 80% of MCP tool inputs cleanly.
 */
export function zodToJsonSchema(schema: z.ZodType): Record<string, unknown> {
  return convert(schema as z.ZodTypeAny);
}

function convert(schema: z.ZodTypeAny): Record<string, unknown> {
  const def = schema._def;
  const typeName = def.typeName as string;

  switch (typeName) {
    case "ZodString": {
      const out: Record<string, unknown> = { type: "string" };
      if (schema.description) out.description = schema.description;
      const checks = (def.checks ?? []) as Array<{ kind: string; value?: unknown }>;
      for (const c of checks) {
        if (c.kind === "min") out.minLength = c.value;
        if (c.kind === "max") out.maxLength = c.value;
        if (c.kind === "email") out.format = "email";
        if (c.kind === "url") out.format = "uri";
        if (c.kind === "uuid") out.format = "uuid";
      }
      return out;
    }
    case "ZodNumber": {
      const out: Record<string, unknown> = { type: "number" };
      if (schema.description) out.description = schema.description;
      const checks = (def.checks ?? []) as Array<{ kind: string; value?: number; inclusive?: boolean }>;
      for (const c of checks) {
        if (c.kind === "int") out.type = "integer";
        if (c.kind === "min") out.minimum = c.value;
        if (c.kind === "max") out.maximum = c.value;
      }
      return out;
    }
    case "ZodBoolean":
      return schema.description ? { type: "boolean", description: schema.description } : { type: "boolean" };
    case "ZodNull":
      return { type: "null" };
    case "ZodLiteral":
      return { const: def.value };
    case "ZodEnum":
      return { type: "string", enum: def.values };
    case "ZodArray": {
      const out: Record<string, unknown> = { type: "array", items: convert(def.type) };
      if (schema.description) out.description = schema.description;
      return out;
    }
    case "ZodOptional":
      return convert(def.innerType);
    case "ZodDefault":
      return { ...convert(def.innerType), default: def.defaultValue() };
    case "ZodNullable": {
      const inner = convert(def.innerType);
      const currentType = inner.type;
      if (typeof currentType === "string") inner.type = [currentType, "null"];
      else inner.type = ["null"];
      return inner;
    }
    case "ZodObject": {
      const shape = (def.shape as () => Record<string, z.ZodTypeAny>)();
      const properties: Record<string, unknown> = {};
      const required: string[] = [];
      for (const [key, value] of Object.entries(shape)) {
        properties[key] = convert(value);
        if (!(value._def.typeName === "ZodOptional" || value._def.typeName === "ZodDefault")) {
          required.push(key);
        }
      }
      const out: Record<string, unknown> = {
        type: "object",
        properties,
        additionalProperties: false,
      };
      if (required.length > 0) out.required = required;
      if (schema.description) out.description = schema.description;
      return out;
    }
    case "ZodUnion": {
      const options = (def.options as z.ZodTypeAny[]).map(convert);
      return { anyOf: options };
    }
    case "ZodRecord":
      return { type: "object", additionalProperties: convert(def.valueType) };
    default:
      // Unknown or complex — fall back to permissive schema.
      return { description: `Unsupported Zod type: ${typeName}` };
  }
}
