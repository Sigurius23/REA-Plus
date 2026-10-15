import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema, ValidateFunction } from "ajv";
import { z } from "zod";

import { TOOL_CONTRACTS } from "../contracts/toolContracts.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import type { Result } from "../domain/result.js";
import type { ExternalMcpTool } from "../externalMcp/ExternalMcpConnection.js";
import { record } from "./BinaryNinjaMcpValues.js";

const inputValidators = new WeakMap<object, ValidateFunction>();
const outputValidators = new WeakMap<object, ValidateFunction>();

export const TOOL_ALIASES = Object.freeze({
  openItems: ["bn_open_item_list"],
  openItemOpen: ["bn_open_item_open"],
  binaryViews: ["bn_binary_view_list"],
  setActive: ["bn_binary_view_set_active"],
  overview: [
    "bn_binary_overview",
    "bn_binary_view_overview",
    "bn_binary_view_info",
  ],
  functions: ["bn_function_list"],
  strings: ["bn_string_list", "bn_strings_list"],
  decompile: ["bn_function_decompile"],
  disassembly: ["bn_function_disassembly", "bn_function_disassemble"],
});

export type ToolRole = keyof typeof TOOL_ALIASES;

export const missingBinaryNinjaToolRoles = (
  allowedTools: readonly string[],
): readonly string[] =>
  (Object.keys(TOOL_ALIASES) as ToolRole[]).filter(
    (role) => !TOOL_ALIASES[role].some((name) => allowedTools.includes(name)),
  );

const schemaProperties = (tool: ExternalMcpTool): Record<string, unknown> => {
  const schema = record(tool.inputSchema);
  return record(schema?.properties) ?? {};
};

const chooseField = (
  tool: ExternalMcpTool,
  candidates: readonly string[],
  fallback: string,
): string => {
  const properties = schemaProperties(tool);
  return candidates.find((candidate) => candidate in properties) ?? fallback;
};

const setSemanticArgument = (
  tool: ExternalMcpTool,
  args: Record<string, JsonValue>,
  argument: {
    readonly value: JsonValue;
    readonly candidates: readonly string[];
    readonly fallback: string;
  },
): void => {
  const { value, candidates, fallback } = argument;
  const field = chooseField(tool, candidates, fallback);
  if (field in schemaProperties(tool)) args[field] = value;
};

const inputContract = (operation: string) =>
  TOOL_CONTRACTS.find(({ name }) => name === operation);

export const parseOperationInput = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
): Result<Readonly<Record<string, JsonValue>>, AnalysisError> => {
  const contract = inputContract(operation);
  const parsed = contract?.inputSchema.safeParse(parameters);
  if (parsed?.success !== true)
    return err(new AnalysisInputError(operation, { cause: parsed?.error }));
  const result = jsonValueSchema.parse(parsed.data);
  return ok(result as Readonly<Record<string, JsonValue>>);
};

/** One target-bound, read-only normalized session over the official BN MCP server. */
export const semanticArguments = (
  _name: string,
  tool: ExternalMcpTool,
  semantics: Readonly<Record<string, JsonValue | undefined>>,
): Record<string, JsonValue> => {
  const args: Record<string, JsonValue> = {};
  for (const [semantic, value] of Object.entries(semantics)) {
    if (value === undefined) continue;
    const configuration: Record<
      string,
      { readonly candidates: readonly string[]; readonly fallback: string }
    > = {
      path: {
        candidates: ["path", "filePath", "file_path", "filename", "file"],
        fallback: "path",
      },
      openItem: {
        candidates: [
          "openItem",
          "open_item",
          "openItemHandle",
          "open_item_handle",
        ],
        fallback: "openItem",
      },
      binaryView: {
        candidates: [
          "binaryView",
          "binary_view",
          "binaryViewHandle",
          "binary_view_handle",
          "view",
        ],
        fallback: "binaryView",
      },
      function: {
        candidates: [
          "function",
          "address",
          "functionAddress",
          "function_address",
          "start",
        ],
        fallback: "function",
      },
      arch: { candidates: ["arch", "architecture"], fallback: "arch" },
      offset: { candidates: ["offset"], fallback: "offset" },
      limit: { candidates: ["limit"], fallback: "limit" },
    };
    const mapping = configuration[semantic];
    if (mapping === undefined) continue;
    setSemanticArgument(tool, args, {
      value,
      candidates: mapping.candidates,
      fallback: mapping.fallback,
    });
  }
  return args;
};

export const validateToolArguments = (
  tool: ExternalMcpTool,
  args: Readonly<Record<string, JsonValue>>,
): void => {
  const schema = record(tool.inputSchema);
  if (schema === undefined)
    throw new AnalysisProtocolError(
      `Binary Ninja MCP tool ${tool.name} omitted its input schema.`,
    );
  let validate = inputValidators.get(schema);
  if (validate === undefined) {
    validate = new Ajv2020({ allErrors: true, strict: false }).compile(
      schema as AnySchema,
    );
    inputValidators.set(schema, validate);
  }
  if (!validate(args))
    throw new AnalysisInputError(
      tool.name,
      undefined,
      (validate.errors ?? []).map((issue) => ({
        path: [issue.instancePath],
        reason: "invalid_type" as const,
        message:
          issue.message ?? "Argument does not match the official tool schema.",
      })),
    );
};

/** Normalize inventory rows only when the caller-supplied server advertises an output schema. */
export const validateToolOutput = (
  tool: ExternalMcpTool,
  value: JsonValue,
): void => {
  const schema = record(tool.outputSchema);
  if (schema === undefined)
    throw new AnalysisCapabilityUnavailableError(
      "binary-ninja",
      tool.name,
      "The server did not advertise an output schema for this inventory tool; REA+ will not infer the response shape. Use the generic MCP bridge for the raw upstream result.",
    );

  let validate = outputValidators.get(schema);
  if (validate === undefined) {
    try {
      validate = new Ajv2020({ allErrors: true, strict: false }).compile(
        schema as AnySchema,
      );
      outputValidators.set(schema, validate);
    } catch (cause: unknown) {
      throw new AnalysisProtocolError(
        `Binary Ninja MCP tool ${tool.name} advertised an unsupported output schema.`,
        { cause },
      );
    }
  }
  if (!validate(value))
    throw new AnalysisProtocolError(
      `Binary Ninja MCP tool ${tool.name} returned data that does not match its advertised output schema.`,
    );
};

export const requiredProcedure = (value: unknown): string => {
  const result = z.string().min(1).safeParse(value);
  if (!result.success) throw new AnalysisInputError("procedure_address");
  return result.data;
};

export const isAnalysisError = (value: unknown): value is AnalysisError =>
  typeof value === "object" &&
  value !== null &&
  "_tag" in value &&
  typeof Reflect.get(value, "_tag") === "string";
