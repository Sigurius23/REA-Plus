import { readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { z } from "zod";

import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

const idSchema = z.string().regex(/^[a-z][a-z0-9\-]{0,63}$/u);
const childProcessString = (maximum: number) =>
  z
    .string()
    .max(maximum)
    .refine(
      (value) => !value.includes(String.fromCharCode(0)),
      "NUL is not permitted",
    );
const environmentKeySchema = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/u);
const environmentSchema = z
  .record(environmentKeySchema, childProcessString(8192))
  .refine(
    (environment) =>
      new Set(Object.keys(environment).map((key) => key.toUpperCase())).size ===
      Object.keys(environment).length,
    "env keys must be unique without regard to case",
  )
  .default({});
const headerNameSchema = z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u);
const headersSchema = z
  .record(
    headerNameSchema,
    z
      .string()
      .max(8192)
      .refine(
        (value) =>
          !value.includes(String.fromCharCode(10)) &&
          !value.includes(String.fromCharCode(13)),
        "HTTP header values cannot contain CR or LF",
      ),
  )
  .refine(
    (headers) =>
      new Set(Object.keys(headers).map((key) => key.toLowerCase())).size ===
      Object.keys(headers).length,
    "HTTP header names must be unique without regard to case",
  )
  .default({});
const allowedToolsSchema = z
  .array(
    z
      .string()
      .min(1)
      .max(256)
      .refine(
        (value) => !value.includes(String.fromCharCode(0)),
        "NUL is not permitted",
      ),
  )
  .max(512)
  .refine((names) => new Set(names).size === names.length, {
    message: "allowedTools must not contain duplicate names",
  })
  .default([]);
const timeoutSchema = z
  .number()
  .int()
  .min(1)
  .max(2_147_483_647)
  .default(300_000);

const common = {
  name: z.string().min(1).max(128).optional(),
  timeoutMs: timeoutSchema,
  allowedTools: allowedToolsSchema,
};

const registrationSchema = z.discriminatedUnion("type", [
  z
    .object({
      ...common,
      type: z.literal("stdio"),
      command: childProcessString(4096).pipe(z.string().min(1)),
      args: z.array(childProcessString(8192)).max(256).default([]),
      env: environmentSchema,
    })
    .strict(),
  z
    .object({
      ...common,
      type: z.literal("http"),
      url: z
        .string()
        .url()
        .refine((value) => {
          const url = new URL(value);
          return (
            ["http:", "https:"].includes(url.protocol) &&
            ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) &&
            url.username === "" &&
            url.password === "" &&
            url.search === "" &&
            url.hash === ""
          );
        }, "External MCP endpoints must use loopback HTTP(S) without URL credentials, queries, or fragments"),
      headers: headersSchema,
    })
    .strict(),
]);

const configSchema = z
  .object({ mcpServers: z.record(idSchema, registrationSchema).default({}) })
  .strict();

export type ExternalMcpRegistration = z.infer<typeof registrationSchema>;
export type ExternalMcpConfiguration = z.infer<typeof configSchema>;

/** Configuration-file limit applied before reading or parsing any bytes. */
export const EXTERNAL_MCP_CONFIG_MAX_BYTES = 65_536;

/** Parse the caller-selected, local MCP registrations without starting a server. */
export const readExternalMcpConfiguration = (
  path: string | undefined,
): Result<ExternalMcpConfiguration, ConfigurationError> => {
  if (path === undefined) return ok({ mcpServers: {} });
  if (!isAbsolute(path))
    return err(
      externalMcpConfigurationError(
        "REA_EXTERNAL_MCP_CONFIG must be an absolute file path.",
      ),
    );
  try {
    const size = statSync(path).size;
    if (size > EXTERNAL_MCP_CONFIG_MAX_BYTES)
      return err(
        externalMcpConfigurationError(
          "REA_EXTERNAL_MCP_CONFIG exceeds the 64 KiB configuration limit.",
        ),
      );
    const source = readFileSync(path, "utf8");
    if (Buffer.byteLength(source) > EXTERNAL_MCP_CONFIG_MAX_BYTES)
      return err(
        externalMcpConfigurationError(
          "REA_EXTERNAL_MCP_CONFIG exceeds the 64 KiB configuration limit.",
        ),
      );
    const input: unknown = JSON.parse(source);
    const parsed = configSchema.safeParse(input);
    if (!parsed.success)
      return err(
        externalMcpConfigurationError(
          "REA_EXTERNAL_MCP_CONFIG must contain a strict mcpServers object; each entry must be a loopback HTTP registration or an explicit stdio command with an allowedTools list.",
          parsed.error,
        ),
      );
    return ok(parsed.data);
  } catch (cause: unknown) {
    return err(
      externalMcpConfigurationError(
        "Cannot read REA_EXTERNAL_MCP_CONFIG; provide a readable JSON file.",
        cause,
      ),
    );
  }
};

/** Secret-safe configuration failure tied to the one environment setting. */
export const externalMcpConfigurationError = (
  constraint: string,
  cause?: unknown,
): ConfigurationError =>
  new ConfigurationError("Invalid external MCP configuration", {
    ...(cause === undefined ? {} : { cause }),
    settings: [{ setting: "REA_EXTERNAL_MCP_CONFIG", constraint }],
  });
