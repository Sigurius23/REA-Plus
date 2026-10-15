import { readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { z } from "zod";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

const common = (defaultMode: "attached" | "headless") => ({
  mode: z.enum(["attached", "headless"]).default(defaultMode),
  timeoutMs: z.number().int().positive().max(2_147_483_647).default(300_000),
  workspaceRoot: z
    .string()
    .refine(isAbsolute, "workspaceRoot must be absolute on the REA+ host")
    .optional(),
});

const registrationSchema = (defaultMode: "attached" | "headless") =>
  z.union([
    z
      .object({
        ...common(defaultMode),
        type: z.literal("stdio").optional(),
        command: z.string().min(1),
        args: z.array(z.string()).default([]),
        env: z.record(z.string(), z.string()).default({}),
      })
      .strict(),
    z
      .object({
        ...common(defaultMode),
        type: z.literal("http").optional(),
        url: z.url().refine((value) => {
          const url = new URL(value);
          return (
            ["http:", "https:"].includes(url.protocol) &&
            ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) &&
            url.username === "" &&
            url.password === ""
          );
        }, "IDA MCP must use a local HTTP endpoint without URL credentials"),
        headers: z.record(z.string(), z.string()).default({}),
      })
      .strict(),
  ]);

/** An upstream MCP registration plus REA+'s database lifecycle selection. */
export type IdaConfiguration = z.infer<ReturnType<typeof registrationSchema>>;

/** Read one explicit registration without starting or installing a provider. */
const readConfiguration = (
  path: string,
  serverId: "ida-pro-mcp" | "ida-hexrays",
  setting: "REA_IDA_MCP_CONFIG" | "REA_IDA_OFFICIAL_MCP_CONFIG",
  defaultMode: "attached" | "headless",
): Result<IdaConfiguration, ConfigurationError> => {
  try {
    if (statSync(path).size > 65_536)
      return err(
        registrationConfigurationError(
          `${setting} exceeds the 64 KiB registration size.`,
          setting,
        ),
      );
    const input: unknown = JSON.parse(readFileSync(path, "utf8"));
    const envelope = z
      .object({ mcpServers: z.record(z.string(), z.unknown()) })
      .safeParse(input);
    const registration =
      envelope.success && serverId in envelope.data.mcpServers
        ? envelope.data.mcpServers[serverId]
        : input;
    const parsed = registrationSchema(defaultMode).safeParse(registration);
    if (!parsed.success)
      return err(
        registrationConfigurationError(
          `${setting} must contain a ${serverId} command/args or local URL registration; see the provider documentation.`,
          setting,
          parsed.error,
        ),
      );
    if (serverId === "ida-hexrays" && parsed.data.mode !== "headless")
      return err(
        registrationConfigurationError(
          "The normalized official IDA provider requires mode=headless so execute_python and IDA database flushes operate only on REA+'s private input copy; use the generic external MCP bridge for caller-controlled attached GUI use.",
          setting,
        ),
      );
    return ok(parsed.data);
  } catch (cause: unknown) {
    return err(
      registrationConfigurationError(
        `Cannot read ${setting} registration ${path}; provide a readable JSON configuration.`,
        setting,
        cause,
      ),
    );
  }
};

/** Configuration for the existing mrexodia/ida-pro-mcp compatibility profile. */
export const readIdaConfiguration = (
  path: string,
): Result<IdaConfiguration, ConfigurationError> =>
  readConfiguration(path, "ida-pro-mcp", "REA_IDA_MCP_CONFIG", "attached");

/** Configuration for the vendor-maintained Hex-Rays ida-mcp profile. */
export const readOfficialIdaConfiguration = (
  path: string,
): Result<IdaConfiguration, ConfigurationError> =>
  readConfiguration(
    path,
    "ida-hexrays",
    "REA_IDA_OFFICIAL_MCP_CONFIG",
    "headless",
  );

/** A named IDA registration rejection suitable for provider diagnostics. */
const registrationConfigurationError = (
  constraint: string,
  setting: "REA_IDA_MCP_CONFIG" | "REA_IDA_OFFICIAL_MCP_CONFIG",
  cause?: unknown,
): ConfigurationError =>
  new ConfigurationError("Invalid IDA MCP provider configuration", {
    ...(cause === undefined ? {} : { cause }),
    settings: [{ setting, constraint }],
  });

/** A REA_IDA_MCP_CONFIG rejection that names the setting it concerns. */
export const idaConfigurationError = (
  constraint: string,
  cause?: unknown,
): ConfigurationError =>
  registrationConfigurationError(constraint, "REA_IDA_MCP_CONFIG", cause);
