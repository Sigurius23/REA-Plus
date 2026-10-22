import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";
import { digestSchema } from "../digests.js";

/** Upper bound for one decoded resource projection in one response. */
const MAX_MANIFEST_BYTES = 512 * 1024;
const MAX_STRINGS = 2_000;

const count = z.number().int().nonnegative();

/**
 * Caller intent for Apktool-backed resource decoding. Apktool is
 * bring-your-own: REA+ never installs it, and decoding happens in a
 * provider-owned workspace that is removed after the facts are projected.
 */
export const apktoolInputSchemas = {
  inspect_apktool_client: z.strictObject({}),
  decode_android_resources: z.strictObject({
    path: localPathStringSchema.describe("Local APK file to decode"),
    include_strings: z
      .boolean()
      .default(true)
      .describe(
        `Project res/values/strings.xml entries (bounded to ${String(MAX_STRINGS)} entries)`,
      ),
    locale: z
      .string()
      .min(2)
      .max(16)
      .regex(
        /^(?:[a-z]{2,3}(?:-(?:r?[A-Z]{2}|r?[0-9]{3}))?|b\+[a-z]{2,3}(?:\+[A-Za-z0-9]{2,8})*)$/u,
        "Locale must look like de, pt-BR, pt-rBR, or b+zh+Hans+CN",
      )
      .optional()
      .describe(
        "Project strings from res/values-<locale>/strings.xml instead of the default table",
      ),
    strings_offset: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe(
        "Index of the first parsed string entry projected in this response",
      ),
    strings_limit: z
      .number()
      .int()
      .min(1)
      .max(MAX_STRINGS)
      .default(MAX_STRINGS)
      .describe(
        `Maximum parsed string entries projected in this response (bounded to ${String(MAX_STRINGS)})`,
      ),
    include_xml_resources: z
      .boolean()
      .default(false)
      .describe(
        "Project decoded res/xml files such as a network security config",
      ),
  }),
} as const;

/** Supported Apktool-backed operations. */
export type ApktoolOperation = keyof typeof apktoolInputSchemas;
/** Validated Apktool requests carry their selected operation. */
export type ApktoolRequest = {
  [Name in ApktoolOperation]: {
    operation: Name;
    input: z.infer<(typeof apktoolInputSchemas)[Name]>;
  };
}[ApktoolOperation];

/** Validate operation and input together so their types remain correlated. */
export const apktoolRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("inspect_apktool_client"),
    input: apktoolInputSchemas.inspect_apktool_client,
  }),
  z.strictObject({
    operation: z.literal("decode_android_resources"),
    input: apktoolInputSchemas.decode_android_resources,
  }),
]);

const client = z.strictObject({
  command: z.string().min(1),
  command_source: z.enum(["environment", "path"]),
  apktool_version: z.string().min(1).nullable(),
});

/** Portable Apktool observations with explicit coverage limitations. */
export const apktoolResultSchemas = {
  inspect_apktool_client: z.strictObject({
    client,
  }),
  decode_android_resources: z.strictObject({
    client,
    target: z.strictObject({
      path: localPathStringSchema,
      bytes: z.number().int().nonnegative(),
      sha256: digestSchema,
    }),
    metadata: z.strictObject({
      version_name: z.string().nullable(),
      version_code: z
        .string()
        .nullable()
        .describe(
          "Version code exactly as apktool.yml prints it, e.g. '45' or '45.1'",
        ),
      min_sdk_version: z.string().nullable(),
      target_sdk_version: z.string().nullable(),
      package_name: z.string().nullable(),
    }),
    manifest: z.string().nullable(),
    strings: z.array(
      z.strictObject({
        name: z.string().min(1),
        value: z.string(),
      }),
    ),
    strings_page: z.strictObject({
      offset: count,
      limit: count,
      total: count,
      returned: count,
    }),
    xml_resources: z.array(
      z.strictObject({
        path: z.string().min(1),
        bytes: count,
        truncated: z.boolean(),
        content: z.string().nullable(),
      }),
    ),
    locale: z.string().nullable(),
    locales: z.array(z.string().min(1)),
    decoded_file_count: z.number().int().nonnegative(),
    coverage: z.enum(["complete", "partial"]),
  }),
} as const;
