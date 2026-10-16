import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const text = z.string().nullable();

export const MOBSF_VIEWS = [
  "findings",
  "locations",
  "permissions",
  "components",
  "binaries",
  "apis",
  "endpoints",
  "domains",
  "secrets",
  "trackers",
  "protections",
  "files",
] as const;

export const MOBSF_SEVERITIES = ["high", "warning", "info", "secure"] as const;

export const MOBSF_PAGE_LIMIT = 1000;

export const inspectMobsfReportInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute MobSF static-analysis JSON report (the web UI's JSON download or /api/v1/report_json)",
    ),
  view: z
    .enum(MOBSF_VIEWS)
    .default("findings")
    .describe(
      "findings: manifest, network, certificate, code and binary issues with CWE/OWASP/MASVS and file locations; locations: one row per file and finding or API; permissions; components: activities, services, receivers, providers and URL schemes with exported and deep-link data; binaries: native libraries and Mach-O hardening checks; apis: API usage with files; endpoints: URLs, emails and Firebase databases; domains; secrets; trackers; protections: APKiD packers, obfuscators, anti-debug and anti-VM; files.",
    ),
  severity: z
    .enum(MOBSF_SEVERITIES)
    .optional()
    .describe("Keep findings of this severity"),
  section: z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe(
      "Keep findings or locations from one section: manifest, network, certificate, code, binary (iOS binary code), macho (main iOS binary), hardening (native libraries and frameworks), files, or api (locations of API usage)",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of titles, rule ids, names, paths, values or descriptions",
    ),
  app_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Absolute APK, AAB or IPA to check against the SHA-256 the report names",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(MOBSF_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

export const mobsfLocationSchema = z.strictObject({
  path: z.string(),
  lines: z.array(count),
});

export const mobsfFindingSchema = z.strictObject({
  section: z.string().describe("Report section the finding comes from."),
  rule: text.describe("MobSF rule id, when the report names one."),
  title: z.string(),
  severity: z.enum(MOBSF_SEVERITIES),
  mobsf_severity: z
    .string()
    .describe("The label as MobSF wrote it (good, medium, insecure...)."),
  description: z.string(),
  cwe: text,
  owasp_mobile: text,
  masvs: text,
  cvss: z.number().nullable(),
  reference: text,
  components: z
    .array(z.string())
    .describe(
      "Manifest components, network scopes or the binary the finding is about.",
    ),
  location_count: count,
  locations: z
    .array(mobsfLocationSchema)
    .describe(
      "Files with line numbers; the first 200, see the locations view.",
    ),
});

export const mobsfLocationRowSchema = z.strictObject({
  source: z.enum(["finding", "api"]),
  section: z.string(),
  rule: z.string(),
  path: z.string(),
  lines: z.array(count),
});

export const mobsfPermissionSchema = z.strictObject({
  name: z.string(),
  status: z.string().describe("dangerous, normal, signature..."),
  info: text,
  description: text,
  malware_top: z
    .boolean()
    .nullable()
    .describe(
      "Among the permissions MobSF lists as most used by malware; null when the report has no such list.",
    ),
});

export const mobsfComponentSchema = z.strictObject({
  kind: z.enum(["activity", "service", "receiver", "provider", "url-scheme"]),
  name: z.string(),
  main: z.boolean(),
  exported: z
    .boolean()
    .nullable()
    .describe(
      "From MobSF's exported activity list; null for kinds it does not list.",
    ),
  schemes: z.array(z.string()),
  hosts: z.array(z.string()),
  paths: z.array(z.string()),
  mime_types: z.array(z.string()),
});

export const mobsfBinaryCheckSchema = z.strictObject({
  check: z.string(),
  value: z.union([z.string(), z.number(), z.boolean()]).nullable(),
  severity: z.enum(MOBSF_SEVERITIES),
  description: z.string(),
});

export const mobsfBinarySchema = z.strictObject({
  name: z.string(),
  kind: z.enum(["library", "executable", "framework", "dylib"]),
  weak: count.describe("Checks MobSF rates high or warning."),
  checks: z.array(mobsfBinaryCheckSchema),
});

export const mobsfApiSchema = z.strictObject({
  id: z.string(),
  description: z.string(),
  severity: z.enum(MOBSF_SEVERITIES),
  file_count: count,
  files: z
    .array(mobsfLocationSchema)
    .describe("The first 200 files; see the locations view."),
});

export const mobsfEndpointSchema = z.strictObject({
  kind: z.enum(["url", "email", "firebase"]),
  value: z.string(),
  path: text.describe("Source file MobSF found it in."),
  open: z
    .boolean()
    .nullable()
    .describe("Firebase databases MobSF found readable without credentials."),
});

export const mobsfDomainSchema = z.strictObject({
  domain: z.string(),
  bad: z.boolean().describe("MobSF's malware domain check."),
  ofac: z.boolean().nullable(),
  ip: text,
  country: text,
  region: text,
  city: text,
});

export const mobsfSecretSchema = z.strictObject({
  text: z.string(),
});

export const mobsfTrackerSchema = z.strictObject({
  name: z.string(),
  categories: z.array(z.string()),
  url: text,
});

export const mobsfProtectionSchema = z.strictObject({
  file: z.string().describe("DEX file APKiD examined."),
  category: z
    .string()
    .describe(
      "anti_vm, anti_debug, anti_disassembly, compiler, obfuscator, packer, manipulator...",
    ),
  value: z.string(),
});

export const mobsfFileSchema = z.strictObject({ path: z.string() });

export const mobsfReportSchema = z.strictObject({
  report: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    mobsf_version: text,
    timestamp: text,
    layout: z
      .enum(["current", "legacy"])
      .describe(
        "current: the layout of MobSF 3.6 to 4.x (manifest_findings, code_analysis.findings); legacy: the bare lists and maps of MobSF 3.1.",
      ),
    unread: z
      .array(z.string())
      .describe("Sections present in a shape this reader does not know."),
  }),
  app: z.strictObject({
    platform: z.enum(["android", "ios", "other"]),
    file_name: text,
    app_name: text,
    app_type: text,
    identifier: text.describe("Package name or bundle id."),
    version: text,
    build: text.describe("Version code or bundle build."),
    min_sdk: text.describe("Minimum Android SDK or iOS version."),
    target_sdk: text.describe("Target Android SDK or iOS SDK name."),
    main_activity: text,
    certificate: text.describe(
      "Signing certificate details as MobSF printed them.",
    ),
    size: text,
    md5: text,
    sha1: text,
    sha256: text,
  }),
  app_file: z
    .strictObject({
      path: z.string(),
      sha256: digest,
      matches_report: z.boolean(),
    })
    .nullable(),
  summary: z.strictObject({
    security_score: z.number().nullable(),
    average_cvss: z.number().nullable(),
    findings: z.strictObject({
      high: count,
      warning: count,
      info: count,
      secure: count,
    }),
    permissions: count,
    dangerous_permissions: count,
    components: count,
    exported_components: count,
    binaries: count,
    weak_binaries: count,
    api_categories: count,
    endpoints: count,
    domains: count,
    flagged_domains: count.describe("Malware or OFAC-flagged domains."),
    secrets: count,
    trackers: count,
    total_trackers: count.nullable().describe("Trackers MobSF checked for."),
    protections: count,
    files: count,
  }),
  page: z.strictObject({
    view: z.enum(MOBSF_VIEWS),
    severity: z.enum(MOBSF_SEVERITIES).nullable(),
    section: text,
    query: text,
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  findings: z.array(mobsfFindingSchema),
  locations: z.array(mobsfLocationRowSchema),
  permissions: z.array(mobsfPermissionSchema),
  components: z.array(mobsfComponentSchema),
  binaries: z.array(mobsfBinarySchema),
  apis: z.array(mobsfApiSchema),
  endpoints: z.array(mobsfEndpointSchema),
  domains: z.array(mobsfDomainSchema),
  secrets: z.array(mobsfSecretSchema),
  trackers: z.array(mobsfTrackerSchema),
  protections: z.array(mobsfProtectionSchema),
  files: z.array(mobsfFileSchema),
  limitations: z.array(z.string()),
});

export type InspectMobsfReportInput = z.output<
  typeof inspectMobsfReportInputSchema
>;
export type MobsfReport = z.output<typeof mobsfReportSchema>;
