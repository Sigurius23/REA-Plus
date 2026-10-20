import type {
  InspectMobsfReportInput,
  MobsfReport,
} from "../domain/mobsf/mobsfReport.js";
import { SectionReader } from "./MobsfSections.js";
import { record, text, type Json } from "./MobsfValues.js";

type View = InspectMobsfReportInput["view"];
type Rows = Pick<MobsfReport, View>;
type Finding = MobsfReport["findings"][number];

/** A report that is not MobSF static-analysis JSON; reported as an input error. */
export class MobsfFormatError extends Error {
  override readonly name = "MobsfFormatError";
}

/** Accept MobSF static reports; name the look-alikes callers most often pass instead. */
export const parseMobsfReport = (bytes: Buffer): Json => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw new MobsfFormatError("The file is not JSON.", { cause });
  }
  const data = record(parsed);
  if (data === null)
    throw new MobsfFormatError("A MobSF report is a JSON object.");
  if ("results" in data && "mobsfscan_version" in data)
    throw new MobsfFormatError(
      "This is a mobsfscan source-code scan, not a MobSF static-analysis report.",
    );
  const identified =
    typeof data["md5"] === "string" &&
    typeof data["file_name"] === "string" &&
    (typeof data["package_name"] === "string" ||
      typeof data["bundle_id"] === "string" ||
      typeof data["app_type"] === "string");
  if (!identified)
    throw new MobsfFormatError(
      "No MobSF static-analysis fields (file_name, md5, package_name or bundle_id).",
    );
  return data;
};

const appOf = (data: Json): MobsfReport["app"] => {
  const field = (name: string) => text(data[name]);
  const android = typeof data["package_name"] === "string";
  const ios = !android && typeof data["bundle_id"] === "string";
  return {
    platform: android ? "android" : ios ? "ios" : "other",
    file_name: field("file_name"),
    app_name: field("app_name"),
    app_type: field("app_type"),
    identifier: android ? field("package_name") : field("bundle_id"),
    version: field(android ? "version_name" : "app_version"),
    build: field(android ? "version_code" : "build"),
    min_sdk: field(android ? "min_sdk" : "min_os_version") || null,
    target_sdk: field(android ? "target_sdk" : "sdk_name") || null,
    main_activity: field("main_activity"),
    certificate: text(
      record(data["certificate_analysis"])?.["certificate_info"],
    ),
    size: field("size"),
    md5: field("md5"),
    sha1: field("sha1"),
    sha256: field("sha256"),
  };
};

/** Weak hardening checks become findings: "macho" for the main iOS binary as MobSF names it, "hardening" for libraries and frameworks. */
const binaryCheckFindings = (binaries: MobsfReport["binaries"]): Finding[] =>
  binaries.flatMap((binary) =>
    binary.checks
      .filter(({ severity }) => severity === "high" || severity === "warning")
      .map((check) => {
        const end = check.description.indexOf(". ");
        return {
          section: binary.kind === "executable" ? "macho" : "hardening",
          rule: check.check,
          title:
            end < 0
              ? check.description.replace(/\.$/u, "")
              : check.description.slice(0, end),
          severity: check.severity,
          mobsf_severity: check.severity,
          description: check.description,
          cwe: null,
          owasp_mobile: null,
          masvs: null,
          cvss: null,
          reference: null,
          components: [binary.name],
          location_count: 0,
          locations: [],
        };
      }),
  );

interface Sections {
  readonly findings: Finding[];
  readonly allLocations: MobsfReport["locations"];
  readonly rows: Omit<Rows, "findings" | "locations">;
  readonly totalTrackers: number | null;
  readonly unread: readonly string[];
  readonly legacy: boolean;
}

const readSections = (data: Json): Sections => {
  const reader = new SectionReader(data);
  const binaries = reader.binaries();
  const findings = [
    ...reader.manifest(),
    ...reader.network(),
    ...reader.certificate(),
    ...reader.code(),
    ...reader.binaryFindings(),
    ...binaryCheckFindings(binaries),
    ...reader.files(),
  ];
  const apis = reader.apis();
  const { rows: trackers, total } = reader.trackers();
  // Locations come from the raw maps, so the 200-per-row cap does not apply here.
  const allLocations = [
    ...reader
      .codeLocations()
      .map((row) => ({ source: "finding" as const, section: "code", ...row })),
    ...reader
      .fileLocations()
      .map((row) => ({ source: "finding" as const, section: "files", ...row })),
    ...reader.apiLocations().map((row) => ({ source: "api" as const, ...row })),
  ];
  const rows = {
    permissions: reader.permissions(),
    components: reader.components(),
    binaries,
    apis,
    endpoints: reader.endpoints(),
    domains: reader.domains(),
    secrets: reader.secrets(),
    trackers,
    protections: reader.protections(),
    files: reader.fileList(),
  };
  return {
    findings,
    allLocations,
    rows,
    totalTrackers: total,
    unread: [...reader.unread].sort(),
    legacy: reader.legacy,
  };
};

const matches = (
  query: string | undefined,
  ...values: readonly (string | null)[]
): boolean =>
  query === undefined ||
  values.some(
    (value) => value?.toLowerCase().includes(query.toLowerCase()) === true,
  );

const filtered = (
  sections: Sections,
  input: InspectMobsfReportInput,
): readonly unknown[] => {
  const { query, severity, section } = input;
  const { rows } = sections;
  switch (input.view) {
    case "findings":
      return sections.findings.filter(
        (row) =>
          (severity === undefined || row.severity === severity) &&
          (section === undefined || row.section === section) &&
          matches(
            query,
            row.title,
            row.rule,
            row.description,
            ...row.components,
            ...row.locations.map(({ path }) => path),
          ),
      );
    case "locations":
      return sections.allLocations.filter(
        (row) =>
          (section === undefined || row.section === section) &&
          matches(query, row.rule, row.path),
      );
    case "permissions":
      return rows.permissions.filter((row) =>
        matches(query, row.name, row.status, row.info, row.description),
      );
    case "components":
      return rows.components.filter((row) =>
        matches(query, row.name, row.kind, ...row.schemes, ...row.hosts),
      );
    case "binaries":
      return rows.binaries.filter((row) => matches(query, row.name));
    case "apis":
      return rows.apis.filter((row) => matches(query, row.id, row.description));
    case "endpoints":
      return rows.endpoints.filter((row) =>
        matches(query, row.value, row.path),
      );
    case "domains":
      return rows.domains.filter((row) =>
        matches(query, row.domain, row.country),
      );
    case "secrets":
      return rows.secrets.filter((row) => matches(query, row.text));
    case "trackers":
      return rows.trackers.filter((row) =>
        matches(query, row.name, ...row.categories),
      );
    case "protections":
      return rows.protections.filter((row) =>
        matches(query, row.file, row.category, row.value),
      );
    default:
      return rows.files.filter((row) => matches(query, row.path));
  }
};

const summaryOf = (data: Json, sections: Sections): MobsfReport["summary"] => {
  const { findings, rows } = sections;
  const bySeverity = (level: Finding["severity"]) =>
    findings.filter(({ severity }) => severity === level).length;
  const score =
    record(data["appsec"])?.["security_score"] ?? data["security_score"];
  const cvss = data["average_cvss"];
  return {
    security_score: typeof score === "number" ? score : null,
    average_cvss: typeof cvss === "number" ? cvss : null,
    findings: {
      high: bySeverity("high"),
      warning: bySeverity("warning"),
      info: bySeverity("info"),
      secure: bySeverity("secure"),
    },
    permissions: rows.permissions.length,
    dangerous_permissions: rows.permissions.filter(
      ({ status }) => status === "dangerous",
    ).length,
    components: rows.components.length,
    exported_components: rows.components.filter(
      ({ exported }) => exported === true,
    ).length,
    binaries: rows.binaries.length,
    weak_binaries: rows.binaries.filter(({ weak }) => weak > 0).length,
    api_categories: rows.apis.length,
    endpoints: rows.endpoints.length,
    domains: rows.domains.length,
    flagged_domains: rows.domains.filter(
      ({ bad, ofac }) => bad || ofac === true,
    ).length,
    secrets: rows.secrets.length,
    trackers: rows.trackers.length,
    total_trackers: sections.totalTrackers,
    protections: rows.protections.length,
    files: rows.files.length,
  };
};

/** Normalize a MobSF report into its summary and one paged, filtered view. */
export const buildMobsfReport = (
  file: { readonly bytes: Buffer; readonly sha256: string },
  input: InspectMobsfReportInput,
  appFile: { readonly path: string; readonly sha256: string } | null,
  limitations: readonly string[],
): MobsfReport => {
  const data = parseMobsfReport(file.bytes);
  const sections = readSections(data);
  const app = appOf(data);
  const matching = filtered(sections, input);
  const page = matching.slice(input.offset, input.offset + input.limit);
  const empty: Rows = {
    findings: [],
    locations: [],
    permissions: [],
    components: [],
    binaries: [],
    apis: [],
    endpoints: [],
    domains: [],
    secrets: [],
    trackers: [],
    protections: [],
    files: [],
  };
  return {
    report: {
      path: input.path,
      sha256: file.sha256,
      bytes: file.bytes.length,
      mobsf_version: text(data["version"]),
      timestamp: text(data["timestamp"]),
      layout: sections.legacy ? "legacy" : "current",
      unread: [...sections.unread],
    },
    app,
    app_file:
      appFile === null
        ? null
        : {
            ...appFile,
            matches_report: appFile.sha256 === app.sha256?.toLowerCase(),
          },
    summary: summaryOf(data, sections),
    page: {
      view: input.view,
      severity: input.severity ?? null,
      section: input.section ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    ...empty,
    [input.view]: page,
    limitations: [...limitations],
  };
};
