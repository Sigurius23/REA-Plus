import type { MobsfReport } from "../domain/mobsf/mobsfReport.js";

/** Value readers shared by the MobSF section readers; every one tolerates missing or mistyped fields. */

export type Severity = MobsfReport["findings"][number]["severity"];
type Finding = MobsfReport["findings"][number];
type Location = Finding["locations"][number];

export type Json = Readonly<Record<string, unknown>>;

export const record = (value: unknown): Json | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Json)
    : null;
export const list = (value: unknown): readonly unknown[] | null =>
  Array.isArray(value) ? value : null;
export const text = (value: unknown): string | null =>
  typeof value === "string"
    ? value
    : typeof value === "number" && Number.isFinite(value)
      ? String(value)
      : null;
export const number = (value: unknown): number | null => {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string" || value.trim() === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};
export const strings = (value: unknown): string[] =>
  (list(value) ?? []).flatMap((item) => {
    const value = text(item);
    return value === null ? [] : [value];
  });

export const SEVERITIES: Readonly<Record<string, Severity>> = {
  high: "high",
  insecure: "high",
  danger: "high",
  warning: "warning",
  medium: "warning",
  info: "info",
  good: "secure",
  secure: "secure",
};

/** MobSF's labels mapped onto four levels; good becomes secure, medium warning. */
export const severityOf = (label: string | null): Severity =>
  SEVERITIES[(label ?? "").toLowerCase()] ?? "info";

/** MobSF titles carry HTML from its templates. */
export const plain = (value: string): string =>
  value
    .replace(/<br\s*\/?>/giu, "\n")
    .replace(/<\/?[a-z][^>]*>/giu, "")
    .replace(/&nbsp;/gu, " ")
    .trim();

export const firstSentence = (value: string): string => {
  const end = value.indexOf(". ");
  return end < 0 ? value.replace(/\.$/u, "") : value.slice(0, end);
};

/** "218,332,555" → [218, 332, 555], ascending and unique. */
export const linesOf = (value: unknown): number[] =>
  [
    ...new Set(
      (text(value) ?? "")
        .split(",")
        .map((part) => Number(part.trim()))
        .filter((line) => Number.isInteger(line) && line >= 0),
    ),
  ].sort((left, right) => left - right);

/** A MobSF `files` map (path → line list), or a list of paths. */
export const locationsOf = (value: unknown): Location[] => {
  const map = record(value);
  if (map !== null)
    return Object.entries(map).map(([path, lines]) => ({
      path,
      lines: linesOf(lines),
    }));
  return (list(value) ?? []).flatMap((item) => {
    const path = text(item) ?? text(record(item)?.["file_path"]);
    return path === null ? [] : [{ path, lines: [] }];
  });
};

export const MAX_ROW_LOCATIONS = 200;

export const finding = (
  values: Partial<Omit<Finding, "locations" | "location_count">> &
    Pick<Finding, "section" | "title"> & {
      readonly label: string | null;
      readonly locations?: readonly Location[];
    },
): Finding => {
  const locations = values.locations ?? [];
  return {
    section: values.section,
    rule: values.rule ?? null,
    title: values.title,
    severity: severityOf(values.label),
    mobsf_severity: values.label ?? "",
    description: values.description ?? "",
    cwe: values.cwe ?? null,
    owasp_mobile: values.owasp_mobile ?? null,
    masvs: values.masvs ?? null,
    cvss: values.cvss ?? null,
    reference: values.reference ?? null,
    components: values.components ?? [],
    location_count: locations.length,
    locations: locations.slice(0, MAX_ROW_LOCATIONS),
  };
};

/** MobSF stores the exported activity list as a Python list literal, or as a list. */
export const quotedList = (value: unknown): string[] => {
  if (Array.isArray(value)) return strings(value);
  const source = text(value) ?? "";
  return [...source.matchAll(/'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"/gu)].map(
    (match) => match[1] ?? match[2] ?? "",
  );
};

/** MobSF 3.1 wrote findings as bare lists and maps; 3.6 and later wrap them. */
export const isLegacyLayout = (data: Json): boolean => {
  const wrapped = (name: string, key: string) => {
    const value = record(data[name]);
    return value === null || Object.keys(value).length === 0 || key in value;
  };
  const binary = data["binary_analysis"];
  // Legacy iOS reports also list permissions; Android reports always map them.
  const iosPermissionList =
    Array.isArray(data["permissions"]) && data["bundle_id"] !== undefined;
  return (
    ["manifest_analysis", "network_security", "ats_analysis"].some((name) =>
      Array.isArray(data[name]),
    ) ||
    iosPermissionList ||
    !wrapped("code_analysis", "findings") ||
    (!Array.isArray(binary) && !wrapped("binary_analysis", "findings"))
  );
};
