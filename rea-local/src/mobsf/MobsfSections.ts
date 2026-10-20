import type { MobsfReport } from "../domain/mobsf/mobsfReport.js";
import {
  type Json,
  MAX_ROW_LOCATIONS,
  finding,
  firstSentence,
  isLegacyLayout,
  list,
  locationsOf,
  number,
  plain,
  quotedList,
  record,
  severityOf,
  strings,
  text,
} from "./MobsfValues.js";

/**
 * Normalizes the sections of a MobSF static-analysis report. MobSF changed
 * several layouts between releases (manifest and network findings became
 * objects, code findings moved under `findings`, iOS permissions became a
 * map), so every reader accepts both shapes and records sections it found in
 * neither as unread instead of failing.
 */

type Finding = MobsfReport["findings"][number];
type Binary = MobsfReport["binaries"][number];
type Component = MobsfReport["components"][number];

/** Collects what each section yields and which sections had an unknown shape. */
export class SectionReader {
  readonly unread = new Set<string>();

  constructor(readonly data: Json) {}

  /** The value of a present section, or null; a wrong shape is recorded as unread. */
  section<T>(name: string, read: (value: unknown) => T | null): T | null {
    const value = this.data[name];
    if (value === undefined || value === null) return null;
    const result = read(value);
    if (result === null) this.unread.add(name);
    return result;
  }

  get legacy(): boolean {
    return isLegacyLayout(this.data);
  }

  manifest(): Finding[] {
    return (
      this.section("manifest_analysis", (value) => {
        const items = list(record(value)?.["manifest_findings"] ?? value);
        return (
          items?.flatMap((item) => {
            const entry = record(item);
            if (entry === null) return [];
            const [title = "", ...rest] = plain(
              text(entry["title"]) ?? "",
            ).split("\n");
            const description =
              text(entry["description"] ?? entry["desc"]) ?? "";
            return [
              finding({
                section: "manifest",
                rule: text(entry["rule"]),
                title: title.trim(),
                label: text(entry["severity"] ?? entry["stat"]),
                description: [
                  ...rest.map((line) => line.trim()),
                  plain(description),
                ]
                  .filter((line) => line !== "")
                  .join("\n"),
                components: strings(entry["component"]),
              }),
            ];
          }) ?? null
        );
      }) ?? []
    );
  }

  network(): Finding[] {
    const android =
      this.section("network_security", (value) =>
        list(record(value)?.["network_findings"] ?? value),
      ) ?? [];
    const ios =
      this.section("ats_analysis", (value) =>
        list(record(value)?.["ats_findings"] ?? value),
      ) ?? [];
    return [...android, ...ios].flatMap((item) => {
      const entry = record(item);
      if (entry === null) return [];
      const description = plain(text(entry["description"]) ?? "");
      return [
        finding({
          section: "network",
          // MobSF's scorecard titles a network finding with its first sentence.
          title:
            text(entry["issue"]) ?? description.split(".")[0] ?? description,
          label: text(entry["severity"] ?? entry["status"]),
          description,
          components: strings(entry["scope"]),
        }),
      ];
    });
  }

  certificate(): Finding[] {
    return (
      this.section("certificate_analysis", (value) => {
        const entries = record(value);
        if (entries === null) return null;
        if (!("certificate_findings" in entries)) return [];
        return (
          list(entries["certificate_findings"])?.flatMap((item) => {
            const [label, description, title] = strings(item);
            if (label === undefined || description === undefined) return [];
            return [
              finding({
                section: "certificate",
                title: title ?? firstSentence(description),
                label,
                description,
              }),
            ];
          }) ?? null
        );
      }) ?? []
    );
  }

  /** Code and API rules share one layout: id → { files, metadata }. */
  private rules(name: string): [string, Json, Json][] {
    return (
      this.section(name, (value) => {
        const outer = record(value);
        if (outer === null) return null;
        const rules = record(outer["findings"]) ?? outer;
        return Object.entries(rules).flatMap(([id, item]) => {
          const entry = record(item);
          const metadata = record(entry?.["metadata"]);
          return entry === null || metadata === null
            ? []
            : [[id, entry, metadata] as [string, Json, Json]];
        });
      }) ?? []
    );
  }

  code(): Finding[] {
    return this.rules("code_analysis").map(([id, entry, metadata]) =>
      finding({
        section: "code",
        rule: id,
        title: plain(text(metadata["description"]) ?? id),
        label: text(metadata["severity"]),
        description: plain(text(metadata["description"]) ?? ""),
        cwe: text(metadata["cwe"]) || null,
        owasp_mobile: text(metadata["owasp-mobile"]) || null,
        masvs: text(metadata["masvs"]) || null,
        cvss: number(metadata["cvss"]),
        reference: text(metadata["ref"]) || null,
        locations: locationsOf(entry["files"]),
      }),
    );
  }

  apis(): MobsfReport["apis"] {
    return [...this.rules("android_api"), ...this.rules("ios_api")].map(
      ([id, entry, metadata]) => {
        const files = locationsOf(entry["files"]);
        return {
          id,
          description: plain(text(metadata["description"]) ?? id),
          severity: severityOf(text(metadata["severity"])),
          file_count: files.length,
          files: files.slice(0, MAX_ROW_LOCATIONS),
        };
      },
    );
  }

  /** Every file of every code rule, uncapped. */
  codeLocations(): { rule: string; path: string; lines: number[] }[] {
    return this.rules("code_analysis").flatMap(([rule, entry]) =>
      locationsOf(entry["files"]).map((location) => ({ rule, ...location })),
    );
  }

  apiLocations(): {
    section: string;
    rule: string;
    path: string;
    lines: number[];
  }[] {
    return [...this.rules("android_api"), ...this.rules("ios_api")].flatMap(
      ([rule, entry]) =>
        locationsOf(entry["files"]).map((location) => ({
          section: "api",
          rule,
          ...location,
        })),
    );
  }

  fileLocations(): { rule: string; path: string; lines: number[] }[] {
    return this.files().flatMap((row) => {
      const entry = (list(this.data["file_analysis"]) ?? [])
        .map(record)
        .find(
          (item) => text(item?.["finding"] ?? item?.["issue"]) === row.title,
        );
      return locationsOf(entry?.["files"]).map((location) => ({
        rule: row.title,
        ...location,
      }));
    });
  }

  /** iOS binary findings: title → { detailed_desc, severity, cwe... }. */
  binaryFindings(): Finding[] {
    const value = this.data["binary_analysis"];
    if (Array.isArray(value)) return [];
    return (
      this.section("binary_analysis", (raw) => {
        const outer = record(raw);
        if (outer === null) return null;
        const rules = record(outer["findings"]) ?? outer;
        return Object.entries(rules).flatMap(([title, item]) => {
          const entry = record(item);
          if (entry === null || !("detailed_desc" in entry)) return [];
          return [
            finding({
              section: "binary",
              title,
              label: text(entry["severity"]),
              description: plain(text(entry["detailed_desc"]) ?? "").replace(
                /\n,/gu,
                ",",
              ),
              cwe: text(entry["cwe"]) || null,
              owasp_mobile: text(entry["owasp-mobile"]) || null,
              masvs: text(entry["masvs"]) || null,
              cvss: number(entry["cvss"]),
            }),
          ];
        });
      }) ?? []
    );
  }

  /** Hardening checks per native library (Android) or Mach-O binary (iOS). */
  binaries(): Binary[] {
    const read = (kind: Binary["kind"]) => (item: unknown) => {
      const entry = record(item);
      const name = text(entry?.["name"]);
      if (entry === null || name === null) return [];
      const checks = Object.entries(entry).flatMap(([check, raw]) => {
        const result = record(raw);
        if (result === null || !("severity" in result)) return [];
        const value = Object.entries(result).find(
          ([key]) => key !== "severity" && key !== "description",
        )?.[1];
        return [
          {
            check,
            value:
              typeof value === "string" ||
              typeof value === "number" ||
              typeof value === "boolean"
                ? value
                : null,
            severity: severityOf(text(result["severity"])),
            description: plain(text(result["description"]) ?? ""),
          },
        ];
      });
      return [
        {
          name,
          kind,
          weak: checks.filter(
            ({ severity }) => severity === "high" || severity === "warning",
          ).length,
          checks,
        },
      ];
    };
    const android = Array.isArray(this.data["binary_analysis"])
      ? (this.section("binary_analysis", list) ?? []).flatMap(read("library"))
      : [];
    const macho = this.section("macho_analysis", (value) => {
      const entry = record(value);
      return entry === null
        ? null
        : Object.keys(entry).length === 0
          ? []
          : read("executable")(entry);
    });
    return [
      ...android,
      ...(macho ?? []),
      ...(this.section("framework_analysis", list) ?? []).flatMap(
        read("framework"),
      ),
      ...(this.section("dylib_analysis", list) ?? []).flatMap(read("dylib")),
    ];
  }

  files(): Finding[] {
    return (
      this.section("file_analysis", list)?.flatMap((item) => {
        const entry = record(item);
        const title = text(entry?.["finding"] ?? entry?.["issue"]);
        if (entry === null || title === null) return [];
        return [
          finding({
            section: "files",
            title,
            label: null,
            locations: locationsOf(entry["files"]),
          }),
        ];
      }) ?? []
    );
  }

  permissions(): MobsfReport["permissions"] {
    const malware = list(
      record(this.data["malware_permissions"])?.["top_malware_permissions"],
    );
    const top = malware === null ? null : new Set(strings(malware));
    const row = (name: string, entry: Json, legacyIos: boolean) => ({
      name,
      status: text(entry["status"]) ?? "",
      // Legacy iOS reports put Apple's text in description and the app's reason in reason.
      info: text(legacyIos ? entry["description"] : entry["info"]),
      description: text(
        legacyIos ? entry["reason"] : (entry["description"] ?? entry["reason"]),
      ),
      malware_top: top === null ? null : top.has(name),
    });
    return (
      this.section("permissions", (value) => {
        const map = record(value);
        if (map !== null)
          return Object.entries(map).flatMap(([name, item]) => {
            const entry = record(item);
            return entry === null ? [] : [row(name, entry, false)];
          });
        return (
          list(value)?.flatMap((item) => {
            const entry = record(item);
            const name = text(entry?.["name"]);
            return entry === null || name === null
              ? []
              : [row(name, entry, true)];
          }) ?? null
        );
      }) ?? []
    );
  }

  components(): Component[] {
    const main = text(this.data["main_activity"]);
    const exported = new Set(quotedList(this.data["exported_activities"]));
    const browsable = record(this.data["browsable_activities"]) ?? {};
    const deepLink = (name: string) => {
      const entry = record(browsable[name]) ?? {};
      return {
        schemes: strings(entry["schemes"]),
        hosts: strings(entry["hosts"]),
        paths: [
          ...strings(entry["paths"]),
          ...strings(entry["path_prefixs"]),
          ...strings(entry["path_patterns"]),
        ],
        mime_types: strings(entry["mime_types"]),
      };
    };
    const kinds = [
      ["activity", "activities"],
      ["service", "services"],
      ["receiver", "receivers"],
      ["provider", "providers"],
    ] as const;
    const android = kinds.flatMap(([kind, key]) =>
      strings(this.section(key, list)).map((name) => ({
        kind,
        name,
        main: kind === "activity" && name === main,
        exported: kind === "activity" ? exported.has(name) : null,
        ...deepLink(name),
      })),
    );
    const ios = (this.section("bundle_url_types", list) ?? []).flatMap(
      (item) => {
        const entry = record(item);
        if (entry === null) return [];
        const schemes = strings(entry["CFBundleURLSchemes"]);
        const name = text(entry["CFBundleURLName"]) ?? schemes[0];
        return name === undefined
          ? []
          : [
              {
                kind: "url-scheme" as const,
                name,
                main: false,
                exported: true,
                schemes,
                hosts: [],
                paths: [],
                mime_types: [],
              },
            ];
      },
    );
    return [...android, ...ios];
  }

  endpoints(): MobsfReport["endpoints"] {
    const grouped = (name: string, key: string, kind: "url" | "email") =>
      (this.section(name, list) ?? []).flatMap((item) => {
        const entry = record(item);
        const path = text(entry?.["path"]);
        return strings(entry?.[key]).map((value) => ({
          kind,
          value,
          path,
          open: null,
        }));
      });
    const firebase = (this.section("firebase_urls", list) ?? []).flatMap(
      (item) => {
        const entry = record(item);
        const value = text(entry?.["url"]) ?? text(item);
        const open = entry?.["open"];
        return value === null
          ? []
          : [
              {
                kind: "firebase" as const,
                value,
                path: null,
                open: typeof open === "boolean" ? open : null,
              },
            ];
      },
    );
    return [
      ...grouped("urls", "urls", "url"),
      ...grouped("emails", "emails", "email"),
      ...firebase,
    ];
  }

  domains(): MobsfReport["domains"] {
    return Object.entries(this.section("domains", record) ?? {}).flatMap(
      ([domain, item]) => {
        const entry = record(item);
        if (entry === null) return [];
        const where = record(entry["geolocation"]) ?? {};
        const ofac = entry["ofac"];
        return [
          {
            domain,
            bad: text(entry["bad"])?.toLowerCase() === "yes",
            ofac: typeof ofac === "boolean" ? ofac : null,
            ip: text(where["ip"]),
            country: text(where["country_long"]),
            region: text(where["region"]),
            city: text(where["city"]),
          },
        ];
      },
    );
  }

  secrets(): MobsfReport["secrets"] {
    return strings(this.section("secrets", list)).map((value) => ({
      text: value,
    }));
  }

  trackers(): { rows: MobsfReport["trackers"]; total: number | null } {
    const entry = this.section("trackers", record);
    const rows = (list(entry?.["trackers"]) ?? []).flatMap((item) => {
      const tracker = record(item);
      const name = text(tracker?.["name"]);
      return tracker === null || name === null
        ? []
        : [
            {
              name,
              categories: (text(tracker["categories"]) ?? "")
                .split(",")
                .map((part) => part.trim())
                .filter((part) => part !== ""),
              url: text(tracker["url"]),
            },
          ];
    });
    const total = entry?.["total_trackers"];
    return { rows, total: typeof total === "number" ? total : null };
  }

  protections(): MobsfReport["protections"] {
    return Object.entries(this.section("apkid", record) ?? {}).flatMap(
      ([file, item]) =>
        Object.entries(record(item) ?? {}).flatMap(([category, values]) =>
          strings(values).map((value) => ({ file, category, value })),
        ),
    );
  }

  fileList(): MobsfReport["files"] {
    return locationsOf(this.section("files", list)).map(({ path }) => ({
      path,
    }));
  }
}
