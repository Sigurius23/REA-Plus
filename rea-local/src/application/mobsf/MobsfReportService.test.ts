import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { MobsfReport } from "../../domain/mobsf/mobsfReport.js";
import { ok } from "../../domain/result.js";
import { MobsfReportService } from "./MobsfReportService.js";

const PATH = "/scans/game.apk.json";
const DIGEST = "a".repeat(64);
const finding = (
  severity: MobsfReport["findings"][number]["severity"],
  section = "manifest",
): MobsfReport["findings"][number] => ({
  section,
  rule: "clear_text_traffic",
  title: "Clear text traffic is Enabled For App",
  severity,
  mobsf_severity: severity,
  description: "",
  cwe: null,
  owasp_mobile: null,
  masvs: null,
  cvss: null,
  reference: null,
  components: [],
  location_count: 0,
  locations: [],
});
const report = (): MobsfReport => ({
  report: {
    path: PATH,
    sha256: DIGEST,
    bytes: 10,
    mobsf_version: "v4.0.7",
    timestamp: null,
    layout: "current",
    unread: [],
  },
  app: {
    platform: "android",
    file_name: "game.apk",
    app_name: "Game",
    app_type: "apk",
    identifier: "com.game",
    version: "1.0",
    build: "1",
    min_sdk: "21",
    target_sdk: "34",
    main_activity: null,
    certificate: null,
    size: "1MB",
    md5: null,
    sha1: null,
    sha256: DIGEST,
  },
  app_file: null,
  summary: {
    security_score: 50,
    average_cvss: null,
    findings: { high: 1, warning: 0, info: 0, secure: 0 },
    permissions: 0,
    dangerous_permissions: 0,
    components: 0,
    exported_components: 0,
    binaries: 0,
    weak_binaries: 0,
    api_categories: 0,
    endpoints: 0,
    domains: 0,
    flagged_domains: 0,
    secrets: 0,
    trackers: 0,
    total_trackers: null,
    protections: 0,
    files: 0,
  },
  page: {
    view: "findings",
    severity: "high",
    section: "manifest",
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  findings: [finding("high")],
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
  limitations: [],
});
const service = (value: MobsfReport) =>
  new MobsfReportService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "mobsf", name: "mobsf", version: "1" },
            { subject: { path: PATH, format: "file", sha256: DIGEST } },
          ),
        ),
      ),
  });
const INPUT = { path: PATH, severity: "high", section: "manifest", limit: 1 };

it.each([
  { path: "game.apk.json" },
  { path: PATH, app_path: "game.apk" },
  { path: PATH, view: "strings" },
  { path: PATH, severity: "critical" },
  { path: PATH, limit: 0 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new MobsfReportService({
    close: () => Promise.resolve(),
    inspect: () => {
      throw new Error("Must not execute");
    },
  });
  expect(await unused.inspect(input)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
});

it.each([
  "path",
  "view",
  "severity",
  "section",
  "rows",
  "page",
  "digest",
  "app_file",
  "other view",
])("rejects a report that drifts from the request: %s", async (problem) => {
  const value = report();
  if (problem === "path") value.report.path = "/other.json";
  if (problem === "view") value.page.view = "permissions";
  if (problem === "severity") value.findings = [finding("warning")];
  if (problem === "section") value.findings = [finding("high", "code")];
  if (problem === "rows") value.findings.push(finding("high"));
  if (problem === "page") value.page.offset = 2;
  if (problem === "digest") value.report.sha256 = "b".repeat(64);
  if (problem === "app_file")
    value.app_file = {
      path: "/game.apk",
      sha256: DIGEST,
      matches_report: true,
    };
  if (problem === "other view") value.secrets = [{ text: "x" }];
  expect(await service(value).inspect(INPUT)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisOutputError" },
  });
});

it("records the report as observed Evidence", async () => {
  expect(await service(report()).inspect(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "inspect_mobsf_report", confidence: "observed" },
  });
});
