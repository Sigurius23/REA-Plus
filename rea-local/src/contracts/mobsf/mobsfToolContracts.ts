import {
  inspectMobsfReportInputSchema,
  mobsfReportSchema,
} from "../../domain/mobsf/mobsfReport.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free MobSF report reader with CLI/MCP parity; MobSF is never contacted. */
export const MOBSF_TOOL_CONTRACTS = [
  {
    name: "inspect_mobsf_report",
    ...toolContractMetadata("inspect_mobsf_report"),
    kind: "artifact-provider",
    description:
      "Read a MobSF static-analysis JSON report of an Android or iOS app (MobSF 3.1 to 4.x) and return Evidence of what MobSF found: the app's identity, version, SDK levels, hashes and signing certificate; MobSF's security score; counts; then one paged view. findings lists manifest, network, certificate, code, binary and hardening issues with severity, CWE, OWASP Mobile, MASVS and CVSS, and the files and lines they were found at; locations lists every file of every finding or API rule; permissions, components (activities, services, receivers, providers and URL schemes with exported state and deep links), binaries (native library and Mach-O hardening checks), apis, endpoints (URLs, emails, Firebase databases), domains, secrets, trackers, protections (APKiD packers, obfuscators, anti-debug and anti-VM) and files list the rest. Filter with severity, section and query. With app_path, the APK or IPA is hashed and compared with the SHA-256 the report names, so a report of another build shows up. MobSF is not run or contacted.",
    inputSchema: inspectMobsfReportInputSchema,
    outputSchema: evidenceResultOf(mobsfReportSchema),
    examples: [
      {
        title: "List the high-severity findings of a MobSF scan",
        input: { path: "/scans/game.apk.json", severity: "high" },
      },
      {
        title: "Check a report against the APK and list its native libraries",
        input: {
          path: "/scans/game.apk.json",
          view: "binaries",
          app_path: "/games/game.apk",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
