# MobSF reports

`inspect_mobsf_report` / `inspect-mobsf-report` reads the JSON report that
[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) writes for
a static analysis of an Android or iOS app. Use the web UI's JSON download,
or `/api/v1/report_json`. It turns the report into Evidence: what the app is,
what MobSF flagged and where, and what the app contains. For a mobile game
that means its native engine libraries, its deep links, the servers it talks
to, and the packers or anti-debug checks APKiD found.

MobSF is not run or contacted. REA+ reads the file it already wrote.

```sh
rea inspect-mobsf-report ~/scans/game.apk.json --json
rea inspect-mobsf-report game.apk.json --severity high --json
rea inspect-mobsf-report game.apk.json --view binaries --app_path ~/apks/game.apk --json
rea inspect-mobsf-report game.apk.json --view locations --section code --query android_logging --json
```

```json
{
  "name": "inspect_mobsf_report",
  "arguments": {
    "path": "/scans/game.apk.json",
    "view": "components",
    "query": "deeplink"
  }
}
```

## What the result contains

- `report`: SHA-256, MobSF version and timestamp. It also gives the layout:
  `current` for MobSF 3.6 to 4.x, or `legacy` for the bare lists and maps of
  MobSF 3.1. `unread` lists sections that were present in a shape the
  reader does not know. They are skipped, not guessed at.
- `app`: platform, file and app name, package name or bundle id, version and
  build, minimum and target SDK (or iOS version and SDK), main activity,
  size, MD5, SHA-1, SHA-256, and the signing certificate as MobSF printed it.
- `app_file` (with `app_path`): the APK or IPA's SHA-256, and whether it
  matches the report. A report of another build then shows up.
- `summary`: MobSF's security score and average CVSS, findings per severity,
  and counts for every view.
- `page` and one view, filtered by `severity`, `section` and `query`:
  - `findings` (default): one row per issue, with `section`, MobSF's `rule`
    id, title, severity, description, CWE, OWASP Mobile, MASVS, CVSS and
    reference. Each row has the components or scopes it is about, and the
    files and line numbers where MobSF found it (the first 200; see
    `locations`). The sections are:
    - `manifest`, `network` (network security config or iOS ATS),
      `certificate` and `code`;
    - `binary`: iOS binary code checks;
    - `macho`: weak hardening checks of the main iOS binary;
    - `hardening`: weak hardening checks of native libraries and frameworks;
    - `files`: certificate, key or plist files.
  - `locations`: every file and line list of every code rule, file finding
    and API rule (`section: "api"`), with no cap.
  - `permissions`: name, status, MobSF's text, and whether MobSF lists it
    among the permissions malware uses most.
  - `components`: activities, services, receivers and providers, and iOS URL
    schemes. Each row says whether it is the main activity and whether it is
    exported (activities only; MobSF lists no others), with deep-link
    schemes, hosts, paths and MIME types.
  - `binaries`: native libraries (`lib/<abi>/*.so`) and Mach-O binaries and
    frameworks, with every hardening check, its value and severity.
  - `apis`: API usage categories with the files that use them.
  - `endpoints`: URLs and emails with the source file, and Firebase
    databases with whether MobSF found them open.
  - `domains`: MobSF's malware and OFAC flags with geolocation.
  - `secrets`, `trackers` (Exodus Privacy signatures), `protections` (APKiD:
    packers, obfuscators, anti-debug, anti-VM and compilers per DEX file) and
    `files`.

## Severities

MobSF uses several labels. REA+ maps them onto four levels and keeps the
original label in `mobsf_severity`:

| MobSF label         | `severity` |
| ------------------- | ---------- |
| `high`, `insecure`  | `high`     |
| `warning`, `medium` | `warning`  |
| `info`, or none     | `info`     |
| `good`, `secure`    | `secure`   |

## Boundaries

- Findings and scores are MobSF's. They reflect the rules of the MobSF
  version that wrote the report, not a new analysis of the app.
- MobSF's own scorecard keeps six Mach-O checks and no library checks. REA+
  lists every weak check, under `macho` and `hardening`.
- MobSF records exported state only for activities. For services,
  receivers and providers, `exported` is `null`; manifest findings name the
  exported ones.
- Strings, NIAP analysis, Quark malware behaviour, the SBOM, store details
  and scan logs are not read.
- Secrets are listed as MobSF found them in the app's files.
- mobsfscan (MobSF's source-code scanner) writes a different format and is
  refused. Reports over 256 MiB are refused.

## Verification

`tests/boundary/providers/mobsf/mobsfReport.test.ts` builds reports in three
layouts: a MobSF 4.x Android game, a MobSF 4.x iOS game, and a MobSF 3.1
Android app. Their fields and nesting follow real reports and MobSF's report
builders. The tests read every view and filter. They check the location cap
and the uncapped `locations` view, the severity mapping, `app_path` matching
and mismatching, sections in unknown shapes, and refusals of non-JSON files,
JSON lists, mobsfscan output and relative or missing app files.

`REA_VERIFY_MOBSF_DIR` points the tests at a folder of real reports. Every
report must read with no unread sections. Counts must match the raw report,
and the findings must agree with the `appsec` scorecard MobSF wrote into it:
the same section, severity and title for every entry, and nothing extra.

The lane passed on nine reports written by MobSF 3.1.6, 3.1.9, 3.6.7, 3.7.9
and 4.0.7. They cover Android (DIVA, Allsafe, InsecureShop, Damn Vulnerable
Bank) and iOS (DVIA-v2 and two other apps), from
[DefectDojo's parser tests](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/mobsf).
The six that carry a full scorecard matched it exactly. No report from MobSF
4.1 or later was available. Their layout was checked against MobSF 4.5.4's
source, not against a file it wrote.
