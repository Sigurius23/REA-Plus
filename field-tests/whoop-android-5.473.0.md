# WHOOP Android 5.473.0: static REA+ pass

A second field test of REA+, after
[consensus.app](../consensus-open-source-rebuild/web-app-observations.md).
Everything here comes from the APK as data. The app was never installed or
run, no request was sent to WHOOP, and nothing was patched. Key and token
values found in the APK are recorded only as present.

## Source and integrity

APKMirror's download page answered with a Cloudflare bot challenge, which was
left alone. The user supplied an APKPure XAPK instead
(`WHOOP_5.473.0_APKPure.xapk`, SHA-256 `f6adb497…af148`).

| File | SHA-256 | Signature |
| --- | --- | --- |
| `com.whoop.android.apk` (base) | `db865d60…e699d` | v2 and v3 verified |
| `config.armeabi_v7a.apk` (native libraries) | `3e034083…064cd` | v2 and v3 verified |
| `config.xhdpi.apk` (density resources) | `16db3f49…44c4` | v2 and v3 verified |

All three are signed by one certificate: `CN=whoop.com, OU=Engineering,
O=WHOOP Inc., L=Boston, ST=MA, C=US`, SHA-256
`4ff1dac8482cce1e121eb197969f8634ba3408ee16a17197d4bbfcdb6db9c8e2`. The base
APK carries a Google Play source stamp (`com.android.stamp.*`). The
signatures were checked with `apksigtool`, since REA+ reports
`signature_verification: not_performed`.

## The app

| | |
| --- | --- |
| Package | `com.whoop.android`, version 5.473.0 (code 618174) |
| SDK | min 28 (Android 9), target 36 |
| Code | 11 DEX files: 83,367 classes, 47,244 top-level; 161 `com.whoop.*` feature packages |
| Resources | 4,957; strings in 9 locales |
| Application class | `com.whoop.WhoopApplication`; `allowBackup="false"` |

Feature packages map onto product areas: Advanced Labs (blood tests),
hormonal and pregnancy insights, weekly plan, an AI coach (`bot`, `ai`,
`sage`, `ai-conversation-service`), clinician-in-the-loop, ECG and
arrhythmia screening, Health Connect, community, membership, gifting and
native checkout.

## Permissions (70 distinct)

- **Health Connect:** read 25 record types, including heart rate, SpO2,
  temperature, blood pressure and glucose, menstruation and cervical mucus,
  nutrition and VO2 max. Write 10, including sleep, heart rate, steps and
  exercise.
- **Strap connection:** Bluetooth scan/connect, companion-device presence and
  background use, `FOREGROUND_SERVICE_CONNECTED_DEVICE`, boot completed.
- **Location:** fine, coarse and background, for GPS activities.
- **Calls:** camera, microphone, `MANAGE_OWN_CALLS` and the phone-call,
  camera and microphone foreground-service types, used by the video-call
  SDKs below.
- Other: notifications, biometrics, Wi-Fi state, user-selected photos.

## Components

68 activities, 31 services, 30 receivers and 6 providers; 17 components are
exported. The foreground services show what runs in the background:

| Service | Type |
| --- | --- |
| `WhoopSyncService`, `BleDeviceScannerService` | connected device |
| `RealTimeActivityService` (two), `TrackSessionService` | connected device, location |
| `FirmwareUpdateService`, `NewDfuService` (Nordic DFU) | connected device |
| `StrengthBuilderWorkoutService` | connected device |
| `WhoopLabsService` | connected device, data sync |
| `HMSScreenCaptureService` (100ms) | microphone, camera, media projection |
| `CallService` (Stream Video) | microphone, camera, phone call |

**Deep links.** `LinkingActivity` handles 106 verified paths on
`https://app.whoop.com`, such as `/SleepPillar`, `/advanced_labs_home`,
`/heart_screener`, `/whoop_coach` and `/external_auth`, plus the
`whoop://strength.builder` scheme. Invites use `/mobile-redir`.

## Network

**Hosts.** The API is `https://api.prod.whoop.com`. Others: `app.whoop.com`
(web app and links), `app-cdn.prod.whoop.com`, `cdn.whoop.com`,
`icons.whoop.com` and `videos.*.whoop.com` on S3, and `support.whoop.com`.
Dev and QA hosts (`app.dev`, `app.qa`, `status.dev`, `shop.qa`,
`videos.qa`) are left in the build.

**API paths.** 542 distinct paths across 74 services, all shaped
`<name>-service/v<N>/…`, which points to a microservice backend behind one
gateway. The full list is in
[whoop-android-5.473.0-api-paths.txt](whoop-android-5.473.0-api-paths.txt).

| Service | Paths | Examples |
| --- | --- | --- |
| community | 69 | teams, posts, reactions |
| onboarding | 41 | |
| membership | 36 | `billing/annual/switch`, `dunning/…`, `family-plan-invitations/mobile` |
| advanced-labs | 35 | lab tests and biomarkers |
| progression | 24 | |
| health | 23 | `hormonal-insights/settings/…`, `mci/cycles/hidden/{id}`, `pregnancy/onboarding/…` |
| weightlifting | 18 | |
| ai-conversation | 17 | `conversations/{conversationId}`, `…/message/{messageId}/action/{actionId}` |
| commerce, growth-content | 17 each | |
| womens-health | 16 | |
| journal | 15 | |
| users, smart-alarm, arrhythmia, ecg, clinician-in-the-loop | 10–12 each | `ecg/readings`, `v2/afibhistory/paginated` |
| auth | 6 | `v2/whoop/refresh`, `v2/oauth/code/{provider}`, `v3/whoop` |
| firmware | 5 | `v4/firmware/check`, `v4/firmware/version`, `v4/strap/unlock-token` |

149 paths have `{placeholders}`. For data access, WHOOP publishes an OAuth
developer API; these are the app's private routes.

**Transport security.** The network security config (`@xml/certificates`)
pins nothing. It trusts user-installed CAs only in debug builds. No OkHttp
pin strings (`sha256/…`) or `CertificatePinner` references were found.
Other forms of pinning were not ruled out.

## Bluetooth and devices

Codenames resolved from the app's own strings:

| Codename | Device |
| --- | --- |
| Harvard | WHOOP 4.0 |
| Goose | WHOOP 5.0 |
| Maverick | WHOOP MG |
| Puffin | battery pack (`com.whoop.puffin.network.BatteryPackApi`) |
| Kenmore, Copley | in enums and states; not identified |

**GATT layout.** Five custom UUID families share one pattern: `XXXX0001` is
the service and `XXXX0002`–`XXXX0007` are characteristics. The characteristic
constant names give their roles: `CMD_TO_STRAP`, `CMD_FROM_STRAP`,
`EVENTS_FROM_STRAP`, `DATA_FROM_STRAP` and `MEMFAULT` (device diagnostics).

| Family | Note |
| --- | --- |
| `61080001-8d6d-82b8-614a-1c8cb0f8dcc6` | matches the UUID community WHOOP 4.0 projects document |
| `fd4b0001-cce1-4033-93ce-002d5875f58a` | |
| `8a580001-2fe8-4796-9267-b87a2b0c8234` | |
| `59830001-5955-419b-bb8d-c8262926af23` | |
| `11500001-6215-11ee-8c99-0242ac120002` | time-based UUID created 2023-10-03 on a Docker host (node `02:42:ac:12:00:02`); the newest family |

The obfuscated classes `st0.w` (all five families) and `nj0.e` (four) hold
these as `UUID` fields. radare2 on `classes7.dex` shows `nj0.e`'s static
initializer: `a` = `61080001…`, `b` = `fd4b0001…`, `c` = `59830001…`,
`d` = `8a580001…`. Which family belongs to which device was not settled.

Standard services are used too: Heart Rate (`180D`, measurement `2A37`, the
strap's heart-rate broadcast), Battery (`180F`/`2A19`) and Nordic DFU
(`FE59`). Firmware updates use Nordic's DFU library. The base APK bundles one
DFU package, `assets/firmware/beacon-12_3_0_47_bootloader_app_softdevice-dfu.zip`
(June 2020): an nRF52840 application plus SoftDevice and bootloader.

**Data path.** Strap packets are queued in Room databases
(`PersistentStrapPacketDatabase`, `LabradorPacketDatabase`) and uploaded by
background workers; `LabradorNetworkApi.uploadEcgData` sends ECG readings,
called from one method (`ku1.a.c`). Straps are unlocked with a server-issued
token (`firmware-service/v4/strap/unlock-token`, package `strapauth`); that
mechanism was not examined further.

## Third-party SDKs

| Area | SDKs |
| --- | --- |
| Video calls | Stream Video (`io.getstream`, 3,134 classes), 100ms (`live.hms`), two WebRTC builds |
| Maps | Mapbox |
| Analytics and messaging | Amplitude (with its QuickJS engagement runtime and a 900 KB `engagement.js`), Iterable, Firebase |
| Payments | Stripe (Link, Financial Connections, Express Checkout through `assets/www`) |
| Monitoring | Sentry (Java and native) |
| Fraud and integrity | SEON device fingerprinting (`libseon`, `libseon2`, `libnatdet`, `libpgs`); RootBeer native root check (`libtoolChecker`) |
| Other | AWS SDK, Ktor, Koin, Room, Glance widgets, Health Connect, Nimbus JOSE |

The manifest carries a Google Maps API key and a Sentry DSN; their values are
not recorded here.

## How REA+ did

| Step | Tool | Result |
| --- | --- | --- |
| Manifest, permissions, counts | `inspect-android-package` | worked (33 s) after fix 1 |
| Resources and strings | `decode-android-resources` (Apktool 2.12.1) | worked, with gap 2 |
| Class inventory | `search-android-classes` | worked (30 s) after fix 2 |
| Members, method bodies | `inspect-android-class`, `inspect-android-method` | worked, with gap 3 |
| Callers | `trace-android-references` | worked (34 s) |
| Bundled web page | `analyze-javascript-application` | worked |
| Bundled firmware | `inspect-firmware-regions` | needs binwalk, not installed |

**Fixed in REA+ during this pass:**

1. The JADX readiness check rejected the pinned, audited
   `jadx-headless-mcp` 0.7.1 JAR, whose SHA-256 matches `JadxRelease.ts`,
   because the JAR repeats three license files. The check now lists entry
   names and accepts repeats; analyzed archives still reject them.
2. Class search failed on any app where JADX names two classes alike, which
   happens with R8 and Kotlin metadata (167 names here). It now lists each
   name once and returns the shared ones in `shared_names`.

**Gaps still open:**

1. No search over string constants or bytecode. Hosts, API paths and the
   UUID-holding classes were found with small DEX string-table and
   `const-string` scanners outside REA+. REA+'s binary tools (`search`,
   `xrefs`, disassembly through radare2 or Ghidra) would answer this, but
   they reject DEX files as an unsupported format. radare2 itself, run
   directly, found the loader of a UUID in 22 s and showed which field
   each UUID is stored in.
2. `decode-android-resources` returns the first 2,000 of 5,226 strings with
   no paging, and doesn't expose `res/xml` files such as the network
   security config.
3. Annotation values are not shown, so Retrofit paths can't be tied to their
   methods. Static field initial values are not shown either: JADX moves
   them out of `<clinit>`, so the UUID-to-field mapping isn't visible.
4. Split APKs, XAPK bundles and signatures are out of scope for the Android
   tools.

## Not done

- Running the app or its traffic; reading the strap protocol itself; the
  strap unlock and membership checks.
- Mapping UUID families to device generations, and the unidentified
  codenames (Kenmore, Copley).
