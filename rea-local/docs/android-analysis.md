# Static Android APK analysis

REA+ wraps an existing headless JADX engine through `src/android/`. Its source is
kept as an unmodified, commit-pinned Git submodule; see
[upstream provenance](https://github.com/morluto/rea/blob/main/third_party/README.md). CLI and MCP use the same
application workflow and return artifact-bound Evidence inline.

This family is present on repository main and in npm 4.1.0. Check the
[released package boundary](installation.md#released-package-and-main) and the
connected server's tool list before selecting it.

## Supply tools

Use a **full JDK 17 or newer** (including its compiler module) and
**jadx-headless-mcp 0.7.1**. REA+ runs its packaged Java metadata bridge in
source-file mode against the unmodified engine JAR. REA+ does not install Java,
an Android SDK, JADX, a device service or an emulator. Set the path in the shell
or MCP server environment:

```sh
export REA_JADX_MCP_JAR=/absolute/path/jadx-headless-mcp-0.7.1-all.jar
# Optional: select an existing JDK rather than java on PATH.
export JAVA_HOME=/absolute/path/existing-jdk
```

On Windows x64, use a REA+ package with its matching bundled Windows native
controls **including owned protocol stdin support**. This Windows boundary is
new on repository main; an older released package can still reject this host.
PowerShell accepts paths containing spaces without additional escaping
inside these environment values:

```powershell
$env:REA_JADX_MCP_JAR = 'D:\tools\jadx-headless-mcp-0.7.1-all.jar'
$env:JAVA_HOME = 'D:\tools\jdk-21'
rea inspect-android-package 'D:\targets\Example.apk'
```

REA+ selects `JAVA_HOME\bin\java.exe`, or resolves `java.exe` on the selected
Windows `PATH`. A missing or mismatched native artifact reports the package
prerequisite rather than attempting an unowned Java launch. Windows arm64 is
outside this provider's current native boundary.

Readiness checks the selected JAR's ZIP directory for the classes consumed by
REA+'s metadata bridge, as well as Java's compiler and version modules. It does
not load an APK or execute engine code. Invalid archives and missing bridge
classes report JAR-specific recovery; classpath inventory alone does not prove
that every class or engine operation will load successfully. Discovery limits
each ZIP metadata read to 8 MiB before allocation; a larger directory reports
the exhausted read budget and the selected JAR path.

The current metadata bridge is verified on macOS arm64 with OpenJDK 21 and the
public Appium ApiDemos fixture. The POSIX adapter also supports Linux; the new
bridge has not yet undergone real verification on Linux/JDK 25. On Linux x64
with OpenJDK 21 and the pinned JAR, all five operations ran against a
production APK (WHOOP 5.473.0: 11 DEX files, 47,244 top-level classes).

Readiness lists the JAR's entry names and accepts repeated ones: the pinned
release repeats `LICENSE`, `META-INF/LICENSE` and `META-INF/LICENSE.txt` from
the dependencies shaded into it. APKs and other analyzed archives still reject
repeated entry names.
Windows x64 uses an owned Job Object with bidirectional stdio, atomic job
assignment and kill-on-owner-close. Real Windows verification uses JDK 21 and
the pinned JADX 0.7.1 JAR; see the real verification lane below.

## Answer an analyst question

```sh
rea inspect-android-package /path/Example.apk
rea search-android-classes /path/Example.apk MainActivity
rea inspect-android-class /path/Example.apk example.MainActivity
rea inspect-android-method /path/Example.apk example.MainActivity onCreate
rea inspect-android-method /path/Example.apk example.MainActivity select --overload-index 1
rea trace-android-references /path/Example.apk example.MainActivity
rea trace-android-references /path/Example.apk example.MainActivity --method-name onCreate
```

Equivalent MCP methods are `inspect_android_package`, `search_android_classes`,
`inspect_android_class`, `inspect_android_method` and `trace_android_references`.
Every request includes `path`. Class/method operations use `class_name`,
`method_name` and optional `overload_index` as applicable. For example:

```json
{
  "name": "inspect_android_method",
  "arguments": {
    "path": "/path/Example.apk",
    "class_name": "example.MainActivity",
    "method_name": "select",
    "overload_index": 1
  }
}
```

Use `inspect_android_class` to choose an overload. REA+ rejects an ambiguous
method request rather than silently selecting the first match. The engine's
method reference operation cannot select overloads, so REA+ reports that boundary
as unsupported when multiple same-name methods exist.

The engine's smali fallback also joins same-name overloads; REA+ rejects that
fallback for an overloaded method instead of attributing all bodies to one
selected overload. Native/abstract methods with no decompiled body report
`body_status: "not_available"` without inferring which implementation flag caused it.

## Open one DEX member inside an APK container

The generic binary/session layer (CLI `analyze`, `inspect`, `decompile`,
`xrefs`, `search`, MCP `open_binary` and the other target-accepting operations)
accepts a `container#member` fragment to analyze one DEX file inside an APK (or
any ZIP-package container) without manual extraction:

```sh
rea analyze /path/Example.apk#classes2.dex
rea analyze /path/Example.apk#classes2.dex --provider ghidra
```

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "/path/Example.apk#classes2.dex"
  }
}
```

The container is verified by its ZIP directory and SHA-256 first; the selected
member must be a top-level `.dex` entry. REA+ streams the member into a staging
file beside the container (`app-extracted/classes2.dex`), reuses an equally
digested stage on later opens, classifies the staged bytes as Dalvik, and then
admits the extracted DEX target to any DEX-capable provider (`radare2`,
`ghidra`). The open result stays bound to the staged file; the container path,
container digest and member name are retained as provenance
(`container_selection`) on the resolved target.

Pass `--staging-dir` (CLI) or `staging_dir` (MCP `open_binary`) to stage
extractions under a caller-owned directory instead of beside the container.
Staged files are not deleted by resolution: delete them with close or manually.
Filename-level boundaries stay explicit: the fragment applies only when the
part before `#` exists as a readable file (a file literally named
`odd#name.apk` still resolves whole), other container kinds report
`requires a ZIP-based container`, non-`.dex` member names are rejected before
the archive is read, and a missing member lists the container's DEX members.
Errors list exact member names so callers can pick the right `classesN.dex`.
The Android-specific `inspect_android_*` operations keep whole-package semantics
and do not fragment-match: pass those operations the container path itself.

## Analyze a XAPK container

The five Android operations admit `.xapk` packages (crucible/XAPK-style ZIP
containers) in addition to standalone APKs. Admission composes the analysis
image the engine actually loads, instead of copying the container into the
session's private runtime root:

- The container must carry a top-level `manifest.json` and one readable,
  top-level `base.apk`; mis-shaped containers are refused with their
  disproportionate or nested members listed as ignored.
- The base module's entries are copied into a stored-entry `bundle.apk` as-is
  (manifest, resources, native libraries, signing metadata), so the loaded
  package stays byte-derived from `base.apk`.
- Every other top-level APK member (split APKs) contributes only its `*.dex`
  entries. A colliding declared name — each split ships its own `classes.dex` —
  is kept under `splits/<member>/<name>`, e.g.
  `splits/split_config.arm64_v8a/classes.dex`, so jadx decompiles all of them.
- Split resources, native libraries and member signatures are deliberately not
  merged, and the image is not the signed install package; the Evidence
  limitations state the merged members and entry count for every XAPK request.
- Composition happens once per admitted container, streamed with constant
  memory, capped at a 4 GiB image and 65,535 entries. Failed admission leaves
  no composed image. A stable container yields a byte-stable image and SHA-256.

The inspection result then reflects the merged Java code: class counts include
split DEX entries. The retained session still numbers the _composed_ input,
while Evidence subject fields keep the original container path and its SHA-256.
Inventory and extraction treat `.xapk` like any other ZIP package family.

## Interpret the result

- Package inspection retains decoded manifest XML, summary declarations,
  permissions and class/resource counts. Summary fields are extracted by the
  upstream engine and should be checked against the retained XML when needed.
  Signature verification is explicitly `not_performed`.
- Class search consumes all pages and checks their counts. An empty `query`
  inventories all class names; class names are decompiler representations.
- Class inventories read parsed metadata without generating source and return
  full reported display types, fields and inner class names. Synthetic members
  that code generation hides can appear in the inventory; it stays consistent
  after method decompilation within the retained session.
  Exact DEX descriptors are unknown. Overload indices are tied to this artifact
  and engine, not stable identities across different builds.
- Class and method inspection also project the declared dex annotations and (for
  classes) encoded static field initial values into `annotations` and
  `static_inits`, with `value_coverage: "partial"` whenever a projection limit
  cut something. Values are parsed dex data, not runtime loading: Retrofit
  endpoint strings, BLE UUID-like constants and other encoded values appear as
  typed `{kind, value}` records. Field, enum and method references keep only
  their identity strings; type references are descriptors such as
  `Lretrofit2/http/GET;`. Annotation visibility is reported as build, runtime or
  system. Integer and float encoded values are JSON numbers, but a `long` beyond
  the safe JSON integer range is reported as its decimal string.
- Method inspection reports Java or smali, fallback markers and complete/partial
  returned text. Decompiled source is a derived representation. A complete text
  result does not establish complete semantics or a byte-identical reconstruction.
- Reference results are incoming static relationships between provider nodes.
  Source lines and DEX instruction offsets remain unknown. They are not observed
  runtime calls.
- Original requests, APK SHA-256, actual engine JAR SHA-256 and raw producer
  responses remain in Evidence. Source revision is populated only for bytes
  matching the audited release JAR.

If a later step fails, the error's `details.partial_observation` retains the
selected and resolved APK paths, digest, observed provider identity and versions,
and each upstream request and reply collected before the failure. Failed replies
remain available even when their payload cannot be interpreted. Cancellation
also stops target hashing before provider admission.

These operations do not execute the APK or provide Android App Bundle
(`.aab`)/split-APK _bundle_ handling (directory or `.apks` sets of separate
split files), signature validation, full resource-table semantics,
native-library analysis or Android runtime capture. XAPK containers are the
supported multi-APK input, with the merge scope documented above. An `.aab`
suffix is a ZIP archive, not an APK, so
Android tools and the application graph do not treat it as a standalone APK.
Existing artifact inventory/extraction tools can supply archive evidence.
Inventory records an APK root only for ZIP bytes whose name ends in `.apk`.
The projection adds a limitation when no root `AndroidManifest.xml` was
observed, because such a ZIP may not be an APK. Nested members take a ZIP or
ASAR family from their bytes; an unread member keeps an unknown format.
Inventory keeps ZIP names that differ only in case and records that a
case-insensitive destination cannot store both spellings. Extraction fails
only when that destination directory cannot keep both names. Project that
Evidence with the execution-free inventory tool:

```sh
rea project-android-application-graph '{"inventory_evidence":[<inventory_artifact Evidence>]}'
```

```json
{
  "name": "project_android_application_graph",
  "arguments": {
    "inventory_evidence": ["<inventory_artifact Evidence>"]
  }
}
```

The projection reports exact component paths and hashes, runtime-family hints,
and path-based bridge hypotheses. It does not decode DEX or claim observed
runtime calls. Framework hints match complete native library names, such as
`libreactnativejni.so`, `libreactnative.so`, `libhermes.so`,
`libhermes_executor.so`, `libflutter.so`, and `libunity.so`; unrelated names
such as `libcommunity.so` and `libreactivity.so` do not identify those families.
The bridge basis is inferred from the native path and repeated for each managed
component, so it does not identify a specific JNI binding. Bridge hypotheses form a DEX/JVM-class by native-library
Cartesian product. The projection computes the product and exact serialized
candidate-array size before creating candidate objects, then retains a
deterministic prefix within a 2 MiB UTF-8 JSON budget. If candidates are omitted,
`bridge_candidate_coverage` reports total, emitted, and omitted counts; overall
coverage is `partial` while component arrays still include every component
from the supplied inventory pages. A path pair does not establish that a
managed declaration names, loads, or calls the native library.

## Analyze an extracted DEX with radare2

JADX answers questions about Java source. To disassemble the Dalvik bytecode
itself, extract a `classesN.dex` member (or an app's single `classes.dex`) and
open it as a target with the [radare2 provider](radare2-provider.md) selected:

```sh
export REA_RADARE2_PATH=/absolute/path/to/radare2
export REA_ANALYSIS_PROVIDER=radare2
rea analyze /absolute/path/to/extracted/classes.dex --json
rea function /absolute/path/to/extracted/classes.dex method.public.static.Lcom_example_Api.load__V --json
```

DEX targets default to the `aa` analysis level, because `aaa` finds the same
methods and strings several times slower. Methods are named from their class
and signature, Dalvik registers are not stack slots, and `procedure_pseudo_code`
is an annotated Dalvik listing rather than Java. Addresses are offsets in that
particular DEX file: they do not match Ghidra's DEX addresses or another
`classesN.dex` of the same APK. Methods defined in a different DEX of the APK
appear as imports. Opening a DEX inside an APK is not supported yet; extract
the member first.

The same DEX file also imports into the [Ghidra provider](ghidra-dex.md): REA+
forces Ghidra's `DexLoader` with the Dalvik language selected from the DEX
header version. Ghidra's Dalvik addresses differ from these radare2 offsets,
and Ghidra's DEX memory is not backed by the admitted file, so byte reads and
file offsets stay unavailable there.

## Resource and lifecycle limits

REA+ retains one serialized session with private, immutable APK, engine JAR and
metadata-bridge copies. Matching requests reuse the loaded engine. APK/engine
digests and JVM configuration are checked before reuse; changed inputs retire
the previous session. Sessions are cleaned after 60 seconds of inactivity, on
target/configuration changes, failure, timeout, cancellation, MCP disconnect or
server shutdown. One-shot CLI commands always join cleanup before returning.
REA+ never writes to the original APK or launches target code.

On Windows, stdin writes preserve stream backpressure and run outside the Node
event loop. Cancellation terminates the retained job, including descendants,
before workspace cleanup. An abrupt CLI/server process termination closes the
job and stops Java, but cannot run JavaScript workspace cleanup; temporary
workspace files can remain after that forced exit.

If Java cannot start the bridge, REA+ reports the selected executable and retained
startup diagnostics. Select a full JDK through `JAVA_HOME` or `PATH`, and use
`java --list-modules` to confirm `jdk.compiler` is present. A runnable JRE alone
cannot compile the bridge. Missing or ambiguous class and method selections are
input failures; discover names with `search_android_classes` and
`inspect_android_class` before correcting the selected argument.

If process cleanup cannot be confirmed, REA+ retains the workspace and reports its
location. That provider instance blocks subsequent engine launches until the
caller resolves the reported resources and starts a fresh instance.

The provider uses one JADX analysis worker independently of JVM processor and
garbage-collector settings. REA+ supplies no default heap or visible-CPU override;
Java uses its normal ergonomics and inherits caller JVM settings. Optional
provider settings add explicit JVM arguments:

```sh
export REA_JADX_HEAP_MIB=8192
# Optional, independent of the single JADX worker:
export REA_JADX_ACTIVE_PROCESSOR_COUNT=4
# Or select settings through Java's standard environment options:
export JAVA_TOOL_OPTIONS=-Xmx8g
```

Both REA+ settings must be positive safe integers; processor counts must also fit
the JVM's signed 32-bit range. REA+ preserves
`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS` rather than replacing
them. Java's standard precedence applies: explicit command-line heap settings
override `JAVA_TOOL_OPTIONS`, while `_JAVA_OPTIONS` can override command-line
settings. Evidence reports the worker's observed `Runtime.maxMemory()` rounded
down to MiB and retains exact bytes, Java version and visible processors in its
raw runtime response. The observed allocatable heap can differ from configured
`-Xmx`, especially with Serial GC. Heap is not a total RSS cap: the JVM also
uses native memory. Independent REA+ instances have independent queues. Whole
operations have a **120-second** execution deadline after reaching the queue's
front; upstream decompilation is limited to **90 seconds**.

Decoded manifest and method text have a **1 MiB** upstream byte budget and report
truncation. Class-name pages use indexed slices of up to 4,096 names without changing the
complete, case-sensitive search contract. JADX names R8-obfuscated classes from
their Kotlin metadata, so several classes can share one name (167 names in the
WHOOP APK above). Search lists each name once and returns the shared ones in
`shared_names`; `inspect_android_class` reports such a name as ambiguous,
with its raw identities. A protocol frame above **8 MiB**, or combined stdout/stderr above
**32 MiB per operation**, fails with a diagnostic instead of returning an incomplete inventory
as complete. These are memory-safety boundaries, not undocumented result caps.

## Real verification

Download the explicit public fixtures once; this installs no tools:

```sh
npm run fixtures:android
export REA_JADX_MCP_JAR="$PWD/_reference/apk-integration/jadx-headless-mcp-0.7.1-all.jar"
export REA_ANDROID_TEST_APK="$PWD/_reference/apk-integration/ApiDemos-debug.apk"
npm run verify:android
```

The lane also uses the selected full JDK's `jlink` to create a disposable JRE
without the compiler module. It checks real Java startup failures, missing
selectors, recovery after failures, and CLI cancellation with owned cleanup.
The original APK and host Java configuration remain unchanged.

The same lane runs on Windows x64 with the bundled native controls and a full
JDK. It checks CLI/MCP results, real MCP cancellation and disconnect, and Java
exit after abrupt CLI owner termination. Windows forced termination is checked
separately from the POSIX CLI SIGTERM handler; it does not claim a structured
cancellation result or workspace removal after the owner is forcibly killed.

The download script verifies fixed SHA-256 values, reuses matching files and
refuses to overwrite a different existing file. APK/JAR files live under ignored
`_reference/` and are excluded from package contents. The lane exercises actual
REA+ CLI and MCP results with the real engine, separately from synthetic protocol
regressions. It needs no Gradle build, emulator, Android SDK or Ghidra.
