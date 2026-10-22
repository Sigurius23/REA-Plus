# Apktool resource decoding

REA+ decodes Android resource tables and the binary manifest through the
caller's Apktool launcher. This completes the static triad for Android
targets: Java/Kotlin sources through the JADX family, engine-grade
decompilation through JEB, and resources through this family. REA+ never
installs Apktool or a Java runtime.

## Supply tools

Use Apktool 2.7.0 or newer (verified with 2.7.0) and a Java runtime the
launcher can find. Select the launcher through the environment:

```sh
# Optional: absolute path to the apktool launcher (upstream wrapper or a
# java -jar script); without it, apktool resolves from PATH.
export REA_APKTOOL_COMMAND=/absolute/path/apktool
```

Readiness is `rea inspect-apktool-client`: it runs `apktool --version` and
reports the resolved launcher, its selection source, and its version. A
missing launcher reports `capability_unavailable` with the
`REA_APKTOOL_COMMAND` remediation rather than attempting an installation.

On Windows, a `.bat` or `.cmd` launcher (such as Chocolatey's `apktool.bat`)
runs through an explicit `cmd.exe /d /s /c` call. That call has no AutoRun,
no delayed expansion, and quotes every argument. A launcher path that
contains `"`, `%`, `^`, `!`, `&`, `|`, `<` or `>` is reported as
`not_configured` instead of being passed to `cmd.exe`. If REA+'s temporary
decode paths contain those characters, decoding through a batch launcher
reports `capability_unavailable`.

## Answer an analyst question

```sh
rea inspect-apktool-client
rea decode-android-resources /targets/Example.apk
rea decode-android-resources /targets/Example.apk --locale de
rea decode-android-resources /targets/Example.apk --no-strings
rea decode-android-resources /targets/Example.apk --strings-offset 2000
rea decode-android-resources /targets/Example.apk --include-xml-resources
```

Equivalent MCP methods are `inspect_apktool_client` and
`decode_android_resources`. The decode request takes `path`, an optional
`locale` (project `res/values-<locale>/strings.xml` instead of the default
table), and `include_strings` (default true). Regional locales such as `pt-BR`
select Android's `values-pt-rBR`; Android qualifiers such as `pt-rBR` and
`b+zh+Hans+CN` may also be supplied directly.

`decode_android_resources` may also take:

- `strings_offset` (default 0) and `strings_limit` (default and upper bound 2000) to page through more parsed entries than one response carries. The
  response reports the slice in `strings_page` (`total`, `offset`, `limit`,
  `returned`), and a response that does not carry every parsed entry reports
  partial coverage with a limitation naming `strings_offset`.
- `include_xml_resources` (default false) to project each decoded file under
  `res/xml`, such as a network security config, sorted by path and bounded to
  200 files. Each entry names its workspace-relative path, the decoded size,
  and the decoded text; a file larger than the 512 KiB per-file budget keeps
  its size but carries `content: null` with `truncated: true` and a
  limitation. When exposure is skipped but the folder is present, the
  limitations say how many files were skipped.

## Interpret the result

- **An owned APK snapshot is digested and decoded.** `target.sha256` and
  `target.bytes` bind the observation to the exact APK that was decoded.
- **Metadata comes from apktool.yml as apktool printed it.** Version codes
  keep their own spelling (`'7'` versus `7`); `package_name` is read from
  the decoded manifest, not inferred.
- **The manifest is the decoded text**, bounded at 512 KiB and reported as
  truncated when larger.
- **Strings are projected verbatim.** Escaped entities stay escaped, and
  entries containing nested markup (`<b>`, `<xliff:g>`) are counted as
  unparsed rather than flattened — the limitation names the count. One
  response carries at most 2000 entries, selected by `strings_offset` and
  `strings_limit`; `strings_page` reports `total`, `offset`, `limit` and
  `returned`, and partial coverage marks a response that omits parsed
  entries. `locales` lists every `values-<locale>` that has a strings table.
- **`res/xml` exposure is opt-in.** With `include_xml_resources`, every
  decoded file under `res/xml` (up to 200 files) appears in `xml_resources`
  with its size, truncation state and decoded content; otherwise the
  limitations name the skipped file count instead of the contents.
- **Smali is skipped by design** (`apktool d --no-src`): Java-source
  recovery belongs to the JADX family. Resource smali edits and rebuild are
  a follow-up lane with mutation authority.
- **Workspaces are owned and short-lived.** Decoding happens in a
  provider-owned temporary directory that is removed before the result is
  returned. The APK snapshot and framework cache both live inside this directory.
  If removal fails, the result names the residual path and the provider retains
  ownership for a cleanup retry on close, including failed decodes.

## Resource and lifecycle limits

- The decode runs with a 600 s deadline and a 4 MiB output capture budget;
  a stopped decode reports `provider_timeout` and exceeded budgets report
  `resource_constraint`.
- Manifest reads are bounded to 512 KiB before decoding UTF-8. Strings XML
  reads are bounded to 8 MiB; larger documents are skipped with partial
  coverage and an explicit limit, rather than reported as missing. Each
  projected `res/xml` file is likewise bounded to 512 KiB.
- `decoded_file_count` is capped at 100,000 files; the cap is reported in
  the limitations when hit. `xml_resources` is capped at 200 files, also
  reported as a limitation when reached.
- Apktool's own decode failures (`AndrolibException`, directory traversal
  refusals) surface as `unsupported_target` with apktool's reason preserved
  verbatim.

## Real verification

`npm run verify:apktool -- --apk PATH` exercises both operations against a
real launcher. Record: apktool 2.7.0-dirty (Debian packaging) on Linux with
OpenJDK 25 against a signed aapt2-built probe APK carrying two resource
locales — launcher version, on-disk digest agreement, apktool.yml metadata
(1.2.3, SDK 24–34), manifest package agreement, default and `de` string
tables projected. Parser goldens in the test suite come from the same
decode. See `docs/testing.md` for the lane summary.
