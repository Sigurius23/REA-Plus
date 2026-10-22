# Android DEX analysis with Ghidra

REA+ admits Android DEX files as Dalvik binary targets and analyzes them through
the bring-your-own Ghidra adapter. The real-Ghidra lane exercises actual
disassembly and inventory operations on a small DEX built from Java source with
`javac` and `d8`; no Android SDK runtime is required. A DEX member inside an APK
can also be opened directly through the `container#member` fragment
(`/path/App.apk#classes2.dex`); REA+ stages the member beside the container (or
under MCP `staging_dir` / CLI `--staging-dir`) and imports the staged bytes. See
[Android DEX member targeting](android-analysis.md#open-one-dex-member-inside-an-apk-container).

## Forced import

Ghidra imports a private target snapshot with Ghidra's `DexLoader` and the
Dalvik language selected from the DEX header version — the `035`/`037`… magic
maps to the smallest covering Android-era variant (`DEX_KitKat` for `035`,
`DEX_Lollipop` for `037`, `DEX_Nougat` for `038`, `DEX_Pie` for `039`,
`DEX_Android10` for `040`, `DEX_Android11` for `041`, `DEX_Android12` for `042`,
the newest variant for anything later). The chosen language, compiler
specification `default`, and the DEX version observation are committed in the
analysis profile; the handshake rejects language or compiler drift. `open_binary`
rejects `REA_GHIDRA_LANGUAGE_ID` overrides for a DEX import the same way it
rejects them for DOS and PSP.

Closing the session deletes the temporary project and snapshot.

## Ghidra's DEX memory and file offsets

Ghidra's DEX loader maps the Dalvik program into loader-owned memory. The
`.dex` block maps the imported file's bytes one-to-one, and the
`method_bytecode`/`method_lookup` blocks hold loader-generated views, but none
of that memory is annotated with source mappings. The provider's byte-level
observations report exactly that contract:

- `read_bytes` returns initialized memory, including the `.dex` block's
  file-backed bytes (the DEX header reads back as `646578 0a 303335 00`); an
  unmapped address ends the read with `returned_bytes: 0` and
  `complete: false`.
- `address_to_file_offset` has no source mapping to consult and fails
  explicitly with an invalid-request error rather than guessing an offset.
- `inspect_native_load_image`'s digest and source-mapping verification applies
  to ordinary imports; it does not claim byte mapping for a DEX target.

Addresses are Ghidra's Dalvik memory coordinates for the imported file. They
are not file offsets, and they are not comparable with radare2's DEX addresses
or with the JVM/DEX tool ids from `inspect_android_*`. Use each provider's own
addresses for that provider.

## Strings

Ghidra's DEX loader symbolizes string-pool items but defines their bytes only
as structural records, so defined-data string inventories would miss every
pool value. The session's packaged post-analysis preparation redefines one
UTF-8 string item per pool entry directly over the loader-mapped `.dex` block
before the resident bridge serves results. Dalvik method creation happens
during auto-analysis, which is why the preparation cannot run earlier. The
loader-internal `align` markers inside `method_bytecode` stay outside the
inventory: for a Dalvik program the bridge admits only string data inside the
`.dex` block.

## Function landscape

Dalvik methods become one function each, named by their class and descriptor.
Dalvik registers are not stack slots; Ghidra's decompiler output over Dalvik is
a low-level rendering. Prefer `inspect_android_method` (JADX lane) for
decompiled Java, and treat Ghidra's DEX decompilation as operand-level
instrumentation.

## Real verification

```bash
npm run verify:ghidra:dex
```

The lane imports `tests/fixtures/dex/classes.dex` (one class built from the
sibling `Fixture.java` with `javac --release 17` and `d8 --release --min-api
21`) through the compiled module and the resident bridge. It verifies the
committed Dalvik language, one-function-per-method discovery with class-
qualified names, real decompilation through the CLI and stdio MCP, the string
constant and its pool value defined by the preparation, that the loader maps
the DEX header bytes, and that file-offset mapping is honestly rejected.
Nothing in the input file changes; the session cleanup removes the snapshot
and project, and the verifier run records process ownership lineage.
