# Unity IL2CPP metadata

`inspect_il2cpp_metadata` / `inspect-il2cpp-metadata` reads a Unity IL2CPP
`global-metadata.dat` with a caller-supplied
[r2unity](https://github.com/radareorg/r2unity) 1.2 and returns one filtered,
paged view. When you also select the build's native binary, each managed
method gets its native address, which you can take to a
[binary provider](native-investigation.md) such as radare2 or Ghidra. Neither
file is loaded or executed.

```sh
export REA_R2UNITY_PATH=/absolute/path/to/r2unity
META=/games/Example/Example_Data/il2cpp_data/Metadata/global-metadata.dat
rea inspect-il2cpp-metadata "$META" --binary_path /games/Example/GameAssembly.so --query license --json
rea inspect-il2cpp-metadata "$META" --view string_literals --query https:// --json
rea inspect-il2cpp-metadata "$META" --view interop --json
rea inspect-il2cpp-metadata "$META" --view assemblies --json
```

```json
{
  "name": "inspect_il2cpp_metadata",
  "arguments": {
    "metadata_path": "/games/Example/Example_Data/il2cpp_data/Metadata/global-metadata.dat",
    "binary_path": "/games/Example/GameAssembly.so",
    "view": "classes",
    "query": "license",
    "offset": 0,
    "limit": 25
  }
}
```

## Requirements

- `REA_R2UNITY_PATH`: absolute path to an `r2unity` executable that reports
  `r2unity 1.2.8` or a later 1.2 release. r2unity builds against radare2's
  development files (`make` in its repository, or `r2pm -ci r2unity`) and
  links radare2's libraries, which must be on the loader path. REA+ does not
  download or build it.
- REA+ runs r2unity with `R2_NOPLUGINS=1`, so radare2 plugins in your profile
  cannot change how a binary is read.

## Files to select

| Platform           | `binary_path`                                        | `metadata_path`                                                    |
| ------------------ | ---------------------------------------------------- | ------------------------------------------------------------------ |
| Windows standalone | `GameAssembly.dll`                                   | `<Game>_Data/il2cpp_data/Metadata/global-metadata.dat`             |
| Linux standalone   | `GameAssembly.so`                                    | `<Game>_Data/il2cpp_data/Metadata/global-metadata.dat`             |
| macOS standalone   | `GameAssembly.dylib`                                 | `Contents/Resources/Data/il2cpp_data/Metadata/global-metadata.dat` |
| Android            | `lib/<abi>/libil2cpp.so`                             | `assets/bin/Data/Managed/Metadata/global-metadata.dat`             |
| iOS                | `Frameworks/UnityFramework.framework/UnityFramework` | `Data/Managed/Metadata/global-metadata.dat`                        |

`binary_path` is optional. Without it, the classes view still lists every
type and member, with null addresses. For stripped binaries where neither the
`g_CodeRegistration` symbol nor r2unity's section scan finds the registration,
pass the `Il2CppCodeRegistration` address you found as `code_registration`.

## Views

Every view takes `query` (a case-insensitive substring), `offset` and `limit`
(1–200, default 25). `page.total` counts all matches.

- `classes`: types in metadata order with namespace, base type, interfaces,
  fields (name, type, token) and methods (name, parameter count, token,
  `MethodAttributes` flags and their C# reading, and `address`). A class
  matches when its qualified name contains the query; otherwise it matches
  through member names and lists only those members (`member_scope:
  "matching"`). With `binary_path`, `native` reports how the registration was
  found (`symbol`, `override`, `heuristic` or `none`) and the recovered
  `Il2CppCodeRegistration` and codeGenModules addresses.
- `string_literals`: managed `ldstr` literals with their file offset, byte
  length and UTF-8 text. REA+ reads each literal from the metadata bytes and
  checks it against r2unity's rendering. Literals that are not valid UTF-8,
  such as lone UTF-16 surrogates, keep their exact bytes in `hex`.
- `interop`: P/Invoke methods, and on wire version 29 and later
  `[MonoPInvokeCallback]` and `[UnmanagedCallersOnly]` reverse-P/Invoke
  methods, with tokens and flags. With `binary_path`, r2unity also tries to
  recover reverse-P/Invoke wrapper addresses.
- `assemblies`: managed assemblies with version, culture, public-key token,
  image and the assemblies each one references.

Every report also carries `metadata` (path, SHA-256, size, wire version and
the Unity releases that emit it), `native_binary`, the type, method and field
`counts`, and `tool_profile` with r2unity's path, SHA-256, version and the
exact arguments. The private copies appear as `<metadata_path>` and
`<binary_path>` in those arguments.

The MCP server keeps the parsed listing for the most recent selection, keyed by
the SHA-256 of r2unity, the metadata, the binary and any `code_registration`.
Paging and other queries on the same view reuse it, and `tool_profile.cached`
says so. Changing any file starts a fresh listing.

## Boundaries

- r2unity 1.2 decodes wire versions 24.1 through 35 and 38 through 39
  (Unity 2018.3 through Unity 6). REA+ checks the `0xFAB11BAF` magic and the
  version before running it. Encrypted or obfuscated metadata, v24.0, and
  versions 36 and 37 are rejected rather than guessed.
- Names are metadata identifiers, not source. Obfuscated builds keep their
  obfuscated names, and names that are not valid UTF-8 contain U+FFFD.
- Method addresses come from r2unity's registration recovery. A section scan
  can pair tables wrongly in unusual builds, so check addresses against the
  binary before relying on them. Methods without code (abstract methods,
  uninstantiated generic definitions) have no address.
- r2unity 1.2 does not recover P/Invoke DLL or entry-point names.
- r2unity is a trusted caller-supplied program. Its SHA-256 and version
  identify it, not publisher authenticity. Each r2unity process has a
  600-second deadline and a 256 MiB output budget; each page is limited to
  16 MiB serialized.

## Verification

`tests/fixtures/il2cppFixture.ts` builds a wire-version 29
`global-metadata.dat` and a matching x86-64 `GameAssembly.so` in source, with
and without the `g_CodeRegistration` symbol. Every view is checked against them
twice:

- `tests/boundary/providers/il2cpp/r2unityMetadata.real.test.ts` runs the real
  r2unity when `REA_VERIFY_R2UNITY_PATH` is set (otherwise a named skip). It
  was verified with r2unity 1.2.8 (commit `8d46d02b`, executable SHA-256
  `7ac2666be31a68102b22df12892adbd21c0609405fb1e52cc00f73ed80c8a563`) built
  against radare2 6.2.4 on Linux x86-64. The symbol, section-scan and override
  recovery paths were all exercised.
- `r2unityMetadata.process.test.ts` replays output recorded from that run
  through `tests/fixtures/fakeR2unity.mjs`, and also covers caching,
  cancellation, crashes, malformed output and unsupported releases.

No metadata from a shipped Unity game was available, so real-world coverage
rests on r2unity's own format support. Wire versions other than 29, PE and
Mach-O binaries, and 32-bit binaries have not been exercised through REA+.
