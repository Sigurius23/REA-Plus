# Workflow: managed runtimes and JVM packages

## Scope

Use separate providers for package/container structure, intermediate-language metadata, decompilation, and native libraries. A `.dll`, `.jar`, `.apk`, or Unity label alone is not proof that a particular runtime or toolchain is in use.

## .NET

1. Hash the exact assembly and identify its target framework, architecture flags, and signing metadata with a format-aware reader.
2. Choose a verified ILSpy/dotPeek-compatible provider for metadata and IL/decompiled views.
3. Preserve metadata tokens, method signatures, exception regions, offsets, and tool version. Treat reconstructed C# as a view of IL, not original source.
4. If NativeAOT, mixed-mode, obfuscation, or native dependencies are present, record those as separate coverage areas and use a native provider only when appropriate.

## JVM / Android DEX

1. Identify JAR/APK/AAB structure and each DEX or class artifact independently.
2. Use a verified JADX or JVM decompiler adapter and retain class/method descriptors, bytecode offsets, and decompiler version.
3. Keep resources, Smali/DEX, Java-like views, and native libraries as separate evidence sources.
4. Do not treat a decompiler's names, generics, line numbers, or source-level structure as original source unless corroborated by supplied symbols/source maps.

## Unity managed and IL2CPP

- **Mono/managed:** treat managed assemblies and Unity asset files as separate analysis targets.
- **IL2CPP:** treat metadata/code reconstruction and native disassembly as distinct providers; record exact game build, metadata/code pairing, architecture, and tool version.
- Record asset-tool compatibility separately from code analysis. A successful asset parse does not verify code compatibility, and vice versa.

## AERE v0.2 boundary

AERE can parse a bounded root-manifest APK, including Android package declarations and DEX identifier tables. It does not decompile .NET/JVM/DEX, reconstruct IL2CPP, decode Android resource tables, or assert original-source recovery. If no verified adapter exists for the exact format/build, report `unsupported` or `unknown` coverage.
