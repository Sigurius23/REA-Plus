# .NET and Unity code analysis

<!-- Generated from resources.json by scripts/build_categories.py; edit the catalog, not this file. -->

**7 resources.** [Category index](../README.md) · [Main README](../../README.md) · [JSON catalog](../../resources.json)

- **[AvaloniaILSpy](<https://github.com/icsharpcode/AvaloniaILSpy>)** — Former Avalonia-based cross-platform ILSpy graphical port. The upstream archived it on 2025-07-21 after a long period without maintainers; the current main ILSpy project documents a Windows/Linux/macOS desktop UI, so treat this as a historical reference rather than the current default.
  - Tags: dotnet, decompiler, gui, archived, historical
- **[Cpp2IL](<https://github.com/SamboyCoding/Cpp2IL>)** — Work-in-progress tooling for reverse-engineering Unity's IL2CPP toolchain.
  - Tags: unity, il2cpp, reverse-engineering
- **[de4dot](<https://github.com/0xd4d/de4dot>)** — Legacy.NET deobfuscation utility for some supported obfuscators. The upstream repository was archived on 2020-10-17; compatibility is obfuscator-specific and output is not original source.
  - Tags: dotnet, deobfuscation, archived, historical
- **[dnSpyEx](<https://github.com/dnSpyEx/dnSpy>)** — Community continuation of dnSpy for .NET assembly inspection, decompilation, and debugging. Release/runtime support is project-specific; it is a code-analysis tool, not a game loader.
  - Tags: dotnet, decompiler, debugger, managed-code
- **[dotPeek](<https://www.jetbrains.com/decompiler/>)** — JetBrains.NET assembly browser and decompiler. It can aid managed-code inspection, but reconstructed output is not an original project and does not restore Unity assets, editor state, or source history.
  - Tags: dotnet, decompiler, managed-code
- **[Il2CppDumper](<https://github.com/Perfare/Il2CppDumper>)** — Restores IL2CPP metadata into dummy assemblies and generates analysis helpers for IDA, Ghidra, and Binary Ninja. GitHub showed its latest commit as 2024-07-06 when reviewed; current Unity-version support is not specified. Cpp2IL is a separate alternative.
  - Tags: unity, il2cpp, metadata, reverse-engineering, maintenance-check
- **[ILSpy](<https://github.com/icsharpcode/ILSpy>)** — Open-source.NET assembly browser and decompiler with desktop UI documented for Windows, Linux, and macOS. The project also includes ILSpyCmd, a command-line companion for automated decompilation, alongside features such as PDB generation, ReadyToRun, and metadata. Decompiled output is reconstructed, not original source.
  - Tags: dotnet, decompiler, managed-code
