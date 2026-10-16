# REA-Plus (Reverse Engineer Anything Plus)

An agentic reverse-engineering ecosystem, tools workbench, and multi-platform research index.

---

## Overview

**REA-Plus** combines the [REA (Reverse Engineer Anything)](./rea-local) platform with agentic reverse engineering toolsets, mobile & native binary runtime instrumentation, and comprehensive ecosystem research covering Android and Steam game/application reversing.

```
.
├── rea-local/                             # Core REA+ MCP server & CLI engine
│   ├── src/application/mobileRuntime/     # Mobile runtime instrumentation (Frida / Android)
│   ├── src/binaryNinja/                   # Binary Ninja provider integration
│   ├── src/radare2/                       # radare2 deep-analysis provider
│   ├── src/jvm/                           # CFR-based JAR/.class decompilation
│   ├── src/il2cpp/                        # Unity IL2CPP metadata via r2unity
│   ├── src/drcov/                         # drcov coverage logs and baseline diffs
│   ├── src/minidump/                      # Windows/Breakpad/Crashpad crash minidumps
│   ├── src/logic/                         # sigrok logic captures and protocol decoding
│   ├── src/patterns/                      # AOB signature scanning and Cheat Engine tables
│   ├── src/unity/                         # Unity asset bundles and player serialized files
│   ├── src/gamearchives/                  # Godot PCK, Ren'Py RPA, Valve VPK, Doom WAD and Unreal pak archives
│   ├── src/ida/                           # IDA Pro official MCP connection & runner
│   ├── src/browser/history/               # Offline HAR, mitmproxy and PCAP/PCAPNG decoding
│   └── bridge/frida/                      # Frida scripts & bridge agents
├── agentic-reverse-engineering/           # AERE (Agentic Reverse Engineering) Workbench
│   ├── src/                               # Python analysis engine & pipeline
│   ├── skills/                            # Agent skills for reverse-engineering
│   └── schemas/                           # Shared schemas & protocols
├── game-modding-research-index/           # 380+ resource catalog across Android & PC modding
│   ├── resources.json                     # Structured tool database
│   ├── ECOSYSTEM_COVERAGE.md              # Coverage matrix by engine & platform
│   └── categories/                        # Categorized references & guides
├── game-modding-research-index-kplex-vault/ # Obsidian markdown knowledge vault
├── consensus-open-source-rebuild/         # App analysis & rebuild consensus documentation
├── repo-completeness-review.md            # In-depth stack & tool completeness audit
└── agent-reverse-engineering-stack-comparison.md # Cross-stack comparison
```

---

## Components

### 1. [REA+ Core Engine (`rea-local/`)](./rea-local)
A Model Context Protocol (MCP) server and CLI tool designed for AI agents to investigate compiled binaries, applications, and runtime behavior:
- **Expanded Provider Ecosystem**: Integrated support for Ghidra, IDA Pro, Binary Ninja, Hopper, and radare2 ([guide](./rea-local/docs/radare2-provider.md)).
- **Mobile Runtime Instrumentation**: Dynamic tracing, Frida integration, and Android app evidence collection.
- **Network & Protocol Analysis**: Offline HAR, mitmproxy and PCAP/PCAPNG inspection with link/IP/TCP/UDP decoding, HTTP/1.x heads, TLS hello SNI/ALPN and DNS messages ([guide](./rea-local/docs/web-network-captures.md)). Captures are read from files; REA+ does not capture live traffic.
- **JVM Decompilation**: Class inventories and CFR-decompiled Java for selected classes in JARs and `.class` files ([guide](./rea-local/docs/jvm-decompilation.md)).
- **Unity IL2CPP Metadata**: Classes, members, string literals, interop and assemblies from `global-metadata.dat`, with native method addresses recovered from GameAssembly/libil2cpp through r2unity ([guide](./rea-local/docs/il2cpp-metadata.md)).
- **Coverage Logs**: Executed modules and basic blocks from DynamoRIO or Frida drcov logs, and differential coverage against a baseline run to isolate the code behind one action ([guide](./rea-local/docs/drcov-coverage.md)).
- **Crash Minidumps**: Exception, faulting module+offset, threads, registers, modules with PDB/build-ID identifiers and a return-address stack scan from Windows, Breakpad and Crashpad `.dmp` files ([guide](./rea-local/docs/minidumps.md)).
- **Logic-Analyzer Captures**: Channel edges and bit-rate estimates from sigrok `.sr` sessions, plus UART/SPI/I2C and other protocol decoding through sigrok-cli with recovered byte streams such as serial console logs ([guide](./rea-local/docs/logic-captures.md)).
- **AOB Signatures & Cheat Engine Tables**: Signature scanning across PE/ELF/Mach-O with resolved rel32 targets, and `.CT` table inspection that re-checks a table's signatures and asserts against a new game build ([guide](./rea-local/docs/byte-patterns.md)).
- **Unity Asset Bundles**: UnityFS bundles (LZ4/LZMA decoded natively) and player data files (`level0`, `*.assets`, `globalgamemanagers`), with objects, names, owning GameObjects, MonoBehaviour scripts, bundle asset paths and `Resources.Load` paths, with or without type trees ([guide](./rea-local/docs/unity-assets.md)).
- **Game Engine Archives**: Godot `.pck` packs (including packs embedded in exported executables), Ren'Py `.rpa` archives (index pickles decoded without running code), Valve `.vpk` directories, Doom WADs and Unreal Engine `.pak` files (versions 1-11, Zlib/Gzip/Zstd decoded), with verified checksums and single-entry previews ([guide](./rea-local/docs/game-archives.md)).
- **Cross-Language Support**: Documentation and localization across 18 languages.

### 2. [AERE Workbench (`agentic-reverse-engineering/`)](./agentic-reverse-engineering)
A Python-based workbench designed for autonomous reverse-engineering workflows:
- Automated disassembly, function clustering, and symbol recovery.
- Reusable agent skills and CLI workflows.
- Available as a pre-packaged wheel (`aere_workbench-0.2.0-py3-none-any.whl`).

### 3. [Game Modding & Reverse Engineering Research Index (`game-modding-research-index/`)](./game-modding-research-index)
A curated database of 384 reverse engineering, modding, decompression, and memory inspection tools:
- Android APK/DEX/SO tooling (JADX, Apktool, MobSF, Frida, Objection).
- Steam & PC engine mappings (Unity, Unreal Engine, Godot, Source 2, GameMaker, RPG Maker).
- Comprehensive coverage matrices and platform audit reports.

### 4. Obsidian Knowledge Vault (`game-modding-research-index-kplex-vault/`)
A graph-connected Obsidian vault containing structured notes, taxonomies, and entity relations for the reversing catalog.

### 5. Research & Comparative Audits
- **[`repo-completeness-review.md`](./repo-completeness-review.md)**: Comparative matrix ranking tools by workflow roles (static analysis, agent operations, merging, runtime inspection).
- **[`agent-reverse-engineering-stack-comparison.md`](./agent-reverse-engineering-stack-comparison.md)**: Deep dive comparing standalone decompilers vs. agentic orchestration frameworks.

---

## License

Components in this repository retain their respective open-source licenses (MIT / Apache-2.0). Refer to individual component directories for details.
