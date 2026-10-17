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
│   ├── src/radare2/                       # radare2 and Rizin deep-analysis provider
│   ├── src/jvm/                           # CFR-based JAR/.class decompilation
│   ├── src/il2cpp/                        # Unity IL2CPP metadata via r2unity
│   ├── src/drcov/                         # drcov coverage logs and baseline diffs
│   ├── src/minidump/                      # Windows/Breakpad/Crashpad crash minidumps
│   ├── src/logic/                         # sigrok logic captures and protocol decoding
│   ├── src/patterns/                      # AOB signature scanning and Cheat Engine tables
│   ├── src/unity/                         # Unity asset bundles and player serialized files
│   ├── src/gamearchives/                  # Godot PCK, Ren'Py RPA, Valve VPK, Doom WAD and Unreal pak archives
│   ├── src/renpy/                         # Compiled Ren'Py scripts (.rpyc) read as inert data
│   ├── src/rpgmaker/                      # RPG Maker MV/MZ games: data, assets and saves
│   ├── src/gamemaker/                     # GameMaker data.win / game.droid files
│   ├── src/x64dbg/                        # x64dbg .dd32/.dd64 session databases
│   ├── src/wasmmodule/                    # WebAssembly modules decoded without WABT
│   ├── src/mobsf/                         # MobSF static-analysis report import
│   ├── src/lua/                           # Lua 5.1-5.4 and LuaJIT bytecode disassembly
│   ├── src/blob/                          # Schema-less save and packet blob decoding
│   ├── src/godot/                         # Godot resources, scenes, compiled GDScript and saves
│   ├── src/protocol/                      # Protocol field inference over captures
│   ├── src/bindiff/                       # Whole-binary patch diffing
│   ├── src/ida/                           # IDA Pro official MCP connection & runner
│   ├── src/browser/history/               # Offline HAR, Burp, mitmproxy and PCAP/PCAPNG decoding
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
- **Expanded Provider Ecosystem**: Integrated support for Ghidra, IDA Pro, Binary Ninja, Hopper, and radare2 or its fork Rizin ([guide](./rea-local/docs/radare2-provider.md)).
- **Mobile Runtime Instrumentation**: Dynamic tracing, Frida integration, and Android app evidence collection.
- **Network & Protocol Analysis**: Offline HAR, Burp Suite XML, mitmproxy and PCAP/PCAPNG inspection (Charles and Proxyman through their HAR export) with link/IP/TCP/UDP decoding, HTTP/1.x heads, TLS hello SNI/ALPN and DNS messages ([guide](./rea-local/docs/web-network-captures.md)). Captures are read from files; REA+ does not capture live traffic.
- **JVM Decompilation**: Class inventories and CFR-decompiled Java for selected classes in JARs and `.class` files ([guide](./rea-local/docs/jvm-decompilation.md)).
- **Unity IL2CPP Metadata**: Classes, members, string literals, interop and assemblies from `global-metadata.dat`, with native method addresses recovered from GameAssembly/libil2cpp through r2unity ([guide](./rea-local/docs/il2cpp-metadata.md)).
- **Coverage Logs**: Executed modules and basic blocks from DynamoRIO or Frida drcov logs, and differential coverage against a baseline run to isolate the code behind one action ([guide](./rea-local/docs/drcov-coverage.md)).
- **Crash Minidumps**: Exception, faulting module+offset, threads, registers, modules with PDB/build-ID identifiers and a return-address stack scan from Windows, Breakpad and Crashpad `.dmp` files ([guide](./rea-local/docs/minidumps.md)).
- **Logic-Analyzer Captures**: Channel edges and bit-rate estimates from sigrok `.sr` sessions, plus UART/SPI/I2C and other protocol decoding through sigrok-cli with recovered byte streams such as serial console logs ([guide](./rea-local/docs/logic-captures.md)).
- **AOB Signatures & Cheat Engine Tables**: Signature scanning across PE/ELF/Mach-O with resolved rel32 targets, and `.CT` table inspection that re-checks a table's signatures and asserts against a new game build ([guide](./rea-local/docs/byte-patterns.md)).
- **Unity Asset Bundles**: UnityFS bundles (LZ4/LZMA decoded natively) and player data files (`level0`, `*.assets`, `globalgamemanagers`), with objects, names, owning GameObjects, MonoBehaviour scripts, bundle asset paths and `Resources.Load` paths, with or without type trees ([guide](./rea-local/docs/unity-assets.md)).
- **Game Engine Archives**: Godot `.pck` packs (including packs embedded in exported executables), Ren'Py `.rpa` archives (index pickles decoded without running code), Valve `.vpk` directories, Doom WADs and Unreal Engine `.pak` files (versions 1-11, Zlib/Gzip/Zstd decoded), with verified checksums and single-entry previews ([guide](./rea-local/docs/game-archives.md)).
- **Ren'Py Scripts**: Compiled `.rpyc` visual-novel scripts mapped into labels and branches, dialogue with speakers and translation identifiers, menus, definitions and translations, with the pickled AST read as inert data instead of being unpickled ([guide](./rea-local/docs/renpy-scripts.md)).
- **RPG Maker MV/MZ Games**: Maps, dialogue, switch and variable read/write sites, the database with notetags, and `plugins.js` (parsed, never run). The asset key is checked against one recovered from an encrypted PNG, one selected asset can be decrypted, and MV/MZ saves are decoded into party, gold, items, switches and variables. Checked against each game's own engine running in Chromium ([guide](./rea-local/docs/rpgmaker-projects.md)).
- **GameMaker Data Files**: `data.win`, `game.unx`, `game.droid` and audio-group files mapped into chunks, resources (sprites, objects with their sprites, rooms with instances and creation code, scripts, sounds), GML bytecode entries, the string table, functions and variables, texture pages (PNG/QOI) and embedded audio, with VM/YYC and the minimum runtime the chunk set implies ([guide](./rea-local/docs/gamemaker-data.md)).
- **x64dbg Databases**: `.dd32`/`.dd64` session databases (plain or LZ4-compressed) mapped into labels, comments, bookmarks, function and loop ranges, breakpoints with conditions and log/command text, xrefs and watches; given the game executable, entries are placed at file offsets and software breakpoints are re-checked against its bytes ([guide](./rea-local/docs/x64dbg-databases.md)).
- **WebAssembly Modules**: Web game builds (`.wasm`, or gzip/Brotli `.wasm.gz`, `.wasm.br`, `.unityweb`) decoded without WABT into the toolchain they betray (Emscripten, Unity WebGL/IL2CPP, Godot, Rust/Bevy), the debug information kept, functions with signatures and call counts, the callers and callees of one function, imports, exports and data strings. Checked against V8 on ten itch.io HTML5 games ([guide](./rea-local/docs/wasm-modules.md)).
- **MobSF Reports**: MobSF static-analysis JSON for Android and iOS apps (MobSF 3.1 to 4.x) imported as Evidence: app identity and signing certificate, findings with CWE/OWASP/MASVS and file and line locations, permissions, components with exported state and deep links, native library and Mach-O hardening, endpoints, domains, secrets, trackers and APKiD protections, optionally checked against the APK/IPA's hash. Checked against the scorecards MobSF wrote into nine real reports ([guide](./rea-local/docs/mobsf-reports.md)).
- **Lua Bytecode**: Compiled game and mod scripts (luac 5.1-5.4 chunks, LuaJIT 2.0/2.1 dumps, or chunks embedded in game data) disassembled without running them: the function tree with name hints recovered from where each function is stored, instruction listings in luac/luajit form, constants, locals and upvalues. Checked against the real compilers' own listings on 3,836 chunks built from 389 Lua files, including Factorio's game data ([guide](./rea-local/docs/lua-bytecode.md)).
- **Save and Packet Blobs**: Save games, caches, settings blobs and packet payloads decoded without a schema: base64, hex, gzip, zlib, zstd and LZ4 layers removed (raw deflate and Brotli on request), then protobuf read as `protoc --decode_raw` reads it with every field's other readings, MessagePack, CBOR, BSON, Java and Bedrock NBT, JSON, and Minecraft region files chunk by chunk, as a tree with byte offsets or as its strings. Checked against protoc, the Python msgpack, cbor2 and bson libraries, the lz4 and zstd tools, and two NBT libraries' test files ([guide](./rea-local/docs/data-blobs.md)).
- **Godot Files**: Binary resources and scenes, compiled GDScript and saves from Godot 3 and 4 games, read from loose files or straight out of a `.pck` (following `.remap` from the original paths): scene trees with instanced scenes, groups and signal connections, every stored property in Godot's text notation, GDScript rebuilt from `.gdc`/`.gde` tokens on the original line numbers, `store_var` saves (also inside `open_compressed` and, with the key or password, `open_encrypted` files) and `project.binary` settings. Checked against Godot 3.5 itself, the token streams of 288 demo scripts and GDQuest's Godot 4.6 course, and 919 scripts, 1,676 resources and 714 scenes from 12 released games ([guide](./rea-local/docs/godot-files.md)).
- **Protocol Field Inference**: Message formats of undocumented protocols inferred from PCAP/PCAPNG captures or hex messages, without sending anything: TCP streams reassembled and framed by a detected length prefix or delimiter, messages grouped by type field, direction or first word, and each format's header broken into type, length, counter, checksum (with algorithm and covered bytes), timestamp, constant, float, text and enum fields. Checked against tshark's dissections of Wireshark sample captures (TFTP, NTP, DNS, CoAP) and against scapy-generated Modbus/TCP, TFTP and game-style captures ([guide](./rea-local/docs/protocol-fields.md)).
- **Binary Diffing**: Two builds of a native binary compared function by function, BinDiff/Diaphora-style, through any deep provider and on stripped builds: matches by names, identical or same-mnemonic instructions, strings and constants with the same control-flow shape, call-graph neighbours, call order and similarity; changed, added and removed functions with aligned instruction diffs ([guide](./rea-local/docs/binary-diff.md)).
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
