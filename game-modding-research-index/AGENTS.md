# AI-agent instructions for this repository

## Mission

Use this repository as a curated, link-only starting point for researching game-modding, reverse-engineering, asset, and development tools. It links to upstream projects; do not copy source code, vendor repositories, or add submodules.

Tool selection depends on the exact title, edition, store, build, platform, engine version, file format, and task. The catalog is not a universal reverse-engineering system or a compatibility certification.

## Establish the technical scope

Before giving title-specific tool recommendations or analyzing local files, identify the details needed to make the answer accurate:

- Exact game title, edition/remaster, store, platform/OS, version/build, and relevant DLC.
- The goal: inspect code or assets, identify formats, study a mechanic, troubleshoot a mod, or develop a project.
- The relevant file types and the specific directory or project being discussed.
- Whether the user wants conceptual information, tool selection, read-only analysis, or development guidance.

A path on the user's computer is not automatically accessible in the agent workspace. State clearly when a supplied path cannot be inspected from this environment.

## Catalog conventions

1. Start with `README.md` for navigation, `resources.json` as the canonical catalog, and the generated category page for role-based shortlists. Do not edit generated pages directly.
2. Read `ECOSYSTEM_COVERAGE.md` and relevant `platforms/*/README.md` notes for coverage, status, and compatibility context.
3. Classify each candidate before recommending it:
   - **Official SDK/API/source project:** developer-supported or source-based authoring route.
   - **Asset viewer/extractor/editor:** reads or edits resources; not necessarily a code decompiler or runtime loader.
   - **Code analysis/decompiler:** reconstructs or disassembles compiled code; output is not original source.
   - **Runtime framework/loader:** loads compatible mods; not a decompiler or installer by itself.
   - **Runtime debugger/instrumentation:** observes or traces a running process.
   - **Mod manager/installer:** organizes or deploys mods; does not prove that a game has a mod API or that a mod is compatible.
   - **Discovery index/community guide:** a lead to investigate, not verification of every linked project.
   - **Agent skill pack/prompt library:** workflow reference rather than a game tool.
   - **Specialist malware/forensics, network/protocol, and firmware/hardware tools:** distinct specialist categories, not general game-modding tools.
4. Select tools by actual file types and task, not by engine name alone. Examples include ILSpy/ILSpyCmd for .NET assemblies; CFR, Procyon, or Bytecode Viewer for Java/JVM; JADX/Apktool for Android DEX/APK; Ghidra/IDA/Binary Ninja for compiled binaries; WABT/Binaryen for WebAssembly; browser DevTools for JavaScript/WASM; and UE Explorer/UPK Explorer or asset viewers for selected Unreal formats. These tools have distinct roles and version limits.
5. Describe upstream releases, supported formats, exact title/build/store/platform evidence, license and maturity status, and whether a tool reads or modifies files. Label uncertainty and distinguish project claims from independent testing.
6. Keep resource summaries concise and original, with canonical upstream links. Preserve the link-only nature of this repository.

## Analysis and reporting

- Match claims to the exact title, build, store, platform, and tool version; do not infer compatibility from an engine label alone.
- Separate direct observations from hypotheses and note what was not tested.
- Describe decompiler output as a reconstructed view or pseudocode rather than original source.
- Distinguish understanding observed behavior from implementing a new design. Summarize findings in original words.

A useful report structure is:

- **Scope:** title/build/store/platform and goal.
- **Candidate tools:** role, upstream link, compatibility evidence, and technical caveats.
- **Findings:** observations and concise conclusions, with confidence.
- **Unresolved:** unknown compatibility, incomplete decompilation, missing symbols/source, or untested claims.
- **Next step:** the most relevant tool or documentation to consult.

## Request template

```text
Game and edition:
Store/platform and OS:
Version/build and DLC:
Relevant project or file types:
Goal:
Specific mechanic or technical question:
Target project engine/version (if implementing something original):
Preferred output (overview / shortlist / analysis / development plan):
```
