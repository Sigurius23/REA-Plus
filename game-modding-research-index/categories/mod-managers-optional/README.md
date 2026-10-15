# Mod managers (optional)

<!-- Generated from resources.json by scripts/build_categories.py; edit the catalog, not this file. -->

**15 resources.** [Category index](../README.md) · [Main README](../../README.md) · [JSON catalog](../../resources.json)

- **[CKAN (Kerbal Space Program mod manager)](<https://github.com/KSP-CKAN/CKAN>)** — Community mod manager/catalog for Kerbal Space Program; KSP1 is the target of this audit. Latest checked release v1.36.4 was published 2026-05-12. CKAN is an installer and dependency/version manager, not a game mod API; verify the selected game instance and mod metadata.
  - Tags: kerbal-space-program, ksp1, mod-manager, dependency-management, version-specific
- **[Deltamod (GameMaker mod manager)](<https://github.com/deltamodders/deltamod>)** — Community manager for packaged GameMaker mods, with patch/install workflows and backups; its ecosystem is particularly Deltarune-focused. Latest release located is v2.1.4 (2026-10-04), with Windows and Debian-based Linux packages. The release fixes include Linux patch-tool path and data-file backup handling. This is a manager/patch driver, not a runtime mod loader; verify each package against the exact game files and platform.
  - Tags: gamemaker, deltarune, mod-manager, patcher
- **[DokiModManager (DDLC mod manager)](<https://github.com/BKunzite/DokiModManager/releases/tag/1.8.0-release>)** — DDLC-specific download/install/profile manager, not a universal Ren'Py loader or a Team Salvato product. Release 1.8.0-release (2026-09-29) adds a downloads manager. Windows is the primary route; Linux is beta/RC with some mods unsupported, while the macOS alpha was reported as not working properly and is unsigned. DDLC Plus and mobile support are not listed.
  - Tags: ddlc, mod-manager, downloads, windows, linux-beta, macos-alpha
- **[Fluffy Mod Manager](<https://www.nexusmods.com/site/mods/818>)** — Mod manager for RE Engine titles with multiple game-specific installation methods and automatic file backups. The author's Nexus page lists v3.084, updated 2026-09-22. It installs and organizes supported mods; it is not the runtime framework and does not publish a complete game-build compatibility matrix.
  - Tags: capcom, re-engine, mod-manager, file-backups, version-specific
- **[G3M (GameMaker Mod Manager)](<https://github.com/y114git/G3M>)** — Desktop mod manager with GameBanana browsing/discovery, profiles, launch support, patching, merging, and data-file conversion. Latest release located is v3.4.1 (2026-10-04); built-in entries include Deltarune, its demo, Undertale, and selected other GameMaker games. Windows/Linux/macOS x64 and ARM64 downloads describe the manager app, not guaranteed game compatibility. G3M operates on title-specific files/patches; it is not a runtime loader.
  - Tags: gamemaker, mod-manager, patcher, discovery
- **[Melty Desktop App (Windows setup and launcher)](<https://melty.gg/download>)** — Windows-only client for one-click setup and launching of Melty mashups. Its Terms say it can inspect installed game versions, download mashup files and required tools, write into game folders after copying replaced files, locate and copy needed files from the user's own game installation locally, build components, and start games/programs/setup steps. It orchestrates per-mashup tooling; it is not a general-purpose runtime or a cross-game compatibility guarantee.
  - Tags: melty, windows, mod-manager, launcher, installer, version-specific
- **[Mod Organizer 2](<https://github.com/ModOrganizer2/modorganizer>)** — Mod manager for various PC games, especially useful in Bethesda-oriented workflows; it manages installations and profiles rather than replacing a game's mod loader.
  - Tags: mod-manager, bethesda, mod-installation
- **[Outer Wilds Mod Manager](<https://github.com/ow-mods/ow-mod-man>)** — Outer Wilds mod manager with GUI, Core, and CLI release 0.15.7 (2026-07-13); OWML recommends it for installing the loader and mods. Windows, Linux/Steam Deck, and macOS guidance is documented with platform-specific caveats; match the current OWML/game version.
  - Tags: outer-wilds, mod-manager, owml, mod-installation, cross-platform, version-specific
- **[Quake Injector (legacy manager)](<https://www.quaddicted.com/tools/quake_injector>)** — Archived Quaddicted wiki documentation describes Quake Injector v8, a cross-platform Java utility for browsing, installing, and launching Quaddicted single-player maps/mods. It is a content manager/launcher, not the game runtime; engine limits and map requirements vary, and current operation is not documented.
  - Tags: quake, mod-manager, installer, launcher, legacy, discovery
- **[r2modman](<https://github.com/ebkr/r2modmanPlus>)** — Mod manager for games distributed through Thunderstore; check the upstream project for current game and platform support.
  - Tags: mod-manager, thunderstore, mod-installation
- **[RimPy (legacy manager)](<https://github.com/rimpy-custom/RimPy>)** — RimWorld manager with no recent release observed: v1.2.6.29 was Linux-only (2022-11-20) and Windows v1.2.6.28 dates to 2022-10-31. It is a legacy, maintenance-sensitive option; RimWorld 1.6 support is not established.
  - Tags: rimworld, mod-manager, legacy, maintenance-check, version-specific
- **[RimSort](<https://github.com/RimSort/RimSort>)** — Open-source RimWorld mod manager with Windows, macOS, and Linux support. Latest checked stable release v1.15.0 was published 2026-10-04; a manager organizes installs and load order but does not guarantee mod compatibility.
  - Tags: rimworld, mod-manager, cross-platform, active, version-specific
- **[RPGModder (MV/MZ mod manager)](<https://github.com/Zorkats/RPGModder>)** — External manager for packaged RPG Maker MV/MZ games. Latest release v2.0.0 (2026-07-11) uses snapshots, a transaction journal, rollback, and conflict analysis; deployment changes the live game content directory rather than virtualizing files at runtime. Native Windows x64 and Linux x64 builds support common root/www layouts, but unusual structures or runtime loaders may need game-specific rules. No named-game compatibility test was performed.
  - Tags: rpg-maker, rpg-maker-mv, rpg-maker-mz, mod-manager, windows, linux, version-specific
- **[Satisfactory Mod Manager](<https://github.com/satisfactorymodding/SatisfactoryModManager>)** — Community manager recommended by the Satisfactory modding docs for installing mods, dependencies, and SML from the Satisfactory Mod Repository. Latest checked release v3.1.0 (2026-06-06) provides Windows, Linux, and macOS downloads. It manages mod packages but does not prove the SML release or any individual mod supports the current Satisfactory game build.
  - Tags: satisfactory, mod-manager, mod-installation, active-source, cross-platform, version-specific
- **[Vortex](<https://github.com/Nexus-Mods/Vortex>)** — Nexus Mods' general mod manager for installing and organizing supported game mods; it does not replace a game's loader or development API.
  - Tags: mod-manager, nexus-mods, mod-installation
