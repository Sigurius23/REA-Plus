# Android app-analysis tools

This note maps common Android app-analysis tools and their technical roles. It makes no compatibility claim for a particular app.

## Common tool roles

- **APK/package inventory:** [Android Studio APK Analyzer](https://developer.android.com/studio/debug/apk-analyzer) inspects APK/AAB contents, manifest, resources, and DEX structure. It helps identify what is packaged, but it is not a Java/Kotlin source decompiler.
- **Java/Kotlin-style code view:** [JADX](https://github.com/skylot/jadx) reconstructs a browsable, Java-like view from DEX/APK input and can decode manifest/resources. The result may be incomplete and is not the original source.
- **DEX-to-JAR conversion:** [dex2jar](https://github.com/pxb1988/dex2jar) can convert DEX bytecode into Java class/JAR files for compatible downstream inspection. It is a conversion helper, not a source decompiler, and may not preserve original project structure or source.
- **Multi-backend Java/Android viewer:** [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) supports class/JAR and APK/DEX inspection with several decompiler backends. Its inspected 2.13.2 release is marked in-development by upstream; reconstructed output is approximate.
- **Resources and lower-level bytecode:** [Apktool](https://github.com/iBotPeaches/Apktool) decodes resources/manifest and disassembles DEX into Smali. It also supports rebuilding packages.
- **Ghidra:** Ghidra is not limited to native `.so` files. Its [v11.0.2 importer documentation](https://www.ghidradocs.com/11.0.2_PUBLIC/help/Base/help/topics/ImporterPlugin/importer.htm) lists Android APK and Dalvik DEX formats, as well as native executable formats. It can be used to inspect DEX code or native libraries; its disassembly and decompiler output is lower-level analysis/pseudocode, not original Java/Kotlin source. A Java-like view from JADX is often easier to browse.
- **Automated triage:** [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) automates static mobile-app analysis and also has dynamic-analysis capabilities. Its output consists of analysis findings rather than a reconstructed app project.
- **Runtime observation:** [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb) communicates with devices/emulators; [Android Studio Logcat](https://developer.android.com/studio/debug/logcat) shows app/system messages. [Frida](https://github.com/frida/frida) and [Objection](https://github.com/sensepost/objection) are runtime instrumentation/exploration options. These tools concern behavior while an app runs; they are not source decompilers.
- **Projects with source:** The [official Android build documentation](https://developer.android.com/build) describes the build process for source projects. Decompiler output is reconstructed code rather than the original source project.

These tools overlap but answer different questions: APK Analyzer describes the package; JADX, Ghidra, or Bytecode Viewer can show code in reconstructed forms; dex2jar is an optional DEX conversion step rather than original-source recovery; Apktool exposes resources and Smali; MobSF automates checks; and ADB/Logcat, Frida, or Objection relate to runtime behavior. The best fit depends on whether the code is DEX, native, obfuscated, or otherwise transformed.

## Analysis and implementation

Ghidra is an analysis workbench; understanding a code path does not itself create a modified app. A changed version requires a separate authoring/build mechanism, such as a source project or other app-development tooling. A removed prompt or social button could reflect a local UI/code change or a difference in server-provided behavior; appearance alone does not establish how it was changed.

Android requires APKs to be signed, and app updates normally need the installed app's application ID and signing certificate (or valid key rotation) to match. A differently signed copy generally cannot update the official install in place; it would be treated as a separate app or replace the installed copy, which can affect local app data. See Android's [app-signing](https://developer.android.com/studio/publish/app-signing) and [app-update](https://developer.android.com/google/play/app-updates) documentation.

## Technical limitations and coverage

- Decompilers do not recover the original project: comments and many names may be absent, obfuscation/compiler transformations can make code hard to understand, and some code/resources may not decode cleanly. Smali is assembly-like, not Java/Kotlin source; native code may require a separate analysis view.
- No Osmo 360 app/version was inspected for this update. This overview does not make a compatibility claim about any camera companion app.
- The overall mobile crosswalk remains **Partial**. These references do not establish a universal mod API or workflow across Android apps, games, Unity, or Unreal.
- Game-integrated UGC is a separate technical path: a game must integrate the service and meet its platform requirements. [mod.io's UGC documentation](https://docs.mod.io/getting-started) describes participating-game integrations, not a generic Android app/game mod API.
- The [official DDLC mobile announcement](https://teamsalvato.com/news/ddlc-is-now-available-on-ios-and-android/) describes a separate release; it does not establish compatibility with desktop Ren'Py tools or an Android mod API. Serenity Forge's [statement about Google Play removal](https://x.com/SerenityForge/status/2042355439824769399) is a distribution-status reference.

See the [ecosystem coverage audit](../../ECOSYSTEM_COVERAGE.md#platform-and-distribution-checklist) for the Android, iOS, mobile, and game-integrated UGC coverage notes.
