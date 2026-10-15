# Consensus-inspired open research assistant

**Status:** Phase 0 — public-product reconnaissance. This is a clean-room project separate from the game-modding catalog; no Consensus source, assets, or private data have been copied.

## Verified Android product surface

Consensus has an official Google Play app published by Consensus NLP Inc. The listing URL identifies the package as `app.consensus.android` and shows an update date of September 14, 2026: [Google Play listing](https://play.google.com/store/apps/details?id=app.consensus.android&hl=en_US).

The listing describes these user-facing workflows:

- Search a large scholarly corpus and receive paper-grounded, sentence-level citations.
- **Consensus Meter:** summarize how retrieved studies fall into support, contest, and inconclusive groups for a yes/no question.
- **Study Snapshot:** display methods, duration, location, outcomes, and results; filter by study design, citation count, and publication date.
- **Pro** and **Deep** synthesis modes: work across up to 20 papers or, for Deep, up to 50 papers with an advanced search strategy and structured review.
- Ask questions about accessible full-text papers and user-supplied PDFs; dictate questions by voice.
- Save papers to collections; import a Zotero library; export APA, MLA, Chicago, Harvard, or BibTeX citations; sync the library and search history with the web product.

These are features stated in the store listing, not claims about how the service implements them.

## Initial clean-room architecture

1. **Clients:** web UI and Android app sharing a documented backend API.
2. **Scholarly sources:** metadata and full text from sources with suitable access and reuse terms, plus user-supplied documents.
3. **Search/index:** metadata normalization, deduplication, keyword and vector retrieval, ranking, and citation links.
4. **Evidence layer:** paper-level extraction and provenance records so generated claims can be tied back to specific passages and papers.
5. **Pluggable model interface:** separate adapters for text generation, embeddings, and optional reranking, so the operator can configure a compatible model without changing research-workflow code.
6. **Research workflows:** paper search, cited synthesis, support/contest/inconclusive grouping, study snapshots, paper Q&A, library/collections, and citation import/export.

An independent implementation can reproduce workflow classes without recovering Consensus's private corpus, backend code, prompts, or model configuration.

## Android analysis status and tools

For Play Store installation options across macOS, Windows, and Linux—with or without an Android phone—see [Android app installation options](android-app-installation-options.md).

No APK has been supplied or analyzed, so the app's architecture is unknown. The Play listing alone does not show whether it uses mostly native screens, embedded web content, or a combination.

If an APK is available for analysis, the catalog already contains suitable conceptual tools:

- **Android Studio APK Analyzer** for package, manifest, resource, and DEX inventory.
- **JADX** for a Java-like view of DEX; **Apktool** for resources and Smali; **Ghidra** if DEX or native libraries need lower-level inspection.
- **MobSF** for automated mobile-app triage.
- **ADB/Logcat**, **Frida**, and **Objection** for observing ordinary runtime behavior.
- **Chrome/Firefox DevTools**, **Charles**, **Proxyman**, **mitmproxy**, or **Burp Suite** for browser/client behavior and normally exposed request/response patterns.

These tools can characterize client-side behavior. They do not reveal hidden server-side code or create access to private service internals.

## Unknowns for a genuine implementation

- Whether the Android app is native, WebView-based, or hybrid, and which libraries it includes.
- The search corpus providers, update pipeline, ranking features, and actual ranking behavior.
- The server-side request/response schemas, storage model, and model-serving architecture.
- The implementation and evaluation rules behind the Consensus Meter and Study Snapshot.
- Full-text access terms and which document sources can be used by an open-source replacement.

A client-side study can inform the user-facing specification. Server-side internals require authorized source or environment access; otherwise, those components must be designed independently.

## Next milestone

Obtain the Android package from an authorized source or use an installed test device, then produce a package inventory and a feature-to-screen map. No login secrets, private account data, or bypass procedures are needed for that inventory.
