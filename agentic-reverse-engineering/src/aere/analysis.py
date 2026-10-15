"""Workspace integration for Android/Steam analyzers and the evidence ledger."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import __version__
from .android import inspect_apk
from .core import AereError, Workspace, _json_dump, _read_zip_metadata, _redact_json, _redact_export_paths
from .steam import inspect_steam_install


_ANDROID_PROVIDER = "builtin.android.apk"
_STEAM_PROVIDER = "builtin.steam.install"


def _status(value: Any, *, missing: str = "unknown") -> str:
    if value in {"complete", "partial", "unsupported", "not_attempted", "unknown"}:
        return value
    return missing


def _enforce_response_limit(workspace: Workspace, value: dict[str, Any]) -> None:
    size = len(_json_dump(value).encode("utf-8"))
    limit = int(workspace._limits()["max_report_bytes"])
    if size > limit:
        raise AereError("response_too_large", "Domain analysis response exceeds the configured report-size limit.", {"bytes": size, "limit": limit})


def inspect_android_workspace(
    workspace: Workspace,
    artifact_id: str,
    *,
    include_previews: bool = False,
) -> dict[str, Any]:
    """Run bounded APK inspection, then record compact facts and scoped coverage."""
    artifact = workspace.artifact(artifact_id)
    if artifact.get("format") != "apk":
        raise AereError("unsupported_android_artifact", "This operation accepts a registered APK with a root-level AndroidManifest.xml; AAB/APKS, nested split layouts, and APK candidates are not yet supported.", {"format_candidate": artifact.get("format")})
    path, _ = workspace._resolve_artifact_path(artifact_id)
    archive_metadata = _read_zip_metadata(
        path,
        int(workspace._limits()["max_archive_members"]),
        int(workspace._limits()["max_archive_directory_bytes"]),
    )
    analysis = inspect_apk(path, archive_metadata, workspace._limits(), include_previews=include_previews)
    analysis = _redact_export_paths(_redact_json(analysis))
    _enforce_response_limit(workspace, analysis)
    workspace._resolve_artifact_path(artifact_id)

    run = workspace.create_run(
        artifact_id,
        "android-apk-static-inspection",
        _ANDROID_PROVIDER,
        {"include_previews": include_previews, "analysis_version": "0.2.0"},
    )
    run_id = run["run_id"]
    try:
        archive = analysis.get("archive", {})
        workspace.add_evidence(
            run_id,
            kind="observation",
            claim=f"Bounded ZIP central-directory inspection examined {archive.get('members_examined', 0)} of {archive.get('member_count', 0)} APK member(s).",
            source_tool="aere.android.zip-index",
            source_version=__version__,
            locator={"scope": "APK central directory"},
            data={
                "artifact_id": artifact_id,
                "sha256": artifact["sha256"],
                "member_count": archive.get("member_count"),
                "members_examined": archive.get("members_examined"),
                "status": archive.get("status"),
                "unsafe_member_count_in_sample": archive.get("unsafe_member_count_in_sample"),
            },
            caveats=["Member names/sizes are untrusted metadata; members were not written to disk.", "This observation is not proof that any entry is valid or loaded at runtime."],
        )
        manifest = analysis.get("manifest", {})
        workspace.add_evidence(
            run_id,
            kind="observation" if manifest.get("status") == "parsed" else "unknown",
            claim=(
                f"Android manifest metadata was parsed for package {manifest.get('package')!r}."
                if manifest.get("status") == "parsed"
                else f"Android manifest parse status is {manifest.get('status', 'unknown')!r}; no absence conclusion is made."
            ),
            source_tool="aere.android.manifest",
            source_version=__version__,
            locator={"member": manifest.get("member", "AndroidManifest.xml"), "scope": "manifest declaration only"},
            data={
                **{
                    key: manifest.get(key)
                    for key in ("status", "format", "package", "version_name", "version_code", "min_sdk_version", "target_sdk_version", "permission_count", "permissions_truncated", "component_count", "components_truncated", "error")
                    if key in manifest
                },
                "permissions_sample": [str(item)[:256] for item in manifest.get("permissions", [])[:50]],
                "components_sample": [
                    {key: (str(value)[:256] if value is not None else None) for key, value in item.items() if key in {"type", "name", "exported", "enabled", "line"}}
                    for item in manifest.get("components", [])[:25]
                ],
            },
            caveats=list(manifest.get("limitations", [])) + ["Resource references are not resolved; static declarations do not establish runtime reachability."],
        )
        dex_files = analysis.get("dex_files", [])
        if dex_files:
            workspace.add_evidence(
                run_id,
                kind="observation",
                claim=f"Bounded DEX identifier parsing examined {len(dex_files)} DEX entry/entries; no method bodies were decompiled or executed.",
                source_tool="aere.android.dex-identifiers",
                source_version=__version__,
                locator={"scope": "DEX header, string/type/class/method identifier tables"},
                data={
                    "dex_file_count": analysis.get("dex_file_count"),
                    "dex_status": analysis.get("dex_status"),
                    "files": [
                        {
                            "name": str(item.get("name", ""))[:512],
                            "status": item.get("status"),
                            "dex_version": item.get("dex_version"),
                            "class_definition_count": item.get("class_definition_count"),
                            "method_id_count": item.get("method_id_count"),
                            "classes_sample": [str(name)[:128] for name in item.get("classes", [])[:10]],
                            "methods_sample": [
                                {"owner": str(method.get("owner", ""))[:128], "name": str(method.get("name", ""))[:128]}
                                for method in item.get("methods", [])[:10]
                            ],
                        }
                        for item in dex_files[:8]
                    ],
                },
                caveats=["Identifier tables are not a decompilation, call graph, or proof of reachable behavior."],
            )
        if analysis.get("engine_candidates"):
            workspace.add_evidence(
                run_id,
                kind="inference",
                claim="APK member-name markers suggest one or more engine candidates; the engine and build are not confirmed.",
                source_tool="aere.android.engine-markers",
                source_version=__version__,
                locator={"scope": "APK central-directory member names"},
                data={"candidates": [
                    {"engine": item.get("engine"), "status": item.get("status"), "supporting_members": [str(name)[:512] for name in item.get("supporting_members", [])[:20]]}
                    for item in analysis["engine_candidates"][:10]
                ]},
                caveats=["Name/signature markers can be renamed, bundled, stale, or unrelated; no engine version or runtime compatibility is asserted."],
                confidence=0.4,
            )
        if include_previews:
            workspace.add_evidence(
                run_id,
                kind="observation",
                claim=f"Generated {len(analysis.get('previews', []))} bounded in-memory raster preview(s); no archive member was extracted to disk.",
                source_tool="aere.android.asset-preview",
                source_version=__version__,
                locator={"scope": "selected PNG/JPEG/GIF/WebP/BMP APK members"},
                data={"preview_count": len(analysis.get("previews", [])), "status": analysis.get("asset_preview_status"), "members": [str(item.get("name", ""))[:512] for item in analysis.get("previews", [])]},
                caveats=["Only small browser-previewable raster files are included; no proprietary texture/container decoding is performed."],
            )

        workspace.add_coverage(
            run_id,
            subject="APK ZIP central-directory scan",
            status=_status(archive.get("status"), missing="unknown"),
            scope="Member names, declared sizes/compressed sizes, and bounded central-directory sample for this SHA-256 APK.",
            provider_id="aere.android.zip-index",
            provider_version=__version__,
            operation_id="index",
            units_examined=archive.get("members_examined"),
            units_total=archive.get("member_count"),
            limitations=["No archive extraction; central-directory metadata is untrusted and may be incomplete."],
        )
        manifest_status = manifest.get("status")
        workspace.add_coverage(
            run_id,
            subject="Android manifest declaration parse",
            status=("complete" if manifest_status == "parsed" else "unknown" if manifest_status in {"missing", "unknown"} else "partial" if manifest_status in {"invalid", "unreadable", "ambiguous", "limited"} else "not_attempted"),
            scope="Bounded parse of AndroidManifest.xml package/version/SDK/permission/component declarations; resource references are not resolved.",
            provider_id="aere.android.manifest",
            provider_version=__version__,
            operation_id="parse_manifest",
            units_examined=manifest.get("elements_examined"),
            limitations=list(manifest.get("limitations", [])) + ([manifest.get("error")] if manifest.get("error") else []),
        )
        workspace.add_coverage(
            run_id,
            subject="DEX identifier-table scan",
            status=_status(analysis.get("dex_status"), missing="unknown"),
            scope="Bounded DEX header, string/type/class/method identifier tables; no bytecode, method bodies, or call graphs.",
            provider_id="aere.android.dex-identifiers",
            provider_version=__version__,
            operation_id="index_identifiers",
            units_examined=len(dex_files),
            units_total=analysis.get("dex_file_count"),
            limitations=["Identifier tables do not reconstruct source or establish code reachability."],
        )
        workspace.add_coverage(
            run_id,
            subject="Static engine-marker scan",
            status="partial" if archive.get("status") == "partial" else "complete",
            scope="Recognized Unity/Unreal/Godot marker names visible in the bounded APK member listing only.",
            provider_id="aere.android.engine-markers",
            provider_version=__version__,
            operation_id="scan_member_names",
            units_examined=archive.get("members_examined"),
            units_total=archive.get("member_count"),
            limitations=["Candidate markers are not a verified engine/version/runtime classification."],
        )
        workspace.add_coverage(
            run_id,
            subject="Raster image previews",
            status=("not_attempted" if not include_previews else _status(analysis.get("asset_preview_status"), missing="unknown")),
            scope="Optional in-memory previews of selected small PNG/JPEG/GIF/WebP/BMP members; no disk extraction.",
            provider_id="aere.android.asset-preview",
            provider_version=__version__,
            operation_id="preview_raster_members",
            units_examined=len(analysis.get("previews", [])) if include_previews else None,
            limitations=["Proprietary textures and other archive members are not decoded."],
        )
        for subject, operation, scope, provider in (
            ("Android DEX decompilation", "decompile_methods", "Method-body decompilation or bytecode/call-graph analysis.", "external.jadx"),
            ("Android resource and Smali decoding", "decode_resources", "Resource-table resolution, decoded resources, and Smali output.", "external.apktool"),
            ("Android device/runtime evidence", "observe_device_runtime", "ADB device state, process/log/screenshot capture, and runtime instrumentation.", "external.adb-runtime"),
        ):
            workspace.add_coverage(
                run_id,
                subject=subject,
                status="unsupported",
                scope=scope,
                provider_id=provider,
                operation_id=operation,
                limitations=["No verified adapter for this operation is connected in AERE v0.2."],
            )
        workspace.finish_run(run_id, "complete")
    except Exception:
        try:
            workspace.finish_run(run_id, "failed")
        except AereError:
            pass
        raise

    analysis["run_id"] = run_id
    analysis["evidence_count"] = len(workspace.list_evidence(run_id))
    analysis["coverage_count"] = len(workspace.list_coverage(run_id))
    return analysis


def inspect_steam_workspace(
    workspace: Workspace,
    target: str | Path,
    *,
    include_previews: bool = False,
) -> dict[str, Any]:
    """Scan one Steam game folder, linking compact facts to appmanifest evidence when available."""
    analysis = inspect_steam_install(workspace, target, include_previews=include_previews)
    manifest_source = analysis.pop("_manifest_source_path", None)
    analysis = _redact_export_paths(_redact_json(analysis))
    _enforce_response_limit(workspace, analysis)
    run_id: str | None = None
    anchor_artifact_id: str | None = None
    if manifest_source:
        anchor = workspace.import_file(manifest_source)
        if anchor["sha256"] != analysis.get("steam_manifest", {}).get("sha256"):
            raise AereError("artifact_changed", "Steam appmanifest changed between parsing and evidence registration.")
        anchor_artifact_id = anchor["artifact_id"]
        run = workspace.create_run(
            anchor_artifact_id,
            "steam-install-static-inspection",
            _STEAM_PROVIDER,
            {"include_previews": include_previews, "analysis_version": "0.2.0"},
        )
        run_id = run["run_id"]
        try:
            manifest = analysis.get("steam_manifest", {})
            workspace.add_evidence(
                run_id,
                kind="observation" if manifest.get("status") == "parsed" else "unknown",
                claim=f"Steam appmanifest metadata was parsed for App ID {manifest.get('appid')!r} and build {manifest.get('buildid')!r}.",
                source_tool="aere.steam.appmanifest",
                source_version=__version__,
                locator={"scope": "Steam appmanifest key/value metadata"},
                data={key: manifest.get(key) for key in ("status", "appid", "name", "installdir", "buildid", "branch", "state_flags", "size_on_disk", "last_updated", "sha256")},
                caveats=["Steam distribution metadata does not establish engine, asset parser, platform/runtime behavior, or compatibility."],
            )
            inventory = analysis.get("inventory", {})
            workspace.add_evidence(
                run_id,
                kind="observation",
                claim=f"Bounded inventory hashed {inventory.get('file_count', 0)} file(s) totaling {inventory.get('total_bytes', 0)} byte(s) in the approved install directory.",
                source_tool="aere.steam.file-inventory",
                source_version=__version__,
                locator={"scope": "game install directory, relative paths only"},
                data={
                    "file_count": inventory.get("file_count"),
                    "total_bytes": inventory.get("total_bytes"),
                    "truncated": inventory.get("truncated"),
                    "skipped_count": inventory.get("skipped_count"),
                    "extension_counts": analysis.get("file_extension_counts", {}),
                    "file_sample": [
                        {"relative_path": str(item.get("relative_path", ""))[:512], "size": item.get("size"), "sha256": item.get("sha256"), "format": item.get("format")}
                        for item in analysis.get("files", [])[:100]
                    ],
                },
                caveats=["The file sample may be truncated; generated/user data may be excluded by workspace inventory policy."],
            )
            if analysis.get("engine_candidates"):
                workspace.add_evidence(
                    run_id,
                    kind="inference",
                    claim="Installed file markers suggest engine candidates; no engine or title/build compatibility is confirmed.",
                    source_tool="aere.steam.engine-markers",
                    source_version=__version__,
                    locator={"scope": "relative installed-file paths and extensions"},
                    data={"candidates": [
                        {"engine": item.get("engine"), "status": item.get("status"), "supporting_files": [str(name)[:512] for name in item.get("supporting_files", [])[:20]]}
                        for item in analysis["engine_candidates"][:10]
                    ]},
                    caveats=["Markers may be bundled, renamed, stale, or unrelated; no executable/runtime was launched."],
                    confidence=0.4,
                )
            vpk_indexes = analysis.get("vpk_indexes", [])
            if vpk_indexes:
                workspace.add_evidence(
                    run_id,
                    kind="observation",
                    claim=f"Inspected bounded VPK directory metadata for {sum(item.get('status') in {'parsed', 'partial'} for item in vpk_indexes)} VPK candidate(s); no members were read or extracted.",
                    source_tool="aere.steam.vpk-index",
                    source_version=__version__,
                    locator={"scope": "VPK header and directory tree metadata"},
                    data={"indexes": [{key: item.get(key) for key in ("relative_path", "status", "version", "tree_size", "entry_count", "entries_examined", "truncated", "error")} | {"sample_paths": [str(entry.get("path", ""))[:512] for entry in item.get("entries", [])[:10]]} for item in vpk_indexes[:5]]},
                    caveats=["Archive member bytes, CRCs, and external VPK segments were not verified."],
                )
            if include_previews:
                workspace.add_evidence(
                    run_id,
                    kind="observation",
                    claim=f"Generated {len(analysis.get('previews', []))} bounded local raster preview(s).",
                    source_tool="aere.steam.asset-preview",
                    source_version=__version__,
                    locator={"scope": "selected loose PNG/JPEG/GIF/WebP/BMP files under the install root"},
                    data={"preview_count": len(analysis.get("previews", [])), "status": analysis.get("asset_preview_status"), "files": [str(item.get("name", ""))[:512] for item in analysis.get("previews", [])]},
                    caveats=["This does not decode textures or assets inside proprietary containers."],
                )

            inventory = analysis.get("inventory", {})
            inventory_status = "partial" if inventory.get("truncated") or inventory.get("skipped_count") else "complete"
            manifest_status = "complete" if manifest.get("status") == "parsed" else "unknown"
            workspace.add_coverage(
                run_id,
                subject="Steam install file inventory",
                status=inventory_status,
                scope="Approved single-game install folder; bounded file count/entry count/per-file bytes/total bytes; SHA-256 per observed file.",
                provider_id="aere.steam.file-inventory",
                provider_version=__version__,
                operation_id="inventory_and_hash",
                units_examined=inventory.get("file_count"),
                limitations=["Inventory limits, excluded directories, unreadable files, and skipped symlinks can leave gaps."],
            )
            workspace.add_coverage(
                run_id,
                subject="Steam appmanifest metadata",
                status=manifest_status,
                scope="App ID, name, install directory, build/branch fields from the matching Steam appmanifest when present.",
                provider_id="aere.steam.appmanifest",
                provider_version=__version__,
                operation_id="parse_manifest",
                units_examined=1 if manifest_status == "complete" else 0,
                units_total=1 if manifest_status == "complete" else None,
                limitations=["Manifest metadata is not proof that all depot content is present or matches a particular runtime."],
            )
            workspace.add_coverage(
                run_id,
                subject="Engine marker scan",
                status="partial" if inventory_status == "partial" else "complete",
                scope="Recognized Unity/Unreal/Godot/Source-family file markers in inventoried relative paths only.",
                provider_id="aere.steam.engine-markers",
                provider_version=__version__,
                operation_id="scan_inventory_paths",
                units_examined=inventory.get("file_count"),
                limitations=["Heuristic candidates are not verified compatibility claims."],
            )
            vpk_status = "partial" if any(item.get("status") not in {"parsed", "not_vpk"} for item in vpk_indexes) or len(vpk_indexes) > 12 else "complete"
            workspace.add_coverage(
                run_id,
                subject="VPK directory-tree metadata",
                status=vpk_status,
                scope="Bounded VPK v1/v2 header and directory-tree entry metadata for sampled .vpk candidates; no member data extraction.",
                provider_id="aere.steam.vpk-index",
                provider_version=__version__,
                operation_id="list_vpk_entries",
                units_examined=sum(int(item.get("entries_examined", item.get("entry_count") or 0) or 0) for item in vpk_indexes if item.get("status") in {"parsed", "partial"}),
                limitations=["CRC values and external archive-index files are not validated; proprietary archive families remain unsupported."],
            )
            workspace.add_coverage(
                run_id,
                subject="Loose raster image previews",
                status=("not_attempted" if not include_previews else _status(analysis.get("asset_preview_status"), missing="unknown")),
                scope="Optional in-memory previews of small loose PNG/JPEG/GIF/WebP/BMP files under the install directory.",
                provider_id="aere.steam.asset-preview",
                provider_version=__version__,
                operation_id="preview_raster_files",
                units_examined=len(analysis.get("previews", [])) if include_previews else None,
                limitations=["Textures and files inside VPK/PAK/Unity/Godot archives are not decoded by this operation."],
            )
            for subject, operation, scope in (
                ("Unity asset decoding", "decode_unity_assets", "Unity serialized files, AssetBundles, and Unity-specific texture/audio/model decoding."),
                ("Unreal asset decoding", "decode_unreal_assets", "Unreal PAK/IoStore and uasset/umap content decoding."),
                ("Godot/Source 2 proprietary asset decoding", "decode_engine_assets", "Godot PCK contents and Source 2 resource-file decoding."),
                ("Game code analysis", "disassemble_or_decompile", "Native/managed disassembly, decompilation, symbols, and call/reference queries."),
                ("Game runtime behavior", "observe_runtime", "Game launch, process/device observation, and runtime instrumentation."),
            ):
                workspace.add_coverage(
                    run_id,
                    subject=subject,
                    status="unsupported",
                    scope=scope,
                    provider_id="aere.steam.unsupported-layer",
                    operation_id=operation,
                    limitations=["No engine/title-specific decoder or runtime adapter is connected in AERE v0.2."],
                )
            workspace.finish_run(run_id, "complete")
        except Exception:
            try:
                workspace.finish_run(run_id, "failed")
            except AereError:
                pass
            raise

    analysis["run_id"] = run_id
    analysis["evidence_anchor_artifact_id"] = anchor_artifact_id
    analysis["evidence_count"] = len(workspace.list_evidence(run_id)) if run_id else 0
    analysis["coverage_count"] = len(workspace.list_coverage(run_id)) if run_id else 0
    if not run_id:
        analysis["evidence_note"] = "No matching Steam appmanifest was found; analysis is returned without a persisted evidence run."
    return analysis
