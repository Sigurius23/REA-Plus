"""Command-line interface for AERE Workbench."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core import AereError, Workspace


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _parse_json(value: str | None, expected: type, label: str) -> Any:
    if value is None:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AereError("invalid_json", f"{label} is not valid JSON.", {"reason": str(exc)}) from exc
    if not isinstance(parsed, expected):
        raise AereError("invalid_json_type", f"{label} must decode to {expected.__name__}.")
    return parsed



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aere", description="Evidence-first local reverse-engineering workbench")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--home", help="workspace directory (or set AERE_HOME)")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize a workspace and optionally approve input roots")
    init.add_argument("--allow-root", action="append", default=[], metavar="DIR")

    sub.add_parser("status", help="show workspace status and ledger counts")
    sub.add_parser("providers", help="show built-in and external provider status")

    allow_root = sub.add_parser("allow-root", help="approve a local directory as an input root")
    allow_root.add_argument("path")

    inventory = sub.add_parser("inventory", help="bounded read-only inventory of one file or a directory")
    inventory.add_argument("path")

    imp = sub.add_parser("import", help="register one file by SHA-256; does not copy the file")
    imp.add_argument("file")

    artifacts = sub.add_parser("artifacts", help="list registered artifacts")
    artifacts.add_argument("--limit", type=int, default=100)

    artifact = sub.add_parser("artifact", help="show metadata for one registered artifact")
    artifact.add_argument("artifact_id")

    probe = sub.add_parser("probe", help="re-verify and probe a registered artifact")
    probe.add_argument("artifact_id")

    strings = sub.add_parser("strings", help="extract bounded printable ASCII strings")
    strings.add_argument("artifact_id")
    strings.add_argument("--min-length", type=int, default=6)
    strings.add_argument("--limit", type=int, default=200)

    archive = sub.add_parser("archive-list", help="list ZIP central-directory metadata; never extracts")
    archive.add_argument("artifact_id")
    archive.add_argument("--limit", type=int, default=1000)

    android = sub.add_parser("android", help="inspect an Android APK and generate an offline report")
    android_sub = android.add_subparsers(dest="android_command", required=True)
    android_inspect = android_sub.add_parser("inspect", help="parse bounded APK manifest and DEX identifiers")
    android_inspect.add_argument("artifact_id")
    android_inspect.add_argument("--previews", action="store_true", help="embed a bounded sample of raster assets as data URIs")
    android_report = android_sub.add_parser("report", help="write a self-contained offline HTML APK report")
    android_report.add_argument("artifact_id")
    android_report.add_argument("--out", required=True, help="HTML report output path")

    steam = sub.add_parser("steam", help="inspect one approved Steam game install and generate an offline report")
    steam_sub = steam.add_subparsers(dest="steam_command", required=True)
    steam_inspect = steam_sub.add_parser("inspect", help="parse Steam appmanifest, inventory files, and index VPK metadata")
    steam_inspect.add_argument("target", help="one approved game install directory or appmanifest_*.acf")
    steam_inspect.add_argument("--previews", action="store_true", help="embed a bounded sample of loose raster assets as data URIs")
    steam_report = steam_sub.add_parser("report", help="write a self-contained offline HTML Steam install report")
    steam_report.add_argument("target", help="one approved game install directory or appmanifest_*.acf")
    steam_report.add_argument("--out", required=True, help="HTML report output path")

    run = sub.add_parser("run", help="manage provenance-bearing analysis runs")
    run_sub = run.add_subparsers(dest="run_command", required=True)
    run_create = run_sub.add_parser("create", help="create an empty evidence run")
    run_create.add_argument("artifact_id")
    run_create.add_argument("--workflow", required=True)
    run_create.add_argument("--provider", default="manual")
    run_create.add_argument("--config-json")
    run_finish = run_sub.add_parser("finish", help="finish a run with an explicit status")
    run_finish.add_argument("run_id")
    run_finish.add_argument("--status", choices=("complete", "partial", "failed", "cancelled"), default="complete")

    evidence = sub.add_parser("evidence", help="record or query evidence")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_add = evidence_sub.add_parser("add", help="add one evidence record")
    evidence_add.add_argument("run_id")
    evidence_add.add_argument("--kind", required=True, choices=("observation", "inference", "hypothesis", "unknown"))
    evidence_add.add_argument("--claim", required=True)
    evidence_add.add_argument("--tool", required=True, dest="source_tool")
    evidence_add.add_argument("--version", dest="source_version")
    evidence_add.add_argument("--locator-json")
    evidence_add.add_argument("--data-json")
    evidence_add.add_argument("--supports-json")
    evidence_add.add_argument("--caveats-json")
    evidence_add.add_argument("--confidence", type=float)
    evidence_list = evidence_sub.add_parser("list", help="list evidence for a run")
    evidence_list.add_argument("run_id")

    coverage = sub.add_parser("coverage", help="record or query structured coverage")
    coverage_sub = coverage.add_subparsers(dest="coverage_command", required=True)
    coverage_add = coverage_sub.add_parser("add", help="record one scoped coverage statement")
    coverage_add.add_argument("run_id")
    coverage_add.add_argument("--subject", required=True)
    coverage_add.add_argument("--status", required=True, choices=("complete", "partial", "unsupported", "not_attempted", "unknown"))
    coverage_add.add_argument("--scope", required=True)
    coverage_add.add_argument("--provider", required=True)
    coverage_add.add_argument("--provider-version")
    coverage_add.add_argument("--operation", required=True)
    coverage_add.add_argument("--units-examined", type=int)
    coverage_add.add_argument("--units-total", type=int)
    coverage_add.add_argument("--excluded-json")
    coverage_add.add_argument("--limitations-json")
    coverage_add.add_argument("--notes-json")
    coverage_list = coverage_sub.add_parser("list", help="list coverage records for a run")
    coverage_list.add_argument("run_id")

    report = sub.add_parser("report", help="export an evidence bundle as JSON or Markdown")
    report.add_argument("run_id")
    report.add_argument("--format", choices=("json", "markdown"), default="json")
    report.add_argument("--out", help="write report to a file instead of stdout")

    triage = sub.add_parser("triage", help="create a provenance-bearing built-in static triage run")
    triage.add_argument("artifact_id")
    triage.add_argument("--workflow", default="static-triage")
    triage.add_argument("--include-strings", action="store_true")
    triage.add_argument("--string-limit", type=int, default=40)
    triage.add_argument("--list-archive-members", action="store_true")
    triage.add_argument("--archive-limit", type=int, default=100)

    mcp = sub.add_parser("mcp", help="run the optional local stdio MCP server")
    mcp.add_argument("--log-level", default="WARNING", choices=("DEBUG", "INFO", "WARNING", "ERROR"))

    return parser


def _triage(workspace: Workspace, args: argparse.Namespace) -> dict[str, Any]:
    run = workspace.create_run(args.artifact_id, args.workflow, "builtin.triage", config={
        "include_strings": bool(args.include_strings),
        "list_archive_members": bool(args.list_archive_members),
        "string_limit": args.string_limit if args.include_strings else None,
        "archive_limit": args.archive_limit if args.list_archive_members else None,
    })
    run_id = run["run_id"]
    try:
        probe = workspace.probe(args.artifact_id)
        workspace.add_evidence(
            run_id,
            kind="observation",
            claim=f"Built-in bounded probe returned the format candidate {probe['format']!r}; this is a signature/extension result, not proof of a loader, engine, or runtime behavior.",
            source_tool="aere.builtin.probe",
            source_version=workspace.status()["version"],
            locator={"scope": "file-header-and-container-metadata"},
            data={"format": probe["format"], "classification": probe["classification"], "details": probe["details"]},
            caveats=["No target code was executed.", "Format candidates can be ambiguous or malformed."],
        )
        probe_details = probe.get("details", {})
        probe_partial = bool(probe_details.get("member_count_limited") or probe_details.get("directory_bytes_limited") or probe_details.get("zip_parse_error"))
        workspace.add_coverage(
            run_id,
            subject="Signature and container probe",
            status="partial" if probe_partial else "complete",
            scope="Fixed file signatures, extension candidate, and bounded ZIP central-directory metadata sample; not a semantic binary parse.",
            provider_id="aere.builtin.probe",
            operation_id="probe",
            units_examined=probe.get("details", {}).get("member_sample_count"),
            units_total=probe.get("details", {}).get("member_count"),
            limitations=["Does not establish a valid loader, engine, architecture support, or runtime behavior."],
            provider_version=workspace.status()["version"],
        )
        artifact_size = int(workspace.artifact(args.artifact_id)["size"])
        if args.include_strings:
            findings = workspace.strings(args.artifact_id, limit=args.string_limit)
            samples = []
            for item in findings["strings"][:25]:
                sample = dict(item)
                if len(sample["value"]) > 500:
                    sample["value"] = sample["value"][:500]
                    sample["sample_truncated"] = True
                samples.append(sample)
            workspace.add_evidence(
                run_id,
                kind="observation",
                claim=f"A bounded printable-ASCII scan returned {findings['count']} result(s) over {findings['bytes_scanned']} byte(s).",
                source_tool="aere.builtin.strings.ascii",
                source_version=workspace.status()["version"],
                locator={"scope": "whole-file", "minimum_length": 6},
                data={"count": findings["count"], "bytes_scanned": findings["bytes_scanned"], "truncated": findings["truncated"], "samples": samples},
                caveats=["Only printable ASCII was scanned.", "Secret-like values are redacted; results are not interpreted as reachable code or behavior."],
            )
            workspace.add_coverage(
                run_id,
                subject="Printable ASCII string scan",
                status="partial" if findings["truncated"] else "complete",
                scope="Whole-file printable ASCII scan from offset 0, with configured byte/result/sample limits.",
                provider_id="aere.builtin.strings.ascii",
                operation_id="extract",
                units_examined=findings["bytes_scanned"],
                units_total=artifact_size,
                limitations=["Does not decode UTF-16, compressed/encrypted content, or semantic reachability."],
                provider_version=workspace.status()["version"],
            )
        else:
            workspace.add_coverage(
                run_id,
                subject="Printable ASCII string scan",
                status="not_attempted",
                scope="Whole-file printable ASCII scan.",
                provider_id="aere.builtin.strings.ascii",
                operation_id="extract",
                limitations=["Not requested in this run."],
                provider_version=workspace.status()["version"],
            )
        if args.list_archive_members:
            archive = workspace.archive_members(args.artifact_id, limit=args.archive_limit)
            members = []
            for item in archive["members"][:50]:
                safe_item = dict(item)
                if len(safe_item["name"]) > 256:
                    safe_item["name"] = safe_item["name"][:256]
                    safe_item["name_truncated"] = True
                members.append(safe_item)
            workspace.add_evidence(
                run_id,
                kind="observation",
                claim=f"ZIP-compatible central-directory metadata lists {archive['member_count']} member(s); no member contents were extracted.",
                source_tool="aere.builtin.zip.metadata",
                source_version=workspace.status()["version"],
                locator={"scope": "zip-central-directory"},
                data={"member_count": archive["member_count"], "truncated": archive["truncated"], "members": members},
                caveats=["Archive metadata is untrusted input.", "Listing does not establish that files are valid, loadable, or used by a target."],
            )
            workspace.add_coverage(
                run_id,
                subject="ZIP central-directory listing",
                status="partial" if archive["truncated"] else "complete",
                scope="Member names and metadata only; member contents were not extracted or decompressed.",
                provider_id="aere.builtin.zip.metadata",
                operation_id="list_members",
                units_examined=len(archive["members"]),
                units_total=archive["member_count"],
                limitations=["Names/metadata do not prove members are valid or used by a target."],
                provider_version=workspace.status()["version"],
            )
        else:
            workspace.add_coverage(
                run_id,
                subject="ZIP central-directory listing",
                status="not_attempted",
                scope="ZIP member names and metadata.",
                provider_id="aere.builtin.zip.metadata",
                operation_id="list_members",
                limitations=["Not requested in this run."],
                provider_version=workspace.status()["version"],
            )
        workspace.add_coverage(
            run_id,
            subject="Deep native/bytecode analysis, Android resource decoding, proprietary game-asset parsing, and runtime analysis",
            status="unsupported",
            scope="AERE v0.2 parses bounded APK manifests/DEX identifiers and Steam/VPK metadata, but includes no disassembler/decompiler, resource-table decoder, proprietary asset decoder, or runtime provider.",
            provider_id="aere.workbench",
            operation_id="provider-boundary",
            limitations=["External tools may be listed as references or discovered on PATH, but are not invoked or verified as AERE adapters."],
            provider_version=workspace.status()["version"],
        )
        workspace.finish_run(run_id, "complete")
    except Exception:
        try:
            workspace.finish_run(run_id, "failed")
        except AereError:
            pass
        raise
    return workspace.export_run(run_id)


def _write_offline_html(workspace: Workspace, report_data: dict[str, Any], output_value: str, kind: str) -> dict[str, Any]:
    from .visualization import render_offline_html

    output = Path(output_value).expanduser().absolute()
    if output.exists() and output.is_symlink():
        raise AereError("output_symlink_rejected", "Report output path must not be a symlink.")
    if not output.parent.exists() or not output.parent.is_dir():
        raise AereError("output_parent_missing", "Report output parent directory must already exist.")
    text = render_offline_html(report_data)
    encoded = text.encode("utf-8")
    if len(encoded) > int(workspace._limits()["max_report_bytes"]):
        raise AereError("report_too_large", "Offline HTML report exceeds the configured report-size limit.", {"bytes": len(encoded), "limit": workspace._limits()["max_report_bytes"]})
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "wb", closefd=True) as stream:
        stream.write(encoded)
    return {"written": str(output), "format": "html", "kind": kind, "bytes": len(encoded)}


def _run_mcp(log_level: str, home: str | None) -> int:
    try:
        from .mcp_server import run_server
    except ImportError as exc:
        raise AereError("mcp_extra_missing", "The optional MCP SDK is not installed. Install with `pip install 'aere-workbench[mcp]'`.", {"reason": str(exc)}) from exc
    run_server(log_level=log_level, home=home)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "mcp":
            return _run_mcp(args.log_level, args.home)
        workspace = Workspace(args.home)
        if args.command == "init":
            for root in args.allow_root:
                workspace.allow_root(root)
            result = workspace.status()
        elif args.command == "status":
            result = workspace.status()
        elif args.command == "providers":
            result = {"providers": workspace.discover_providers()}
        elif args.command == "allow-root":
            result = workspace.allow_root(args.path)
        elif args.command == "inventory":
            result = workspace.inventory(args.path)
        elif args.command == "import":
            result = workspace.import_file(args.file)
        elif args.command == "artifacts":
            result = {"artifacts": workspace.list_artifacts(args.limit)}
        elif args.command == "artifact":
            result = workspace.artifact(args.artifact_id)
        elif args.command == "probe":
            result = workspace.probe(args.artifact_id)
        elif args.command == "strings":
            result = workspace.strings(args.artifact_id, args.min_length, args.limit)
        elif args.command == "archive-list":
            result = workspace.archive_members(args.artifact_id, args.limit)
        elif args.command == "android":
            from .analysis import inspect_android_workspace
            from .android import android_report_sections

            if args.android_command == "inspect":
                result = inspect_android_workspace(workspace, args.artifact_id, include_previews=args.previews)
            else:
                analysis = inspect_android_workspace(workspace, args.artifact_id, include_previews=True)
                report_data = android_report_sections(analysis)
                report_data["kind"] = "Android APK"
                result = _write_offline_html(workspace, report_data, args.out, "android-apk")
                result["run_id"] = analysis["run_id"]
        elif args.command == "steam":
            from .analysis import inspect_steam_workspace
            from .steam import steam_report_sections

            if args.steam_command == "inspect":
                result = inspect_steam_workspace(workspace, args.target, include_previews=args.previews)
            else:
                analysis = inspect_steam_workspace(workspace, args.target, include_previews=True)
                report_data = steam_report_sections(analysis)
                report_data["kind"] = "Steam game install"
                result = _write_offline_html(workspace, report_data, args.out, "steam-install")
                result["run_id"] = analysis.get("run_id")
        elif args.command == "run" and args.run_command == "create":
            config = _parse_json(args.config_json, dict, "--config-json") or {}
            result = workspace.create_run(args.artifact_id, args.workflow, args.provider, config)
        elif args.command == "run" and args.run_command == "finish":
            result = workspace.finish_run(args.run_id, args.status)
        elif args.command == "evidence" and args.evidence_command == "add":
            result = workspace.add_evidence(
                args.run_id,
                args.kind,
                args.claim,
                args.source_tool,
                args.source_version,
                _parse_json(args.locator_json, dict, "--locator-json"),
                _parse_json(args.data_json, dict, "--data-json"),
                _parse_json(args.supports_json, list, "--supports-json"),
                _parse_json(args.caveats_json, list, "--caveats-json"),
                args.confidence,
            )
        elif args.command == "evidence" and args.evidence_command == "list":
            result = {"evidence": workspace.list_evidence(args.run_id)}
        elif args.command == "coverage" and args.coverage_command == "add":
            result = workspace.add_coverage(
                args.run_id,
                args.subject,
                args.status,
                args.scope,
                args.provider,
                args.operation,
                args.units_examined,
                args.units_total,
                _parse_json(args.excluded_json, list, "--excluded-json"),
                _parse_json(args.limitations_json, list, "--limitations-json"),
                _parse_json(args.notes_json, list, "--notes-json"),
                args.provider_version,
            )
        elif args.command == "coverage" and args.coverage_command == "list":
            result = {"coverage": workspace.list_coverage(args.run_id)}
        elif args.command == "report":
            if args.format == "json":
                text = _json(workspace.export_run(args.run_id)) + "\n"
            else:
                text = workspace.render_markdown_report(args.run_id)
            if args.out:
                output = Path(args.out)
                output.write_text(text, encoding="utf-8")
                result = {"written": str(output), "format": args.format, "run_id": args.run_id}
            else:
                sys.stdout.write(text)
                return 0
        elif args.command == "triage":
            result = _triage(workspace, args)
        else:
            parser.error("unsupported command")
            return 2
        sys.stdout.write(_json(result) + "\n")
        return 0
    except AereError as exc:
        sys.stderr.write(_json(exc.as_dict()) + "\n")
        return 2
    except (OSError, sqlite3.Error) as exc:  # type: ignore[name-defined]
        sys.stderr.write(_json({"error": {"code": "io_error", "message": str(exc)}}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
