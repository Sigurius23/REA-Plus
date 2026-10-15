"""Optional official-MCP-SDK server exposing the AERE core over local stdio.

No tool in this module accepts a command string or launches a target process.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from .core import AereError, Workspace


def _wrap(operation):
    try:
        return operation()
    except AereError as exc:
        return exc.as_dict()


def build_server(home: str | None = None):
    """Build a FastMCP server; the optional SDK is imported only on demand."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise AereError("mcp_extra_missing", "The optional MCP SDK is not installed. Install with `pip install 'aere-workbench[mcp]'`.", {"reason": str(exc)}) from exc

    server = FastMCP("AERE Workbench")
    workspace = Workspace(home)

    @server.tool()
    def workspace_status() -> dict[str, Any]:
        """Show local workspace counts, policy, version, and approved-root count."""
        return workspace.status()

    @server.tool()
    def provider_catalog() -> dict[str, Any]:
        """List shipped capabilities and external tools without launching them."""
        return {"providers": workspace.discover_providers()}

    @server.tool()
    def inventory_path(path: str) -> dict[str, Any]:
        """Hash and classify bounded local files under an approved root; no extraction or execution."""
        return _wrap(lambda: workspace.inventory(path))

    @server.tool()
    def import_artifact(path: str) -> dict[str, Any]:
        """Register a regular file by SHA-256; the source file is not copied."""
        return _wrap(lambda: workspace.import_file(path))

    @server.tool()
    def list_artifacts(limit: int = 100) -> dict[str, Any]:
        """List registered artifact metadata (no local source paths)."""
        return _wrap(lambda: {"artifacts": workspace.list_artifacts(limit)})

    @server.tool()
    def get_artifact(artifact_id: str) -> dict[str, Any]:
        """Return registered metadata for one SHA-256 artifact identity."""
        return _wrap(lambda: workspace.artifact(artifact_id))

    @server.tool()
    def probe_artifact(artifact_id: str) -> dict[str, Any]:
        """Re-hash a registered file and return conservative signature/container candidates."""
        return _wrap(lambda: workspace.probe(artifact_id))

    @server.tool()
    def extract_ascii_strings(artifact_id: str, min_length: int = 6, limit: int = 200) -> dict[str, Any]:
        """Extract bounded printable ASCII strings with offsets and secret-like value redaction."""
        return _wrap(lambda: workspace.strings(artifact_id, min_length, limit))

    @server.tool()
    def list_zip_members(artifact_id: str, limit: int = 1000) -> dict[str, Any]:
        """List ZIP central-directory metadata only. Archive members are never extracted."""
        return _wrap(lambda: workspace.archive_members(artifact_id, limit))

    @server.tool()
    def inspect_android_apk(artifact_id: str, include_previews: bool = False) -> dict[str, Any]:
        """Parse bounded AndroidManifest.xml and DEX identifier tables, index APK assets, and record scoped evidence/coverage. Optional previews are capped raster data URIs; no files are extracted to disk and the APK is never executed."""
        from .analysis import inspect_android_workspace

        return _wrap(lambda: inspect_android_workspace(workspace, artifact_id, include_previews=include_previews))

    @server.tool()
    def inspect_steam_install(target: str, include_previews: bool = False) -> dict[str, Any]:
        """Inventory one approved Steam game folder or appmanifest, detect engine markers as candidates, parse bounded VPK directory metadata, optionally preview loose raster images, and record evidence when a manifest anchor is available. Never launches the game or extracts archive members."""
        from .analysis import inspect_steam_workspace

        return _wrap(lambda: inspect_steam_workspace(workspace, target, include_previews=include_previews))

    @server.tool()
    def create_run(artifact_id: str, workflow: str, provider_id: str = "manual", config: dict[str, Any] | None = None) -> dict[str, Any]:

        """Create a provenance-bearing run record; this does not invoke a provider."""
        return _wrap(lambda: workspace.create_run(artifact_id, workflow, provider_id, config or {}))

    @server.tool()
    def record_evidence(
        run_id: str,
        kind: str,
        claim: str,
        source_tool: str,
        source_version: str | None = None,
        locator: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        supports: list[str] | None = None,
        caveats: list[str] | None = None,
        confidence: float | None = None,
    ) -> dict[str, Any]:
        """Record an observation, inference, hypothesis, or unknown with provenance and caveats."""
        return _wrap(lambda: workspace.add_evidence(run_id, kind, claim, source_tool, source_version, locator, data, supports, caveats, confidence))

    @server.tool()
    def list_evidence(run_id: str) -> dict[str, Any]:
        """Return evidence records attached to one run."""
        return _wrap(lambda: {"evidence": workspace.list_evidence(run_id)})

    @server.tool()
    def finish_run(run_id: str, status: str = "complete") -> dict[str, Any]:
        """Mark a run complete, partial, failed, or cancelled."""
        return _wrap(lambda: workspace.finish_run(run_id, status))

    @server.tool()
    def record_coverage(
        run_id: str,
        subject: str,
        status: str,
        scope: str,
        provider_id: str,
        operation_id: str,
        units_examined: int | None = None,
        units_total: int | None = None,
        excluded: list[str] | None = None,
        limitations: list[str] | None = None,
        notes: list[str] | None = None,
        provider_version: str | None = None,
    ) -> dict[str, Any]:
        """Record scoped complete/partial/unsupported/not-attempted/unknown coverage."""
        return _wrap(lambda: workspace.add_coverage(run_id, subject, status, scope, provider_id, operation_id, units_examined, units_total, excluded, limitations, notes, provider_version))

    @server.tool()
    def list_coverage(run_id: str) -> dict[str, Any]:
        """List structured coverage statements for a run."""
        return _wrap(lambda: {"coverage": workspace.list_coverage(run_id)})

    @server.tool()
    def export_run_json(run_id: str) -> dict[str, Any]:
        """Return a portable evidence bundle with absolute paths and target bytes omitted."""
        return _wrap(lambda: workspace.export_run(run_id))

    @server.tool()
    def export_run_markdown(run_id: str) -> dict[str, Any]:
        """Render a human-readable report from the evidence ledger."""
        return _wrap(lambda: {"markdown": workspace.render_markdown_report(run_id)})

    return server


def run_server(log_level: str = "WARNING", home: str | None = None) -> None:
    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.WARNING), stream=sys.stderr)
    server = build_server(home)
    server.run(transport="stdio")
