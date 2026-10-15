from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from aere.core import Workspace
from .test_android import _apk
from .test_steam import _write_vpk


def test_optional_stdio_mcp_surface(tmp_path: Path):
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    project_src = str(Path(__file__).resolve().parents[1] / "src")
    env = {**os.environ, "PYTHONPATH": project_src}
    home = tmp_path / "mcp-workspace"
    root = tmp_path / "inputs"
    root.mkdir()
    workspace = Workspace(home)
    workspace.allow_root(root)
    apk_path = root / "sample.apk"
    _apk(apk_path)
    imported = workspace.import_file(apk_path)
    library = root / "library"
    steamapps = library / "steamapps"
    game = steamapps / "common" / "MCP Game"
    game.mkdir(parents=True)
    (steamapps / "appmanifest_7.acf").write_text('"AppState" { "appid" "7" "name" "MCP Game" "installdir" "MCP Game" "buildid" "1" }', encoding="utf-8")
    (game / "UnityPlayer.dll").write_bytes(b"unity")
    _write_vpk(game / "pak_dir.vpk")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "aere.cli", "--home", str(home), "mcp"],
        env=env,
    )

    async def exercise():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                names = {tool.name for tool in listed.tools}
                assert {"workspace_status", "import_artifact", "record_evidence", "record_coverage", "export_run_json", "inspect_android_apk", "inspect_steam_install"} <= names
                assert "allow_input_root" not in names
                android_result = await session.call_tool("inspect_android_apk", {"artifact_id": imported["artifact_id"]})
                android = json.loads(android_result.content[0].text)
                assert android["manifest"]["package"] == "com.example.game"
                steam_result = await session.call_tool("inspect_steam_install", {"target": str(game)})
                steam = json.loads(steam_result.content[0].text)
                assert steam["steam_manifest"]["appid"] == "7"
                status_result = await session.call_tool("workspace_status", {})
                status = json.loads(status_result.content[0].text)
                assert status["home"] == str(home)
                assert status["allowed_root_count"] == 1

    asyncio.run(exercise())
