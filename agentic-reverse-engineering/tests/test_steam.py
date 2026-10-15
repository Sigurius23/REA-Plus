from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aere.analysis import inspect_steam_workspace
from aere.core import AereError, Workspace
from aere.steam import parse_vdf, parse_vpk
from aere.steam import steam_report_sections
from aere.visualization import render_offline_html


def _write_vpk(path: Path) -> None:
    tree = bytearray()
    tree.extend(b"png\x00 \x00icon\x00")
    tree.extend(struct.pack("<IHHIIH", 0xAABBCCDD, 0, 0x7FFF, 0, 12, 0xFFFF))
    tree.extend(b"\x00\x00\x00")  # end filename list, directory list, extension list
    header_size = 28
    tree_size = len(tree)
    header = struct.pack("<III4I", 0x55AA1234, 2, tree_size, 12, 0, 0, 0)
    path.write_bytes(header + tree + b"\x00" * 12)


def _steam_fixture(tmp_path: Path) -> tuple[Workspace, Path, Path]:
    library = tmp_path / "library"
    steamapps = library / "steamapps"
    game = steamapps / "common" / "Example Game"
    game.mkdir(parents=True)
    (steamapps / "appmanifest_12345.acf").write_text(
        '"AppState" { "appid" "12345" "name" "Example Game" "installdir" "Example Game" "buildid" "987654" "betakey" "public" }',
        encoding="utf-8",
    )
    (game / "UnityPlayer.dll").write_bytes(b"unity marker")
    (game / "GameAssembly.dll").write_bytes(b"il2cpp marker")
    (game / "Example_Data").mkdir()
    (game / "Example_Data" / "globalgamemanagers").write_bytes(b"marker")
    (game / "splash.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    _write_vpk(game / "pak01_dir.vpk")
    workspace = Workspace(tmp_path / "workspace")
    workspace.allow_root(library)
    return workspace, game, steamapps / "appmanifest_12345.acf"


def test_vdf_parses_nested_appmanifest_values_and_comments():
    parsed = parse_vdf('''// comment\n"AppState" { "appid" "123" "name" "A \\"B\\" Game" "InstalledDepots" { "456" { "manifest" "789" } } }''')
    assert parsed["AppState"]["appid"] == "123"
    assert parsed["AppState"]["InstalledDepots"]["456"]["manifest"] == "789"


def test_vdf_rejects_duplicate_keys_and_unbalanced_braces():
    with pytest.raises(ValueError, match="duplicate"):
        parse_vdf('"AppState" { "appid" "1" "appid" "2" }')
    with pytest.raises(ValueError, match="unclosed"):
        parse_vdf('"AppState" { "appid" "1"')


def test_vpk_v2_directory_tree_is_indexed_without_reading_member_data(tmp_path: Path):
    path = tmp_path / "pak01_dir.vpk"
    _write_vpk(path)
    result = parse_vpk(path)
    assert result["status"] == "parsed"
    assert result["version"] == 2
    assert result["entry_count"] == 1
    assert result["entries"][0]["path"] == "icon.png"
    assert result["entries"][0]["directory_archive"] is True
    assert result["entries"][0]["range_valid"] is True


def test_vpk_content_hash_mismatch_is_reported_as_changed(tmp_path: Path):
    path = tmp_path / "pak01_dir.vpk"
    _write_vpk(path)
    result = parse_vpk(path, expected_sha256="0" * 64)
    assert result["status"] == "changed"
    assert "hash changed" in result["error"]


def test_steam_install_analysis_records_manifest_inventory_and_engine_candidates(tmp_path: Path):
    workspace, game, _manifest = _steam_fixture(tmp_path)
    result = inspect_steam_workspace(workspace, game, include_previews=True)

    assert result["steam_manifest"]["appid"] == "12345"
    assert result["steam_manifest"]["buildid"] == "987654"
    assert result["inventory"]["file_count"] == 5
    assert any(item["engine"] == "Unity" for item in result["engine_candidates"])
    assert result["vpk_indexes"][0]["entries"][0]["path"] == "icon.png"
    assert result["previews"][0]["mime_type"] == "image/png"
    assert result["run_id"]
    assert result["evidence_anchor_artifact_id"].startswith("sha256:")
    assert result["coverage_count"] == 10
    coverage = {item["subject"]: item["status"] for item in workspace.list_coverage(result["run_id"])}
    assert coverage["Unity asset decoding"] == "unsupported"
    assert coverage["Game runtime behavior"] == "unsupported"
    assert not any(Path(item["relative_path"]).is_absolute() for item in result["files"])
    assert not (game.parent / "icon.png").exists()


def test_steam_appmanifest_path_derives_only_safe_install_directory(tmp_path: Path):
    workspace, game, manifest = _steam_fixture(tmp_path)
    result = inspect_steam_workspace(workspace, manifest)
    assert result["game_directory"] == "Example Game"
    assert result["inventory"]["file_count"] == 5

    manifest.write_text('"AppState" { "appid" "1" "installdir" "../outside" }', encoding="utf-8")
    with pytest.raises(AereError) as exc:
        inspect_steam_workspace(workspace, manifest)
    assert exc.value.code == "steam_install_dir_invalid"


def test_steam_manifest_metadata_redacts_secret_like_values(tmp_path: Path):
    workspace, game, manifest = _steam_fixture(tmp_path)
    manifest.write_text('"AppState" { "appid" "12345" "name" "api_key=STEAM_SECRET" "installdir" "Example Game" "buildid" "987654" }', encoding="utf-8")
    result = inspect_steam_workspace(workspace, game)
    assert "STEAM_SECRET" not in str(result)
    assert "[REDACTED]" in result["steam_manifest"]["name"]


def test_steam_directory_without_manifest_is_reported_without_false_evidence_run(tmp_path: Path):

    root = tmp_path / "approved"
    game = root / "LooseGame"
    game.mkdir(parents=True)
    (game / "readme.txt").write_text("game", encoding="utf-8")
    workspace = Workspace(tmp_path / "workspace")
    workspace.allow_root(root)
    result = inspect_steam_workspace(workspace, game)
    assert result["steam_manifest"]["status"] == "not_found"
    assert result["run_id"] is None
    assert result["evidence_note"].startswith("No matching Steam appmanifest")


def test_steam_target_must_be_under_an_approved_root(tmp_path: Path):
    workspace, game, _ = _steam_fixture(tmp_path)
    other = tmp_path / "outside"
    other.mkdir()
    with pytest.raises(AereError) as exc:
        inspect_steam_workspace(workspace, other)
    assert exc.value.code == "outside_allowed_roots"


def test_steam_offline_report_contains_preview_and_relative_paths_only(tmp_path: Path):
    workspace, game, _ = _steam_fixture(tmp_path)
    result = inspect_steam_workspace(workspace, game, include_previews=True)
    data = steam_report_sections(result)
    report = render_offline_html(data)
    assert "Offline report" in report
    assert "data:image/png;base64," in report
    assert str(tmp_path) not in report
    assert "pak01_dir.vpk" in report
    assert "https://" not in report
