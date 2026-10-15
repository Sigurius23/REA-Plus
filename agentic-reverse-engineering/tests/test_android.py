from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from aere.android import parse_android_manifest, parse_dex
from aere.analysis import inspect_android_workspace
from aere.core import AereError, Workspace
from aere.visualization import render_offline_html
from aere.android import android_report_sections


def _pool(strings: list[str]) -> bytes:
    encoded = []
    for text in strings:
        raw = text.encode("utf-8")
        encoded.append(bytes([len(text), len(raw)]) + raw + b"\x00")
    strings_start = 28 + 4 * len(strings)
    offsets = []
    cursor = 0
    for item in encoded:
        offsets.append(cursor)
        cursor += len(item)
    chunk_size = strings_start + cursor
    header = struct.pack("<HHIIIIII", 0x0001, 28, chunk_size, len(strings), 0, 0x100, strings_start, 0)
    return header + b"".join(struct.pack("<I", item) for item in offsets) + b"".join(encoded)


def _start(tag_index: int, attrs: list[tuple[int, str | int, int]]) -> bytes:
    # attrs: (name string index, value string index or integer, value type)
    size = 16 + 20 + 20 * len(attrs)
    header = struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF)
    ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, tag_index, 20, 20, len(attrs), 0, 0, 0)
    encoded_attrs = []
    for name_index, value, value_type in attrs:
        if value_type == 0x03:
            raw_index = int(value)
            value_data = int(value)
        else:
            raw_index = 0xFFFFFFFF
            value_data = int(value)
        encoded_attrs.append(struct.pack("<IIIHBBI", 0xFFFFFFFF, name_index, raw_index, 8, 0, value_type, value_data))
    return header + ext + b"".join(encoded_attrs)


def _binary_manifest() -> bytes:
    strings = [
        "manifest", "package", "versionName", "com.example.game", "1.2.3",
        "uses-sdk", "minSdkVersion", "targetSdkVersion", "uses-permission", "name",
        "android.permission.INTERNET", "application", "label", "Game label",
        "activity", "MainActivity", "exported",
    ]
    chunks = [
        _pool(strings),
        _start(0, [(1, 3, 0x03), (2, 4, 0x03)]),
        _start(5, [(6, 23, 0x10), (7, 34, 0x10)]),
        _start(8, [(9, 10, 0x03)]),
        _start(11, [(12, 13, 0x03)]),
        _start(14, [(9, 15, 0x03), (16, 1, 0x12)]),
    ]
    body = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _dex() -> bytes:
    strings = ["Lcom/example/MainActivity;", "onCreate", "Ljava/lang/Object;"]
    string_ids_off = 112
    type_ids_off = string_ids_off + len(strings) * 4
    method_ids_off = type_ids_off + 4
    class_defs_off = method_ids_off + 8
    data_off = class_defs_off + 32
    payload = bytearray(b"\x00" * data_off)
    string_offsets = []
    for value in strings:
        string_offsets.append(len(payload))
        encoded = value.encode("utf-8")
        payload.extend(_uleb(len(value)) + encoded + b"\x00")
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", payload, string_ids_off + i * 4, offset)
    struct.pack_into("<I", payload, type_ids_off, 0)
    struct.pack_into("<HHI", payload, method_ids_off, 0, 0, 1)
    struct.pack_into("<I", payload, class_defs_off, 0)
    payload[:8] = b"dex\n035\x00"
    struct.pack_into("<I", payload, 32, len(payload))
    struct.pack_into("<I", payload, 36, 112)
    struct.pack_into("<I", payload, 40, 0x12345678)
    struct.pack_into("<II", payload, 56, len(strings), string_ids_off)
    struct.pack_into("<II", payload, 64, 1, type_ids_off)
    struct.pack_into("<II", payload, 88, 1, method_ids_off)
    struct.pack_into("<II", payload, 96, 1, class_defs_off)
    return bytes(payload)


def _sandbox(tmp_path: Path) -> tuple[Workspace, Path]:
    root = tmp_path / "inputs"
    root.mkdir()
    workspace = Workspace(tmp_path / "workspace")
    workspace.allow_root(root)
    return workspace, root


def _apk(path: Path, manifest: bytes | None = None) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", manifest if manifest is not None else _binary_manifest())
        archive.writestr("classes.dex", _dex())
        archive.writestr("assets/splash.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
        archive.writestr("lib/arm64-v8a/libil2cpp.so", b"native-marker")


def test_binary_android_manifest_decodes_package_sdk_permission_and_component():
    result = parse_android_manifest(_binary_manifest())
    assert result["status"] == "parsed"
    assert result["format"] == "android_binary_xml"
    assert result["package"] == "com.example.game"
    assert result["version_name"] == "1.2.3"
    assert result["min_sdk_version"] == 23
    assert result["target_sdk_version"] == 34
    assert result["permissions"] == ["android.permission.INTERNET"]
    assert result["components"][0]["name"] == "MainActivity"


def test_text_manifest_is_parsed_without_resolving_resources():
    xml = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example"><uses-sdk android:minSdkVersion="21"/><uses-permission android:name="android.permission.CAMERA"/><application android:label="@string/title"/></manifest>'''
    result = parse_android_manifest(xml)
    assert result["status"] == "parsed"
    assert result["format"] == "text_xml"
    assert result["package"] == "org.example"
    assert result["min_sdk_version"] == "21"
    assert result["application_label"] == "@string/title"


def test_manifest_entity_declarations_are_rejected():
    result = parse_android_manifest(b'<!DOCTYPE x [<!ENTITY a "boom">]><manifest package="x"/>')
    assert result["status"] == "invalid"
    assert "entity" in result["error"].lower() or "doctype" in result["error"].lower()


def test_dex_identifier_tables_are_read_without_decompiling():
    result = parse_dex(_dex())
    assert result["status"] == "parsed"
    assert result["dex_version"] == "035"
    assert result["classes"] == ["Lcom/example/MainActivity;"]
    assert result["methods"] == [{"owner": "Lcom/example/MainActivity;", "name": "onCreate"}]
    assert any("not a decompilation" in item.lower() for item in result["limitations"])


def test_dex_invalid_table_ranges_fail_closed():
    data = bytearray(_dex())
    struct.pack_into("<I", data, 60, len(data) + 100)
    result = parse_dex(bytes(data))
    assert result["status"] == "invalid"
    assert "outside" in result["error"] or "range" in result["error"]


def test_apk_workspace_inspection_records_evidence_and_optional_preview(tmp_path: Path):
    workspace, root = _sandbox(tmp_path)
    path = root / "game.apk"
    _apk(path)
    artifact = workspace.import_file(path)

    result = inspect_android_workspace(workspace, artifact["artifact_id"], include_previews=True)

    assert result["manifest"]["package"] == "com.example.game"
    assert result["dex_files"][0]["classes"] == ["Lcom/example/MainActivity;"]
    assert result["engine_candidates"][0]["engine"] == "Unity"
    assert result["previews"][0]["mime_type"] == "image/png"
    assert result["previews"][0]["data_uri"].startswith("data:image/png;base64,")
    assert result["evidence_count"] >= 4
    assert result["coverage_count"] == 8
    coverage = {item["subject"]: item["status"] for item in workspace.list_coverage(result["run_id"])}
    assert coverage["Android manifest declaration parse"] == "complete"
    assert coverage["DEX identifier-table scan"] == "complete"
    assert coverage["Raster image previews"] == "complete"
    assert coverage["Android DEX decompilation"] == "unsupported"
    assert coverage["Android resource and Smali decoding"] == "unsupported"
    assert not (root / "AndroidManifest.xml").exists()


def test_apk_member_expansion_ratio_is_bounded(tmp_path: Path):
    workspace, root = _sandbox(tmp_path)
    path = root / "compressed.apk"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("AndroidManifest.xml", b'<manifest package="' + b"A" * 20_000 + b'"/>')
    artifact = workspace.import_file(path)
    result = inspect_android_workspace(workspace, artifact["artifact_id"])
    assert result["manifest"]["status"] == "unreadable"
    assert "ratio" in result["manifest"]["error"].lower()


def test_android_domain_results_redact_secret_like_member_names(tmp_path: Path):
    workspace, root = _sandbox(tmp_path)
    path = root / "redact.apk"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b'<manifest package="org.example"/>')
        archive.writestr("assets/api_key=APK_SECRET.png", b"not-an-image")
    artifact = workspace.import_file(path)
    result = inspect_android_workspace(workspace, artifact["artifact_id"])
    assert "APK_SECRET" not in str(result)


def test_android_inspector_rejects_a_registered_non_apk(tmp_path: Path):


    workspace, root = _sandbox(tmp_path)
    path = root / "archive.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("readme.txt", "not an APK")
    artifact = workspace.import_file(path)
    with pytest.raises(AereError) as exc:
        inspect_android_workspace(workspace, artifact["artifact_id"])
    assert exc.value.code == "unsupported_android_artifact"


def test_android_inspection_is_bound_to_registered_hash(tmp_path: Path):
    workspace, root = _sandbox(tmp_path)
    path = root / "game.apk"
    _apk(path)
    artifact = workspace.import_file(path)
    path.write_bytes(b"changed")
    with pytest.raises(AereError) as exc:
        inspect_android_workspace(workspace, artifact["artifact_id"])
    assert exc.value.code == "artifact_changed"


def test_android_offline_report_is_self_contained_and_escaped(tmp_path: Path):
    workspace, root = _sandbox(tmp_path)
    path = root / "game.apk"
    _apk(path)
    artifact = workspace.import_file(path)
    result = inspect_android_workspace(workspace, artifact["artifact_id"], include_previews=True)
    report = android_report_sections(result)
    report["title"] = "<script>alert(1)</script>"
    html = render_offline_html(report)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "data:image/png;base64," in html
    assert "https://" not in html
    assert "Content-Security-Policy" in html
