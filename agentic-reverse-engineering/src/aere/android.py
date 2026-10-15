"""Bounded, read-only Android APK structure analysis.

This module parses only package metadata that can be read without executing the
package: Android binary/text manifests, DEX identifier tables, ZIP metadata,
and a small set of browser-previewable raster assets. It does not decompile
methods, resolve resources, extract files to disk, or inspect a device.
"""

from __future__ import annotations

import base64
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from .core import AereError, _regular_open

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_MANIFEST_MAX = 2 * 1024 * 1024
_DEX_MAX = 32 * 1024 * 1024
_PREVIEW_MEMBER_MAX = 768 * 1024
_PREVIEW_TOTAL_MAX = 8 * 1024 * 1024
_PREVIEW_COUNT_MAX = 24
_MAX_IDENTIFIERS = 100_000
_MAX_SAMPLES = 100
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


class _ParseFailure(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise _ParseFailure("truncated 16-bit field")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise _ParseFailure("truncated 32-bit field")
    return struct.unpack_from("<I", data, offset)[0]


def _range(data: bytes, offset: int, count: int, width: int, label: str) -> None:
    if offset < 0 or count < 0 or width < 0 or count > (len(data) - offset) // max(width, 1):
        raise _ParseFailure(f"{label} range is outside the bounded input")


def _len8(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise _ParseFailure("truncated UTF-8 string length")
    first = data[offset]
    if first & 0x80:
        if offset + 1 >= len(data):
            raise _ParseFailure("truncated extended UTF-8 string length")
        return (((first & 0x7F) << 8) | data[offset + 1], offset + 2)
    return first, offset + 1


def _len16(data: bytes, offset: int) -> tuple[int, int]:
    first = _u16(data, offset)
    if first & 0x8000:
        second = _u16(data, offset + 2)
        return (((first & 0x7FFF) << 16) | second, offset + 4)
    return first, offset + 2


def _parse_string_pool(data: bytes, offset: int, chunk_size: int, header_size: int) -> list[str]:
    if header_size < 28 or chunk_size < header_size or offset + chunk_size > len(data):
        raise _ParseFailure("invalid string-pool chunk bounds")
    string_count = _u32(data, offset + 8)
    style_count = _u32(data, offset + 12)
    flags = _u32(data, offset + 16)
    strings_start = _u32(data, offset + 20)
    if string_count > _MAX_IDENTIFIERS or style_count > _MAX_IDENTIFIERS:
        raise _ParseFailure("string-pool count exceeds the configured parser bound")
    arrays_start = offset + header_size
    _range(data, arrays_start, string_count + style_count, 4, "string/style offset array")
    strings_base = offset + strings_start
    if strings_start > chunk_size:
        raise _ParseFailure("string-pool data starts outside its chunk")
    utf8 = bool(flags & 0x100)
    values: list[str] = []
    for index in range(string_count):
        item_offset = _u32(data, arrays_start + index * 4)
        cursor = strings_base + item_offset
        chunk_end = offset + chunk_size
        if cursor < strings_base or cursor >= chunk_end:
            raise _ParseFailure("string-pool entry points outside its chunk")
        if utf8:
            _, cursor = _len8(data, cursor)  # UTF-16 code-unit length
            byte_length, cursor = _len8(data, cursor)
            end = cursor + byte_length
            if end >= chunk_end or data[end] != 0:
                raise _ParseFailure("UTF-8 string-pool entry is truncated or unterminated")
            values.append(data[cursor:end].decode("utf-8", errors="replace"))
        else:
            code_units, cursor = _len16(data, cursor)
            byte_length = code_units * 2
            end = cursor + byte_length
            if end + 2 > chunk_end or data[end : end + 2] != b"\x00\x00":
                raise _ParseFailure("UTF-16 string-pool entry is truncated or unterminated")
            values.append(data[cursor:end].decode("utf-16le", errors="replace"))
    return values


def _string(strings: list[str], index: int) -> str | None:
    return strings[index] if 0 <= index < len(strings) else None


def _parse_binary_manifest(data: bytes) -> list[tuple[str, dict[str, Any], int]]:
    if len(data) < 8 or _u16(data, 0) != 0x0003:
        raise _ParseFailure("not Android binary XML")
    root_header_size = _u16(data, 2)
    root_size = _u32(data, 4)
    if root_header_size < 8 or root_size < root_header_size or root_size > len(data):
        raise _ParseFailure("invalid Android XML root chunk bounds")

    chunks: list[tuple[int, int, int]] = []
    cursor = root_header_size
    while cursor < root_size:
        if cursor + 8 > root_size:
            raise _ParseFailure("truncated Android XML child chunk")
        chunk_type = _u16(data, cursor)
        header_size = _u16(data, cursor + 2)
        chunk_size = _u32(data, cursor + 4)
        if header_size < 8 or chunk_size < header_size or cursor + chunk_size > root_size:
            raise _ParseFailure("invalid Android XML child chunk bounds")
        chunks.append((chunk_type, cursor, chunk_size))
        if len(chunks) > 100_000:
            raise _ParseFailure("Android XML chunk count exceeds parser bounds")
        cursor += chunk_size
    if cursor != root_size:
        raise _ParseFailure("Android XML chunks do not end at the declared boundary")

    pools = [item for item in chunks if item[0] == 0x0001]
    if not pools:
        raise _ParseFailure("Android XML string pool is missing")
    _, pool_offset, pool_size = pools[0]
    strings = _parse_string_pool(data, pool_offset, pool_size, _u16(data, pool_offset + 2))

    records: list[tuple[str, dict[str, Any], int]] = []
    for chunk_type, chunk_offset, chunk_size in chunks:
        if chunk_type != 0x0102:  # RES_XML_START_ELEMENT_TYPE
            continue
        node_header = _u16(data, chunk_offset + 2)
        if node_header < 16 or chunk_size < node_header + 20:
            raise _ParseFailure("invalid start-element chunk")
        line = _u32(data, chunk_offset + 8)
        ext = chunk_offset + node_header
        tag_name = _string(strings, _u32(data, ext + 4))
        attribute_start = _u16(data, ext + 8)
        attribute_size = _u16(data, ext + 10)
        attribute_count = _u16(data, ext + 12)
        if not tag_name:
            raise _ParseFailure("start-element tag name is invalid")
        if attribute_size < 20 or attribute_count > 4096:
            raise _ParseFailure("Android XML attribute dimensions exceed parser bounds")
        first_attribute = ext + attribute_start
        if first_attribute < ext or first_attribute + attribute_count * attribute_size > chunk_offset + chunk_size:
            raise _ParseFailure("Android XML attributes exceed their chunk")
        attrs: dict[str, Any] = {}
        for index in range(attribute_count):
            pos = first_attribute + index * attribute_size
            attr_name = _string(strings, _u32(data, pos + 4))
            raw_index = _u32(data, pos + 8)
            value_size = _u16(data, pos + 12)
            value_type = data[pos + 15]
            value_data = _u32(data, pos + 16)
            if not attr_name or value_size < 8:
                continue
            if value_type == 0x03:
                value: Any = _string(strings, value_data)
            elif value_type == 0x12:
                value = bool(value_data)
            elif value_type == 0x10:
                value = value_data if value_data < 0x80000000 else value_data - 0x100000000
            elif value_type == 0x11:
                value = f"0x{value_data:08x}"
            elif value_type == 0x01:
                value = f"@0x{value_data:08x}"
            elif raw_index != 0xFFFFFFFF:
                value = _string(strings, raw_index)
            else:
                value = value_data
            attrs[attr_name] = value
        records.append((tag_name, attrs, line))
        if len(records) > 50_000:
            raise _ParseFailure("Android XML element count exceeds parser bounds")
    return records


def _parse_text_manifest(data: bytes) -> list[tuple[str, dict[str, Any], int]]:
    # Reject DTD/entity declarations before invoking the standard-library XML parser.
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise _ParseFailure("DOCTYPE and entity declarations are not accepted")
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(data)
    except Exception as exc:
        raise _ParseFailure(f"text XML could not be parsed ({type(exc).__name__})") from exc
    records: list[tuple[str, dict[str, Any], int]] = []
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1]
        attrs = {key.rsplit("}", 1)[-1]: value for key, value in elem.attrib.items()}
        records.append((tag, attrs, 0))
        if len(records) > 50_000:
            raise _ParseFailure("Android XML element count exceeds parser bounds")
    return records


def _bounded_text(value: Any, limit: int = 512) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def _manifest_summary(records: list[tuple[str, dict[str, Any], int]], source_format: str) -> dict[str, Any]:
    root = next(((tag, attrs) for tag, attrs, _ in records if tag == "manifest"), None)
    if root is None:
        raise _ParseFailure("manifest root element is missing")
    _, root_attrs = root
    permissions: list[str] = []
    components: list[dict[str, Any]] = []
    component_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
    permission_tags = {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
    for tag, attrs, line in records:
        if tag in permission_tags:
            name = attrs.get("name")
            if isinstance(name, str) and name:
                permissions.append(name)
        if tag in component_tags:
            name = attrs.get("name")
            if isinstance(name, str) and name:
                components.append({
                    "type": tag,
                    "name": name,
                    "exported": attrs.get("exported"),
                    "enabled": attrs.get("enabled"),
                    "line": line or None,
                })
    uses_sdk = next((attrs for tag, attrs, _ in records if tag == "uses-sdk"), {})
    app = next((attrs for tag, attrs, _ in records if tag == "application"), {})
    return {
        "status": "parsed",
        "format": source_format,
        "package": _bounded_text(root_attrs.get("package")),
        "version_code": _bounded_text(root_attrs.get("versionCode")),
        "version_code_major": _bounded_text(root_attrs.get("versionCodeMajor")),
        "version_name": _bounded_text(root_attrs.get("versionName")),
        "compile_sdk_version": _bounded_text(root_attrs.get("compileSdkVersion")),
        "min_sdk_version": _bounded_text(uses_sdk.get("minSdkVersion")),
        "target_sdk_version": _bounded_text(uses_sdk.get("targetSdkVersion")),
        "application_label": _bounded_text(app.get("label")),
        "application_debuggable": app.get("debuggable"),
        "permissions": [_bounded_text(item) for item in sorted(set(permissions))[:1000]],
        "permission_count": len(set(permissions)),
        "permissions_truncated": len(set(permissions)) > 1000,
        "components": [
            {**component, "name": _bounded_text(component.get("name")), "line": component.get("line")}
            for component in components[:1000]
        ],
        "component_count": len(components),
        "components_truncated": len(components) > 1000,
        "elements_examined": len(records),
        "limitations": [
            "Resource references are not resolved; labels and version fields may remain @resource IDs.",
            "Component declarations are static manifest facts, not proof of runtime reachability or exploitability.",
        ],
    }


def parse_android_manifest(data: bytes) -> dict[str, Any]:
    if not data:
        return {"status": "invalid", "format": "unknown", "error": "manifest is empty"}
    if len(data) > _MANIFEST_MAX:
        return {"status": "limited", "format": "unknown", "error": "manifest exceeds the 2 MiB parse limit"}
    try:
        if data.lstrip().startswith(b"<"):
            records = _parse_text_manifest(data)
            source_format = "text_xml"
        else:
            records = _parse_binary_manifest(data)
            source_format = "android_binary_xml"
        return _manifest_summary(records, source_format)
    except _ParseFailure as exc:
        return {"status": "invalid", "format": "android_binary_xml" if not data.lstrip().startswith(b"<") else "text_xml", "error": exc.message}


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise _ParseFailure("truncated DEX ULEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, offset
        shift += 7
    raise _ParseFailure("DEX ULEB128 value is too long")


def _dex_string(data: bytes, offset: int) -> str:
    _, cursor = _uleb128(data, offset)  # UTF-16 code-unit count
    end = data.find(b"\x00", cursor)
    if end < 0 or end - cursor > 1_000_000:
        raise _ParseFailure("DEX string data is unterminated or exceeds the bounded length")
    # DEX uses modified UTF-8. Identifiers are normally standard UTF-8; preserve
    # undecodable modified sequences with replacement rather than interpreting code.
    return data[cursor:end].decode("utf-8", errors="replace")


def _dex_display(value: str) -> str:
    return value if len(value) <= 256 else value[:256] + "…"


def parse_dex(data: bytes, sample_limit: int = _MAX_SAMPLES) -> dict[str, Any]:
    if len(data) < 112 or not re.match(rb"^dex\n[0-9]{3}\x00", data[:8]):
        return {"status": "invalid", "error": "DEX magic/header is missing or truncated"}
    try:
        file_size = _u32(data, 32)
        header_size = _u32(data, 36)
        endian_tag = _u32(data, 40)
        if header_size != 112 or file_size < 112 or file_size > len(data):
            raise _ParseFailure("DEX header size or declared file size is invalid")
        if endian_tag != 0x12345678:
            raise _ParseFailure("reverse-endian DEX is not supported by this parser")
        data = data[:file_size]
        string_count, string_off = _u32(data, 56), _u32(data, 60)
        type_count, type_off = _u32(data, 64), _u32(data, 68)
        method_count, method_off = _u32(data, 88), _u32(data, 92)
        class_count, class_off = _u32(data, 96), _u32(data, 100)
        for count, offset, width, label in (
            (string_count, string_off, 4, "string_ids"),
            (type_count, type_off, 4, "type_ids"),
            (method_count, method_off, 8, "method_ids"),
            (class_count, class_off, 32, "class_defs"),
        ):
            if count > _MAX_IDENTIFIERS:
                raise _ParseFailure(f"{label} count exceeds parser bounds")
            _range(data, offset, count, width, label)

        strings: list[str] = []
        for i in range(string_count):
            item_offset = _u32(data, string_off + i * 4)
            if item_offset >= file_size:
                raise _ParseFailure("DEX string data offset is outside the file")
            strings.append(_dex_string(data, item_offset))

        type_descriptors: list[str] = []
        for i in range(type_count):
            string_idx = _u32(data, type_off + i * 4)
            if string_idx >= len(strings):
                raise _ParseFailure("DEX type descriptor index is outside string_ids")
            type_descriptors.append(strings[string_idx])

        classes: list[str] = []
        identifiers_truncated = False
        for i in range(class_count):
            class_idx = _u32(data, class_off + i * 32)
            if class_idx >= len(type_descriptors):
                raise _ParseFailure("DEX class index is outside type_ids")
            if i < sample_limit:
                identifiers_truncated = identifiers_truncated or len(type_descriptors[class_idx]) > 256
                classes.append(_dex_display(type_descriptors[class_idx]))

        methods: list[dict[str, str]] = []
        for i in range(method_count):
            pos = method_off + i * 8
            class_idx, _proto_idx, name_idx = struct.unpack_from("<HHI", data, pos)
            if class_idx >= len(type_descriptors) or name_idx >= len(strings):
                raise _ParseFailure("DEX method identifier references an invalid index")
            if i < sample_limit:
                identifiers_truncated = identifiers_truncated or len(type_descriptors[class_idx]) > 256 or len(strings[name_idx]) > 256
                methods.append({"owner": _dex_display(type_descriptors[class_idx]), "name": _dex_display(strings[name_idx])})

        version = data[4:7].decode("ascii", errors="replace")
        return {
            "status": "parsed",
            "dex_version": version,
            "declared_file_size": file_size,
            "string_id_count": string_count,
            "type_id_count": type_count,
            "class_definition_count": class_count,
            "method_id_count": method_count,
            "classes": classes[:sample_limit],
            "methods": methods[:sample_limit],
            "classes_truncated": class_count > sample_limit,
            "methods_truncated": method_count > sample_limit,
            "identifiers_truncated": identifiers_truncated,
            "limitations": [
                "Only DEX identifier tables were parsed; this is not a decompilation, and code items, instructions, control flow, annotations, and call graphs were not analyzed.",
                "Method IDs may include referenced methods and are not limited to methods implemented by this DEX.",
                "Names are DEX descriptors/identifiers, not reconstructed source code; sampled names longer than 256 characters are abbreviated.",
            ],
        }
    except _ParseFailure as exc:
        return {"status": "invalid", "error": exc.message}


def image_mime(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"BM"):
        return "image/bmp"
    return None


def _read_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, max_bytes: int) -> bytes:
    if info.flag_bits & 0x1:
        raise _ParseFailure("encrypted ZIP members are not read")
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        raise _ParseFailure("ZIP compression method is not in the supported bounded set")
    if info.file_size < 0 or info.file_size > max_bytes:
        raise _ParseFailure("member exceeds the configured uncompressed-byte limit")
    if info.file_size and info.compress_size == 0:
        raise _ParseFailure("member has an invalid zero compressed size")
    if info.compress_size and info.file_size / info.compress_size > 250:
        raise _ParseFailure("member compression ratio exceeds the configured limit")
    try:
        with archive.open(info, "r") as member:
            raw = member.read(max_bytes + 1)
    except Exception as exc:
        raise _ParseFailure(f"ZIP member could not be read ({type(exc).__name__})") from exc
    if len(raw) > max_bytes or len(raw) != info.file_size:
        raise _ParseFailure("member output did not match its bounded declared size")
    return raw


def inspect_apk(
    path: Path,
    archive_metadata: dict[str, Any],
    limits: dict[str, int],
    include_previews: bool = False,
) -> dict[str, Any]:
    """Inspect an already-registered APK without writing extracted files."""
    metadata_members = archive_metadata.get("members", [])
    member_count = int(archive_metadata.get("member_count", 0))
    directory_limited = bool(archive_metadata.get("directory_bytes_limited"))
    member_limit = int(limits["max_archive_members"])
    archive_status = "partial" if directory_limited or member_count > member_limit or archive_metadata.get("truncated") else "complete"
    result: dict[str, Any] = {
        "kind": "android_apk",
        "analysis_version": "0.2.0",
        "archive": {
            "member_count": member_count,
            "members_examined": len(metadata_members),
            "status": archive_status,
            "directory_bytes": archive_metadata.get("directory_bytes"),
            "directory_bytes_limited": directory_limited,
            "unsafe_member_count_in_sample": archive_metadata.get("unsafe_member_count_in_sample", 0),
        },
        "manifest": {"status": "unknown", "error": "AndroidManifest.xml was not examined"},
        "dex_files": [],
        "image_assets": [],
        "previews": [],
        "engine_candidates": [],
        "limitations": [
            "This is bounded static structure analysis. The APK was not executed, modified, or extracted to disk.",
            "No JADX/Apktool decompilation, resource-table resolution, signature verification, device access, or runtime instrumentation is included.",
        ],
    }
    if archive_status == "partial":
        result["limitations"].append("ZIP member examination is partial because a configured member/directory/sample limit was reached.")

    if member_count > member_limit or directory_limited:
        result["manifest"] = {"status": "not_attempted", "error": "archive structure exceeds the configured inspection bound"}
        result["dex_status"] = "not_attempted"
        result["asset_preview_status"] = "not_attempted"
        return result

    by_name: dict[str, list[dict[str, Any]]] = {}
    for member in metadata_members:
        name = str(member.get("name", ""))
        by_name.setdefault(name, []).append(member)

    try:
        source, _ = _regular_open(path)
        with source, zipfile.ZipFile(source, "r") as archive:
            infos_by_name: dict[str, list[zipfile.ZipInfo]] = {}
            for info in archive.infolist():
                infos_by_name.setdefault(info.filename, []).append(info)
            manifest_entries = by_name.get("AndroidManifest.xml", [])
            manifest_infos = infos_by_name.get("AndroidManifest.xml", [])
            if len(manifest_entries) == 1 and len(manifest_infos) == 1 and not manifest_entries[0].get("unsafe_path"):
                try:
                    manifest_raw = _read_zip_member(archive, manifest_infos[0], min(_MANIFEST_MAX, int(limits["max_file_bytes"])))
                    result["manifest"] = parse_android_manifest(manifest_raw)
                    result["manifest"]["member"] = "AndroidManifest.xml"
                    result["manifest"]["member_size"] = len(manifest_raw)
                except _ParseFailure as exc:
                    result["manifest"] = {"status": "unreadable", "format": "unknown", "error": exc.message}
            elif len(manifest_entries) > 1 or len(manifest_infos) > 1:
                result["manifest"] = {"status": "ambiguous", "error": "multiple AndroidManifest.xml entries were found"}
            else:
                result["manifest"] = {"status": "missing", "error": "AndroidManifest.xml was not found in the bounded member listing"}

            dex_names = sorted(
                (name for name in by_name if re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", name, flags=re.IGNORECASE)),
                key=lambda item: item.casefold(),
            )
            dex_total = len(dex_names)
            for name in dex_names[:64]:
                candidates = infos_by_name.get(name, [])
                meta_candidates = by_name.get(name, [])
                item: dict[str, Any] = {"name": name, "size": meta_candidates[0].get("size") if meta_candidates else None}
                if len(candidates) != 1 or len(meta_candidates) != 1 or meta_candidates[0].get("unsafe_path"):
                    item.update({"status": "ambiguous", "error": "DEX entry is duplicated or unsafe"})
                else:
                    try:
                        raw = _read_zip_member(archive, candidates[0], min(_DEX_MAX, int(limits["max_file_bytes"])))
                        parsed = parse_dex(raw)
                        item.update(parsed)
                    except _ParseFailure as exc:
                        item.update({"status": "limited_or_unreadable", "error": exc.message})
                result["dex_files"].append(item)
            if dex_total > 64:
                result["dex_status"] = "partial"
            elif all(item.get("status") == "parsed" for item in result["dex_files"]):
                result["dex_status"] = "complete" if dex_total else "complete"
            elif not dex_names:
                result["dex_status"] = "complete"
            else:
                result["dex_status"] = "partial"
            result["dex_file_count"] = dex_total

            ext_counts: dict[str, int] = {}
            image_candidates: list[dict[str, Any]] = []
            candidate_names: list[str] = []
            for member in metadata_members:
                if member.get("unsafe_path"):
                    continue
                name = str(member.get("name", ""))
                lower = name.casefold()
                suffix = Path(lower).suffix
                if suffix:
                    ext_counts[suffix] = ext_counts.get(suffix, 0) + 1
                if suffix in _IMAGE_EXTENSIONS and not member.get("unsafe_path"):
                    image_candidates.append({"name": name, "size": member.get("size"), "compressed_size": member.get("compressed_size"), "extension": suffix})
                if lower.endswith(("/globalgamemanagers", "globalgamemanagers", "/gameassembly.dll", "gameassembly.dll", "/libil2cpp.so", "libil2cpp.so", "unityplayer.so", "unityplayer.dll")) or "/managed/assembly-csharp.dll" in lower:
                    candidate_names.append(name)
                if lower.endswith((".pak", ".utoc", ".ucas")) or "/libue4.so" in lower:
                    candidate_names.append(name)
                if lower.endswith(".pck") or lower.endswith("project.godot"):
                    candidate_names.append(name)
            result["asset_extension_counts"] = dict(sorted(ext_counts.items(), key=lambda item: (-item[1], item[0]))[:100])
            result["image_assets"] = image_candidates[:500]
            result["image_asset_count"] = len(image_candidates)
            result["image_assets_truncated"] = len(image_candidates) > 500

            has_unity = any("globalgamemanagers" in name.casefold() or "gameassembly.dll" in name.casefold() or "libil2cpp.so" in name.casefold() for name in candidate_names)
            has_unreal = any(name.casefold().endswith((".pak", ".utoc", ".ucas")) or "libue4.so" in name.casefold() for name in candidate_names)
            has_godot = any(name.casefold().endswith((".pck", "project.godot")) for name in candidate_names)
            result["engine_candidates"] = [
                {"engine": engine, "status": "candidate", "supporting_members": sorted(set(names))[:20], "limitation": "File markers suggest a candidate only; no engine build/runtime compatibility is established."}
                for engine, names, enabled in (
                    ("Unity", candidate_names, has_unity),
                    ("Unreal Engine", candidate_names, has_unreal),
                    ("Godot", candidate_names, has_godot),
                ) if enabled
            ]

            preview_status = "not_requested"
            if include_previews:
                preview_status = "complete"
                preview_bytes = 0
                for candidate in image_candidates[:_PREVIEW_COUNT_MAX]:
                    name = candidate["name"]
                    infos = infos_by_name.get(name, [])
                    meta_items = by_name.get(name, [])
                    if len(infos) != 1 or len(meta_items) != 1:
                        continue
                    declared_size = int(candidate.get("size") or 0)
                    if declared_size > _PREVIEW_MEMBER_MAX or preview_bytes + declared_size > _PREVIEW_TOTAL_MAX:
                        preview_status = "partial"
                        continue
                    try:
                        raw = _read_zip_member(archive, infos[0], _PREVIEW_MEMBER_MAX)
                        mime = image_mime(raw)
                        if not mime:
                            continue
                        encoded = base64.b64encode(raw).decode("ascii")
                        result["previews"].append({
                            "name": name,
                            "size": len(raw),
                            "mime_type": mime,
                            "data_uri": f"data:{mime};base64,{encoded}",
                        })
                        preview_bytes += len(raw)
                    except _ParseFailure:
                        preview_status = "partial"
                if len(image_candidates) > _PREVIEW_COUNT_MAX:
                    preview_status = "partial"
            result["asset_preview_status"] = preview_status
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, RuntimeError, ValueError, NotImplementedError, struct.error) as exc:
        raise AereError("apk_read_failed", "Could not read bounded APK entries.", {"reason": type(exc).__name__}) from exc

    return result


def android_report_sections(result: dict[str, Any]) -> dict[str, Any]:
    manifest = result.get("manifest", {})
    package_rows = [
        ("Package", manifest.get("package")),
        ("Version name", manifest.get("version_name")),
        ("Version code", manifest.get("version_code")),
        ("Minimum SDK", manifest.get("min_sdk_version")),
        ("Target SDK", manifest.get("target_sdk_version")),
        ("Application label", manifest.get("application_label")),
        ("Manifest status", manifest.get("status")),
    ]
    dex_rows = []
    for dex in result.get("dex_files", []):
        dex_rows.append({
            "file": dex.get("name"),
            "status": dex.get("status"),
            "version": dex.get("dex_version"),
            "classes": dex.get("class_definition_count"),
            "method_ids": dex.get("method_id_count"),
            "class_sample": ", ".join(dex.get("classes", [])[:8]),
        })
    permission_rows = [{"permission": item} for item in manifest.get("permissions", [])]
    component_rows = manifest.get("components", [])
    asset_rows = result.get("image_assets", [])
    return {
        "title": manifest.get("application_label") or manifest.get("package") or "Android package",
        "subtitle": "Bounded static APK structure report; source bytes stay local and no files are extracted to disk.",
        "summary": [
            {"label": "ZIP members", "value": result.get("archive", {}).get("member_count", 0)},
            {"label": "DEX files", "value": result.get("dex_file_count", 0)},
            {"label": "Permissions", "value": manifest.get("permission_count", 0)},
            {"label": "Image entries", "value": result.get("image_asset_count", 0)},
        ],
        "sections": [
            {"title": "Package", "rows": [{"field": label, "value": value if value is not None else "—"} for label, value in package_rows]},
            {"title": "DEX identifier tables", "rows": dex_rows, "empty": "No DEX entries found or parseable."},
            {"title": "Permissions", "rows": permission_rows, "empty": "No permission declarations parsed."},
            {"title": "Manifest components", "rows": component_rows, "empty": "No activity/service/receiver/provider declarations parsed."},
            {"title": "Image assets", "rows": asset_rows, "empty": "No previewable image entries found."},
        ],
        "previews": result.get("previews", []),
        "engine_candidates": result.get("engine_candidates", []),
        "limitations": result.get("limitations", []),
        "coverage": {
            "ZIP member inventory": result.get("archive", {}).get("status"),
            "Manifest parse": manifest.get("status"),
            "DEX identifier scan": result.get("dex_status"),
            "Asset previews": result.get("asset_preview_status"),
            "DEX decompilation": "unsupported",
            "Resource/Smali decoding": "unsupported",
            "Device/runtime evidence": "unsupported",
        },
    }
