"""Read-only Steam install, appmanifest, VPK, and loose-asset inspection.

Steam is treated as a distribution/library layout, not as an engine. Engine
results are explicitly candidates based on bounded file markers. This module
never launches a game, writes into an install, or extracts archive members.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import struct
from pathlib import Path, PurePosixPath
from typing import Any

from .android import image_mime
from .core import AereError, _regular_open, _stat_signature

_VDF_MAX_BYTES = 2 * 1024 * 1024
_VDF_MAX_TOKENS = 200_000
_VDF_MAX_TOKEN_CHARS = 4096
_VDF_MAX_DEPTH = 64
_STEAM_MANIFEST_SCAN_MAX = 100
_STEAM_MANIFEST_SCAN_TOTAL_MAX = 16 * 1024 * 1024
_VPK_TREE_MAX = 16 * 1024 * 1024
_VPK_ENTRY_MAX = 50_000
_PREVIEW_FILE_MAX = 768 * 1024
_PREVIEW_TOTAL_MAX = 8 * 1024 * 1024
_PREVIEW_COUNT_MAX = 32
_PACKAGE_SCAN_MAX = 4
_VPK_FILE_REVALIDATE_MAX = 64 * 1024 * 1024


class _VDFError(ValueError):
    pass


def tokenize_vdf(text: str, max_tokens: int = _VDF_MAX_TOKENS) -> list[str]:
    """Tokenize the quoted/braced VDF subset used by Steam app manifests."""
    tokens: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if char.isspace():
            i += 1
            continue
        if text.startswith("//", i):
            newline = text.find("\n", i + 2)
            i = length if newline < 0 else newline + 1
            continue
        if char in "{}":
            tokens.append(char)
            i += 1
        elif char == '"':
            i += 1
            value: list[str] = []
            while i < length:
                char = text[i]
                if char == '"':
                    i += 1
                    break
                if char == "\\" and i + 1 < length:
                    nxt = text[i + 1]
                    if nxt in ('"', "\\"):
                        value.append(nxt)
                    elif nxt == "n":
                        value.append("\n")
                    elif nxt == "t":
                        value.append("\t")
                    else:
                        value.extend(("\\", nxt))
                    i += 2
                    continue
                value.append(char)
                i += 1
            else:
                raise _VDFError("unterminated quoted string")
            tokens.append("".join(value))
        else:
            start = i
            while i < length and not text[i].isspace() and text[i] not in "{}":
                if text.startswith("//", i):
                    break
                i += 1
            if i == start:
                raise _VDFError("invalid VDF token")
            tokens.append(text[start:i])
        if len(tokens) > max_tokens:
            raise _VDFError("VDF token count exceeds parser bounds")
        if tokens and len(tokens[-1]) > _VDF_MAX_TOKEN_CHARS:
            raise _VDFError("VDF token exceeds the bounded string length")
    return tokens


def parse_vdf(text: str, max_tokens: int = _VDF_MAX_TOKENS) -> dict[str, Any]:
    """Parse VDF key/value objects, rejecting ambiguous duplicate keys."""
    tokens = tokenize_vdf(text, max_tokens=max_tokens)
    index = 0
    items_seen = 0

    def object_value(depth: int, needs_close: bool) -> dict[str, Any]:
        nonlocal index, items_seen
        if depth > _VDF_MAX_DEPTH:
            raise _VDFError("VDF nesting exceeds parser bounds")
        result: dict[str, Any] = {}
        while index < len(tokens):
            if tokens[index] == "}":
                if not needs_close:
                    raise _VDFError("unexpected closing brace")
                index += 1
                return result
            key = tokens[index]
            if key == "{":
                raise _VDFError("unexpected opening brace where a key was required")
            index += 1
            if index >= len(tokens):
                raise _VDFError("VDF key has no value")
            if tokens[index] == "{":
                index += 1
                value: Any = object_value(depth + 1, True)
            elif tokens[index] == "}":
                raise _VDFError("VDF key has no value before closing brace")
            else:
                value = tokens[index]
                index += 1
            items_seen += 1
            if items_seen > max_tokens // 2:
                raise _VDFError("VDF pair count exceeds parser bounds")
            if any(existing.casefold() == key.casefold() for existing in result):
                raise _VDFError(f"duplicate VDF key {key!r} is ambiguous")
            result[key] = value
        if needs_close:
            raise _VDFError("unclosed VDF object")
        return result

    return object_value(0, False)


def _case_get(value: Any, key: str) -> Any:
    if not isinstance(value, dict):
        return None
    key_folded = key.casefold()
    for item_key, item_value in value.items():
        if str(item_key).casefold() == key_folded:
            return item_value
    return None


def _read_local_bounded(workspace: Any, path: Path, max_bytes: int) -> tuple[bytes, str, dict[str, int]]:
    """Read one approved regular file with a stable stat signature and digest."""
    path = workspace._input_path(path, expected="file")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AereError("open_failed", "Could not open an approved Steam metadata/asset file.", {"reason": type(exc).__name__}) from exc
    try:
        stream = os.fdopen(fd, "rb", closefd=True)
    except Exception:
        os.close(fd)
        raise
    with stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise AereError("not_regular_file", "Only regular files can be inspected.")
        if before.st_size > max_bytes:
            raise AereError("size_limit", "File exceeds the bounded read limit.", {"size": before.st_size, "limit": max_bytes})
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        total = 0
        while True:
            block = stream.read(min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise AereError("size_limit", "File exceeded the bounded read limit while reading.", {"limit": max_bytes})
            digest.update(block)
            chunks.append(block)
        after = os.fstat(stream.fileno())
    if _stat_signature(before) != _stat_signature(after) or total != before.st_size:
        raise AereError("artifact_changed", "File changed while it was being inspected.")
    return b"".join(chunks), digest.hexdigest(), _stat_signature(after)


def _safe_install_dir(value: str) -> bool:
    if not value or "\x00" in value:
        return False
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not path.is_absolute() and bool(path.parts) and all(part not in {"", ".", ".."} for part in path.parts) and not re.match(r"^[A-Za-z]:", normalized)


def _parse_appmanifest(workspace: Any, path: Path) -> dict[str, Any]:
    raw, digest, signature = _read_local_bounded(workspace, path, _VDF_MAX_BYTES)
    try:
        text = raw.decode("utf-8-sig")
        parsed = parse_vdf(text)
    except (UnicodeDecodeError, _VDFError) as exc:
        return {
            "status": "invalid",
            "display_name": path.name,
            "sha256": digest,
            "error": str(exc)[:300],
            "stat": signature,
        }
    app_state = _case_get(parsed, "AppState")
    if not isinstance(app_state, dict):
        app_state = parsed
    app_id = _case_get(app_state, "appid")
    match = re.fullmatch(r"appmanifest_(\d+)\.acf", path.name, flags=re.IGNORECASE)
    if not app_id and match:
        app_id = match.group(1)
    install_dir = _case_get(app_state, "installdir")
    return {
        "status": "parsed",
        "display_name": path.name,
        "sha256": digest,
        "appid": str(app_id) if app_id is not None else None,
        "name": _case_get(app_state, "name"),
        "installdir": install_dir,
        "buildid": _case_get(app_state, "buildid"),
        "branch": _case_get(app_state, "betakey"),
        "state_flags": _case_get(app_state, "StateFlags"),
        "size_on_disk": _case_get(app_state, "SizeOnDisk"),
        "last_updated": _case_get(app_state, "LastUpdated"),
        "manifest_status": "parsed",
        "stat": signature,
        "limitations": ["Steam appmanifest values describe installed metadata, not engine identity or runtime behavior."],
    }


def _discover_manifest(workspace: Any, game_dir: Path) -> tuple[Path | None, dict[str, Any] | None]:
    if game_dir.parent.name.casefold() != "common" or game_dir.parent.parent.name.casefold() != "steamapps":
        return None, None
    steamapps = game_dir.parent.parent
    manifests: list[Path] = []
    try:
        with os.scandir(steamapps) as entries:
            for entry in entries:
                if not entry.name.casefold().startswith("appmanifest_") or not entry.name.casefold().endswith(".acf"):
                    continue
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                manifests.append(Path(entry.path))
                if len(manifests) > _STEAM_MANIFEST_SCAN_MAX:
                    raise AereError("steam_manifest_limit", "Steam library appmanifest count exceeds the scan limit.", {"limit": _STEAM_MANIFEST_SCAN_MAX})
    except OSError as exc:
        raise AereError("steam_manifest_scan_failed", "Could not enumerate Steam appmanifests.", {"reason": type(exc).__name__}) from exc
    common_root = steamapps / "common"
    try:
        game_relative = game_dir.relative_to(common_root).as_posix().casefold()
    except ValueError:
        return None, None
    matches: list[tuple[Path, dict[str, Any]]] = []
    manifest_bytes = 0
    for candidate in sorted(manifests, key=lambda item: item.name.casefold()):
        workspace._input_path(candidate, expected="file")
        try:
            declared_size = int(candidate.lstat().st_size)
        except OSError as exc:
            raise AereError("steam_manifest_scan_failed", "Could not stat a Steam appmanifest.", {"reason": type(exc).__name__}) from exc
        manifest_bytes += declared_size
        if manifest_bytes > _STEAM_MANIFEST_SCAN_TOTAL_MAX:
            raise AereError("steam_manifest_limit", "Steam appmanifest bytes exceed the aggregate scan limit.", {"limit": _STEAM_MANIFEST_SCAN_TOTAL_MAX})
        parsed = _parse_appmanifest(workspace, candidate)
        installdir = parsed.get("installdir")
        if parsed.get("status") == "parsed" and isinstance(installdir, str) and installdir.replace("\\", "/").casefold() == game_relative:
            matches.append((candidate, parsed))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise AereError("steam_manifest_ambiguous", "More than one Steam appmanifest matches this install directory; pass the exact appmanifest file.")
    return None, None


def _detect_engines(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    signals: dict[str, list[str]] = {"Unity": [], "Unreal Engine": [], "Godot": [], "Source/Source 2": []}
    for item in files:
        rel = str(item.get("relative_path", ""))
        lower = rel.casefold().replace("\\", "/")
        suffix = Path(lower).suffix
        name = Path(lower).name
        if name in {"unityplayer.dll", "unityplayer.so", "unityplayer.dylib", "gameassembly.dll", "libil2cpp.so", "globalgamemanagers"} or "/managed/assembly-csharp.dll" in lower:
            signals["Unity"].append(rel)
        if suffix in {".utoc", ".ucas", ".uasset", ".umap"} or (suffix == ".pak" and ("/content/paks/" in f"/{lower}" or "/paks/" in f"/{lower}")):
            signals["Unreal Engine"].append(rel)
        if name == "project.godot" or suffix == ".pck":
            signals["Godot"].append(rel)
        if suffix == ".vpk" or name in {"gameinfo.txt", "gameinfo.gi"}:
            signals["Source/Source 2"].append(rel)
    candidates: list[dict[str, Any]] = []
    for engine, items in signals.items():
        if items:
            candidates.append({
                "engine": engine,
                "status": "candidate" if len(items) == 1 else "supported_by_multiple_markers",
                "signal_count": len(items),
                "supporting_files": sorted(set(items), key=str.casefold)[:40],
                "limitation": "Heuristic file markers only. A game may bundle, rename, or vendor formats; no executable/runtime verification was performed.",
            })
    candidates.sort(key=lambda item: (-item["signal_count"], item["engine"]))
    return candidates


def _read_vpk_cstring(tree: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(tree):
        raise ValueError("VPK directory tree is truncated")
    end = tree.find(b"\x00", offset)
    if end < 0:
        raise ValueError("VPK tree string is not NUL-terminated")
    raw = tree[offset:end]
    if len(raw) > 4096:
        raise ValueError("VPK tree string exceeds the bounded length")
    return raw.decode("utf-8", errors="replace"), end + 1


def parse_vpk(
    path: Path,
    max_tree_bytes: int = _VPK_TREE_MAX,
    max_entries: int = _VPK_ENTRY_MAX,
    expected_sha256: str | None = None,
    max_file_bytes: int = 256 * 1024 * 1024,
) -> dict[str, Any]:
    """Read a VPK v1/v2 directory tree and entry ranges; never read member data."""
    try:
        stream, before = _regular_open(path)
        with stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size < 12:
                return {"status": "invalid", "error": "VPK file is not a regular file or is shorter than its header"}
            header = stream.read(28)
            if len(header) < 12:
                return {"status": "invalid", "error": "VPK header is truncated"}
            signature, version, tree_size = struct.unpack_from("<III", header, 0)
            if signature != 0x55AA1234 or version not in {1, 2}:
                return {"status": "not_vpk", "error": "VPK signature/version is not recognized"}
            header_size = 12 if version == 1 else 28
            if len(header) < header_size:
                return {"status": "invalid", "error": "VPK v2 header is truncated"}
            if version == 1:
                file_data_size = max(0, before.st_size - header_size - tree_size)
            else:
                file_data_size = struct.unpack_from("<I", header, 12)[0]
            if before.st_size > max_file_bytes:
                return {"status": "partial", "version": version, "tree_size": tree_size, "file_data_size": file_data_size, "entry_count": None, "entries": [], "truncated": True, "error": "VPK exceeds the bounded revalidation size limit"}
            if tree_size > max_tree_bytes or header_size + tree_size > before.st_size:
                return {
                    "status": "partial",
                    "version": version,
                    "tree_size": tree_size,
                    "file_data_size": file_data_size,
                    "entry_count": None,
                    "entries": [],
                    "truncated": True,
                    "error": "VPK tree exceeds the configured limit or file bounds",
                }
            stream.seek(header_size)
            tree = stream.read(tree_size)
            if len(tree) != tree_size:
                return {"status": "changed", "error": "VPK file changed or was truncated during directory-tree read"}
            stream.seek(0)
            digest = hashlib.sha256()
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(stream.fileno())
            if _stat_signature(before) != _stat_signature(after):
                return {"status": "changed", "error": "VPK file changed during directory-tree inspection"}
            if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
                return {"status": "changed", "error": "VPK content hash changed after install inventory"}
    except OSError as exc:
        return {"status": "unreadable", "error": type(exc).__name__}

    cursor = 0
    entries: list[dict[str, Any]] = []
    total = 0
    truncated = False
    try:
        while cursor < len(tree):
            extension, cursor = _read_vpk_cstring(tree, cursor)
            if extension == "":
                break
            while True:
                directory, cursor = _read_vpk_cstring(tree, cursor)
                while True:
                    filename, cursor = _read_vpk_cstring(tree, cursor)
                    if filename == "":
                        break
                    if cursor + 18 > len(tree):
                        raise ValueError("VPK entry record is truncated")
                    crc32, preload_bytes, archive_index, entry_offset, entry_length, terminator = struct.unpack_from("<IHHIIH", tree, cursor)
                    cursor += 18
                    if terminator != 0xFFFF:
                        raise ValueError("VPK entry terminator is invalid")
                    if cursor + preload_bytes > len(tree):
                        raise ValueError("VPK preload data exceeds the bounded tree")
                    cursor += preload_bytes
                    total += 1
                    if total > max_entries:
                        truncated = True
                        break
                    if directory in {"", " "}:
                        virtual_name = f"{filename}.{extension}" if extension else filename
                    else:
                        virtual_name = f"{directory}/{filename}.{extension}" if extension else f"{directory}/{filename}"
                    normalized = virtual_name.replace("\\", "/")
                    parts = PurePosixPath(normalized).parts
                    safe = bool(parts) and not PurePosixPath(normalized).is_absolute() and not re.match(r"^[A-Za-z]:", normalized) and all(part not in {"", ".", ".."} for part in parts)
                    in_directory_archive = archive_index == 0x7FFF
                    range_valid = not in_directory_archive or entry_offset + entry_length <= file_data_size
                    entries.append({
                        "path": (normalized[:1024] if safe else "[UNSAFE_MEMBER_NAME]"),
                        "size": entry_length,
                        "preload_bytes": preload_bytes,
                        "archive_index": archive_index,
                        "directory_archive": in_directory_archive,
                        "range_valid": range_valid,
                        "safe_path": safe,
                        "crc32": f"{crc32:08x}",
                    })
                if truncated:
                    break
                if directory == "":
                    break
            if truncated:
                break
        status = "partial" if truncated else "parsed"
        return {
            "status": status,
            "version": version,
            "tree_size": tree_size,
            "file_data_size": file_data_size,
            "entry_count": None if truncated else total,
            "entries_examined": len(entries),
            "entries": entries[:min(1000, max_entries)],
            "entries_sampled": min(len(entries), 1000),
            "truncated": truncated or len(entries) > 1000,
            "limitations": [
                "VPK names, offsets, sizes, preload lengths, and CRC fields are metadata only; no member bytes were read or extracted.",
                "External archive-index files are not resolved; CRC values are not verified against member data.",
            ],
        }
    except ValueError as exc:
        return {"status": "invalid", "version": version, "tree_size": tree_size, "error": str(exc)[:300], "entries": [], "truncated": False}


def _preview_loose_images(workspace: Any, root: Path, files: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    previews: list[dict[str, Any]] = []
    total_bytes = 0
    candidates = [item for item in files if Path(str(item.get("relative_path", ""))).suffix.casefold() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}]
    status = "complete"
    for item in candidates[:_PREVIEW_COUNT_MAX]:
        size = int(item.get("size") or 0)
        if size > _PREVIEW_FILE_MAX or total_bytes + size > _PREVIEW_TOTAL_MAX:
            status = "partial"
            continue
        relative = PurePosixPath(str(item["relative_path"]))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            continue
        path = root.joinpath(*relative.parts)
        try:
            raw, digest, _ = _read_local_bounded(workspace, path, _PREVIEW_FILE_MAX)
        except AereError:
            status = "partial"
            continue
        if digest != item.get("sha256"):
            status = "partial"
            continue
        mime = image_mime(raw)
        if not mime:
            continue
        previews.append({
            "name": str(item["relative_path"]),
            "size": len(raw),
            "mime_type": mime,
            "sha256": digest,
            "data_uri": f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}",
        })
        total_bytes += len(raw)
    if len(candidates) > _PREVIEW_COUNT_MAX:
        status = "partial"
    return previews, status


def _inspect_vpk_candidates(workspace: Any, root: Path, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    all_candidates = [item for item in files if Path(str(item.get("relative_path", ""))).suffix.casefold() == ".vpk"]
    # Numbered files are usually VPK data segments; the directory index is the
    # *_dir.vpk companion. Avoid treating every segment as a separate index.
    candidates = [
        item for item in all_candidates
        if not re.search(r"_[0-9]{3}\.vpk$", Path(str(item.get("relative_path", ""))).name, flags=re.IGNORECASE)
    ]
    results: list[dict[str, Any]] = []
    for item in candidates[:_PACKAGE_SCAN_MAX]:
        relative = PurePosixPath(str(item.get("relative_path", "")))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            continue
        path = root.joinpath(*relative.parts)
        try:
            workspace._input_path(path, expected="file")
            info = parse_vpk(
                path,
                expected_sha256=str(item.get("sha256") or ""),
                max_file_bytes=min(_VPK_FILE_REVALIDATE_MAX, int(workspace._limits()["max_file_bytes"])),
            )
        except AereError as exc:
            info = {"status": "unreadable", "error": exc.code}
        info["relative_path"] = str(item.get("relative_path", ""))
        info["sha256"] = item.get("sha256")
        results.append(info)
    if len(candidates) > _PACKAGE_SCAN_MAX:
        results.append({"status": "not_attempted", "relative_path": "(additional VPK directory candidates)", "error": f"candidate limit of {_PACKAGE_SCAN_MAX} reached"})
    return results


def _open_game_target(workspace: Any, target: str | os.PathLike[str]) -> tuple[Path, Path | None, dict[str, Any] | None]:
    path = workspace._input_path(target)
    if path.is_file():
        if not (path.name.casefold().startswith("appmanifest_") and path.suffix.casefold() == ".acf"):
            raise AereError("unsupported_steam_input", "Pass one game install directory or a Steam appmanifest_*.acf file.")
        if path.parent.name.casefold() != "steamapps":
            raise AereError("unsupported_steam_input", "A Steam appmanifest must be directly under a steamapps directory.")
        manifest = _parse_appmanifest(workspace, path)
        if manifest.get("status") != "parsed":
            raise AereError("steam_manifest_invalid", "Steam appmanifest could not be parsed.", {"error": manifest.get("error")})
        install_dir = manifest.get("installdir")
        if not isinstance(install_dir, str) or not _safe_install_dir(install_dir):
            raise AereError("steam_install_dir_invalid", "Appmanifest installdir is missing or not a safe relative path.")
        steamapps = path.parent
        game_root = steamapps / "common" / Path(*PurePosixPath(install_dir.replace("\\", "/")).parts)
        game_root = workspace._input_path(game_root, expected="directory")
        return game_root, path, manifest

    game_root = workspace._input_path(path, expected="directory")
    manifest_path, manifest = _discover_manifest(workspace, game_root)
    return game_root, manifest_path, manifest


def inspect_steam_install(workspace: Any, target: str | os.PathLike[str], include_previews: bool = False) -> dict[str, Any]:
    """Inventory one approved Steam install directory (or appmanifest target)."""
    game_root, manifest_path, manifest = _open_game_target(workspace, target)
    inventory = workspace.inventory(game_root)
    files = inventory["files"]
    engines = _detect_engines(files)
    previews: list[dict[str, Any]] = []
    preview_status = "not_requested"
    if include_previews:
        previews, preview_status = _preview_loose_images(workspace, game_root, files)

    vpk_info = _inspect_vpk_candidates(workspace, game_root, files)
    ext_counts: dict[str, int] = {}
    package_candidates: list[dict[str, Any]] = []
    for item in files:
        relative = str(item.get("relative_path", ""))
        suffix = Path(relative).suffix.casefold()
        if suffix:
            ext_counts[suffix] = ext_counts.get(suffix, 0) + 1
        if suffix in {".vpk", ".pak", ".utoc", ".ucas", ".pck", ".bundle", ".assets", ".assetbundle", ".uasset", ".umap"}:
            package_candidates.append({"path": relative, "size": item.get("size"), "sha256": item.get("sha256"), "format_candidate": suffix.lstrip(".")})

    result = {
        "kind": "steam_install",
        "analysis_version": "0.2.0",
        "game_directory": game_root.name,
        "steam_manifest": {
            "status": manifest.get("status") if manifest else "not_found",
            "display_name": manifest.get("display_name") if manifest else None,
            "sha256": manifest.get("sha256") if manifest else None,
            "appid": manifest.get("appid") if manifest else None,
            "name": manifest.get("name") if manifest else None,
            "installdir": manifest.get("installdir") if manifest else None,
            "buildid": manifest.get("buildid") if manifest else None,
            "branch": manifest.get("branch") if manifest else None,
            "state_flags": manifest.get("state_flags") if manifest else None,
            "size_on_disk": manifest.get("size_on_disk") if manifest else None,
            "last_updated": manifest.get("last_updated") if manifest else None,
        },
        "inventory": {
            "file_count": inventory["file_count"],
            "total_bytes": inventory["total_bytes"],
            "truncated": inventory["truncated"],
            "skipped_count": inventory["skipped_count"],
            "limits": inventory["limits"],
        },
        "file_extension_counts": dict(sorted(ext_counts.items(), key=lambda item: (-item[1], item[0]))[:150]),
        "package_candidates": package_candidates[:1000],
        "package_candidates_truncated": len(package_candidates) > 1000,
        "engine_candidates": engines,
        "vpk_indexes": vpk_info,
        "files": files[:3000],
        "files_truncated": len(files) > 3000,
        "skipped": inventory["skipped"],
        "_manifest_source_path": str(manifest_path) if manifest_path is not None else None,
        "previews": previews,
        "asset_preview_status": preview_status,
        "limitations": [
            "Steam identifies distribution/library metadata, not the engine or asset format. Engine markers are heuristics only.",
            "VPK support lists bounded directory-tree metadata; VPK member content is not read or extracted.",
            "No Unreal PAK, Unity serialized-file/bundle, Godot PCK, Source 2 resource, or proprietary title-specific asset decoder is included yet.",
            "The game was not launched; no account, DRM, anti-cheat, network, process, or runtime inspection was performed.",
        ],
        "coverage": {
            "approved-directory inventory": "partial" if inventory["truncated"] or inventory["skipped_count"] else "complete",
            "Steam appmanifest": manifest.get("status") if manifest else "unknown",
            "engine marker scan": "partial" if inventory["truncated"] else "complete",
            "VPK directory metadata": "partial" if any(item.get("status") in {"partial", "invalid", "changed", "unreadable", "not_attempted"} for item in vpk_info) else "complete",
            "loose image previews": preview_status,
            "Unity asset decoding": "unsupported",
            "Unreal asset decoding": "unsupported",
            "Godot/Source 2 asset decoding": "unsupported",
            "Game code analysis": "unsupported",
            "Game runtime behavior": "unsupported",
        },
    }
    if manifest_path is not None:
        result["steam_manifest"]["display_name"] = manifest_path.name
    return result


def steam_report_sections(result: dict[str, Any]) -> dict[str, Any]:
    manifest = result.get("steam_manifest", {})
    inventory = result.get("inventory", {})
    package_rows = result.get("package_candidates", [])
    vpk_rows = []
    for vpk in result.get("vpk_indexes", []):
        vpk_rows.append({
            "file": vpk.get("relative_path"),
            "status": vpk.get("status"),
            "version": vpk.get("version"),
            "entries": vpk.get("entry_count"),
            "tree_bytes": vpk.get("tree_size"),
            "sample_paths": ", ".join(item.get("path", "") for item in vpk.get("entries", [])[:6]),
        })
    file_rows = result.get("files", [])[:2000]
    notices = []
    if len(result.get("files", [])) > len(file_rows) or result.get("files_truncated"):
        notices.append("The Installed files table is a bounded sample (up to 2,000 rows); the JSON inspection may also limit the returned file list.")
    if result.get("evidence_note"):
        notices.append(str(result["evidence_note"]))
    return {
        "title": manifest.get("name") or result.get("game_directory") or "Steam install",
        "subtitle": "Bounded read-only local install inventory. Store metadata is not treated as proof of engine or parser compatibility.",
        "summary": [
            {"label": "App ID", "value": manifest.get("appid") or "unknown"},
            {"label": "Build ID", "value": manifest.get("buildid") or "unknown"},
            {"label": "Files inventoried", "value": inventory.get("file_count", 0)},
            {"label": "Install size", "value": f"{int(inventory.get('total_bytes', 0)):,} bytes"},
        ],
        "sections": [
            {"title": "Steam metadata", "rows": [{"field": label, "value": value if value is not None else "—"} for label, value in [
                ("App ID", manifest.get("appid")),
                ("Name", manifest.get("name")),
                ("Install directory", manifest.get("installdir")),
                ("Build ID", manifest.get("buildid")),
                ("Branch", manifest.get("branch")),
                ("Manifest status", manifest.get("status")),
            ]]},
            {"title": "Engine candidates", "rows": result.get("engine_candidates", []), "empty": "No supported engine markers were observed in the inventoried files."},
            {"title": "Package candidates", "rows": package_rows, "empty": "No known package-like file extensions were inventoried."},
            {"title": "VPK directory indexes", "rows": vpk_rows, "empty": "No VPK files were found."},
            {"title": "Installed files", "rows": file_rows, "empty": "No files were inventoried."},
            {"title": "File-type counts", "rows": [{"extension": key, "count": count} for key, count in result.get("file_extension_counts", {}).items()]},
        ],
        "previews": result.get("previews", []),
        "coverage": result.get("coverage", {}),
        "limitations": result.get("limitations", []),
        "inventory_truncated": bool(inventory.get("truncated")),
        "notices": notices,
    }
