"""Local, evidence-first core for AERE v0.2.

The core has no target-execution or general subprocess capability. It reads
bounded local artifacts, records provenance, and exports evidence bundles.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
import os
import re
import sqlite3
import stat
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from . import __version__


DEFAULT_CONFIG: dict[str, Any] = {
    "schema_version": 1,
    "allowed_roots": [],
    "exclude_directory_names": [".git", ".aere", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target"],
    "limits": {
        "max_file_bytes": 1_073_741_824,
        "max_inventory_files": 50_000,
        "max_inventory_entries": 100_000,
        "max_inventory_skip_samples": 1_000,
        "max_inventory_bytes": 10_737_418_240,
        "max_string_scan_bytes": 268_435_456,
        "max_string_results": 1_000,
        "max_string_length": 4_096,
        "max_archive_members": 20_000,
        "max_archive_directory_bytes": 16_777_216,
        "max_evidence_json_bytes": 262_144,
        "max_evidence_records_per_run": 5_000,
        "max_coverage_records_per_run": 1_000,
        "max_report_bytes": 10_485_760,
    },
    "policy": {
        "follow_symlinks": False,
        "execute_targets": False,
        "network_access": False,
        "dynamic_analysis": False,
        "copy_artifacts_into_repo": False,
    },
}

_SECRET_ASSIGN = re.compile(
    r"(?i)\b((?:[a-z0-9]+[_-])*(?:api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|token|secret|credentials?|authorization|cookie))\b([\"']?\s*[:=]\s*[\"']?)([^\s,;\"']+)"
)
_SENSITIVE_KEY = re.compile(
    r"(?i)^(?:[a-z0-9]+[_-])*(?:api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|token|secret|credentials?|authorization|cookie)$"
)
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_POSIX_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9:/])/[^\s\"'<>|]+")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:\\[^\s\"'<>|]+")
_ASCII_PRINTABLE = set(range(0x20, 0x7F))


class AereError(Exception):
    """Expected, user-actionable AERE error."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _redact_json(value: Any) -> Any:
    """Recursively redact obvious secrets from user/provider evidence payloads."""
    if isinstance(value, str):
        return Workspace._redact(value)[0]
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            cleaned[name] = "[REDACTED]" if _SENSITIVE_KEY.fullmatch(name) and item not in (None, "", [], {}) else _redact_json(item)
        return cleaned
    return value


def _redact_export_paths(value: Any) -> Any:
    """Remove absolute local paths from portable evidence exports."""
    if isinstance(value, str):
        if value.startswith("data:"):
            return value
        result = _POSIX_ABSOLUTE_PATH.sub("[LOCAL_PATH]", value)
        return _WINDOWS_ABSOLUTE_PATH.sub("[LOCAL_PATH]", result)
    if isinstance(value, list):
        return [_redact_export_paths(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_export_paths(item) for key, item in value.items()}
    return value


def _stat_signature(st: os.stat_result) -> dict[str, int]:
    return {
        "device": int(st.st_dev),
        "inode": int(st.st_ino),
        "size": int(st.st_size),
        "mtime_ns": int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
    }


def _abs_path(value: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _assert_no_symlink_components(path: Path) -> None:
    """Reject symlinks in every existing component of an input path."""
    if not path.is_absolute():
        raise AereError("invalid_path", "Input path must be absolute after normalization.")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            raise AereError("not_found", "Input path does not exist.", {"component": str(current)})
        except OSError as exc:
            raise AereError("path_error", "Could not inspect an input path component.", {"component": str(current), "reason": str(exc)}) from exc
        if stat.S_ISLNK(mode):
            raise AereError("symlink_rejected", "Symlinks are not followed by the default AERE workflow.", {"component": str(current)})


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _regular_open(path: Path):
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AereError("open_failed", "Could not open the input as a regular local file.", {"reason": str(exc)}) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AereError("not_regular_file", "Only regular files are accepted by this operation.")
        return os.fdopen(fd, "rb", closefd=True), st
    except Exception:
        os.close(fd)
        raise


def _hash_stable_file(path: Path, max_bytes: int) -> tuple[str, int, bytes, dict[str, int]]:
    sha = hashlib.sha256()
    total = 0
    header = bytearray()
    fileobj, before = _regular_open(path)
    before_sig = _stat_signature(before)
    if before.st_size > max_bytes:
        fileobj.close()
        raise AereError("size_limit", "File exceeds the configured per-file size limit.", {"size": before.st_size, "limit": max_bytes})
    try:
        with fileobj:
            while True:
                block = fileobj.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > max_bytes:
                    raise AereError("size_limit", "File exceeded the configured per-file size limit while reading.", {"limit": max_bytes})
                if len(header) < 4096:
                    header.extend(block[: 4096 - len(header)])
                sha.update(block)
            after_sig = _stat_signature(os.fstat(fileobj.fileno()))
    except AereError:
        raise
    except OSError as exc:
        raise AereError("read_failed", "Could not read the input file.", {"reason": str(exc)}) from exc
    if before_sig != after_sig or total != before_sig["size"]:
        raise AereError("artifact_changed", "File identity changed while it was being hashed.", {"before": before_sig, "after": after_sig, "bytes_read": total})
    return sha.hexdigest(), total, bytes(header), after_sig


def _safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    p = PurePosixPath(normalized)
    if normalized.startswith("/") or p.is_absolute():
        return False
    if any(part == ".." for part in p.parts):
        return False
    if re.match(r"^[A-Za-z]:", normalized):
        return False
    return True


def _zip64_sizes(extra: bytes, compressed_size: int, uncompressed_size: int) -> tuple[int | None, int | None]:
    need_uncompressed = uncompressed_size == 0xFFFFFFFF
    need_compressed = compressed_size == 0xFFFFFFFF
    if not need_uncompressed and not need_compressed:
        return compressed_size, uncompressed_size
    cursor = 0
    while cursor + 4 <= len(extra):
        header_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        field = extra[cursor : cursor + field_size]
        cursor += field_size
        if header_id != 0x0001:
            continue
        offset = 0
        parsed_uncompressed: int | None = None
        parsed_compressed: int | None = None
        if need_uncompressed and offset + 8 <= len(field):
            parsed_uncompressed = struct.unpack_from("<Q", field, offset)[0]
            offset += 8
        if need_compressed and offset + 8 <= len(field):
            parsed_compressed = struct.unpack_from("<Q", field, offset)[0]
        return (parsed_compressed if need_compressed else compressed_size, parsed_uncompressed if need_uncompressed else uncompressed_size)
    return (None if need_compressed else compressed_size, None if need_uncompressed else uncompressed_size)


def _read_zip_metadata(path: Path, max_members: int, max_directory_bytes: int) -> dict[str, Any]:
    """Read a bounded ZIP central directory without ZipFile.infolist() allocation."""
    fileobj, file_stat = _regular_open(path)
    with fileobj as f:
        file_size = int(file_stat.st_size)
        tail_size = min(file_size, 65_577)  # EOCD + max comment + ZIP64 locator
        f.seek(file_size - tail_size)
        tail = f.read(tail_size)
        eocd_pos = tail.rfind(b"PK\x05\x06")
        eocd = None
        while eocd_pos >= 0:
            if eocd_pos + 22 <= len(tail):
                candidate = struct.unpack_from("<4s4H2LH", tail, eocd_pos)
                comment_length = candidate[-1]
                absolute_offset = file_size - tail_size + eocd_pos
                if eocd_pos + 22 + comment_length == len(tail):
                    eocd = (absolute_offset, candidate)
                    break
            eocd_pos = tail.rfind(b"PK\x05\x06", 0, eocd_pos)
        if eocd is None:
            raise AereError("not_zip_archive", "No bounded ZIP end-of-central-directory record was found.")
        eocd_offset, eocd_fields = eocd
        _, disk_number, directory_disk, entries_on_disk, member_count, directory_size, directory_offset, _ = eocd_fields

        zip64_sentinel = (
            entries_on_disk == 0xFFFF
            or member_count == 0xFFFF
            or directory_size == 0xFFFFFFFF
            or directory_offset == 0xFFFFFFFF
        )
        locator_offset = eocd_offset - 20
        if zip64_sentinel:
            if locator_offset < 0:
                raise AereError("zip_parse_error", "ZIP64 locator is missing.")
            f.seek(locator_offset)
            locator = f.read(20)
            if len(locator) != 20:
                raise AereError("zip_parse_error", "ZIP64 locator is truncated.")
            locator_sig, zip64_disk, zip64_offset, disk_count = struct.unpack("<4sLQL", locator)
            if locator_sig != b"PK\x06\x07":
                raise AereError("zip_parse_error", "ZIP64 locator signature is invalid.")
            if zip64_disk != 0 or disk_count != 1 or disk_number != 0 or directory_disk != 0:
                raise AereError("unsupported_archive_layout", "Multi-disk ZIP archives are not supported by the bounded reader.")
            f.seek(zip64_offset)
            zip64_record = f.read(56)
            if len(zip64_record) != 56:
                raise AereError("zip_parse_error", "ZIP64 end record is truncated.")
            fields = struct.unpack("<4sQ2H2L4Q", zip64_record)
            signature, record_size, _, _, zip64_disk_number, zip64_directory_disk, entries_on_disk, member_count, directory_size, directory_offset = fields
            if signature != b"PK\x06\x06" or record_size < 44 or zip64_offset + 12 + record_size > locator_offset:
                raise AereError("zip_parse_error", "ZIP64 end record is invalid or out of bounds.")
            if zip64_disk_number != 0 or zip64_directory_disk != 0 or entries_on_disk != member_count:
                raise AereError("unsupported_archive_layout", "Multi-disk ZIP archives are not supported by the bounded reader.")
        elif disk_number != 0 or directory_disk != 0 or entries_on_disk != member_count:
            raise AereError("unsupported_archive_layout", "Multi-disk ZIP archives are not supported by the bounded reader.")

        member_count = int(member_count)
        directory_size = int(directory_size)
        directory_offset = int(directory_offset)
        if directory_size > max_directory_bytes:
            return {
                "member_count": member_count,
                "member_sample_count": 0,
                "member_count_limited": member_count > 0,
                "unsafe_member_count_in_sample": 0,
                "unsafe_member_examples": [],
                "directory_bytes": directory_size,
                "directory_bytes_examined": 0,
                "directory_bytes_limited": True,
                "truncated": True,
                "members": [],
                "limitation": "Central directory exceeded the configured byte limit; no member names were parsed.",
            }
        if directory_offset < 0 or directory_offset + directory_size > file_size or directory_offset + directory_size > eocd_offset:
            raise AereError("zip_parse_error", "Central directory range is outside the file or overlaps its end record.")

        directory_start = directory_offset
        if member_count:
            f.seek(directory_start)
            if f.read(4) != b"PK\x01\x02":
                adjusted_start = eocd_offset - directory_size
                if adjusted_start < 0:
                    raise AereError("zip_parse_error", "Central directory signature was not found at the declared offset.")
                f.seek(adjusted_start)
                if f.read(4) != b"PK\x01\x02":
                    raise AereError("zip_parse_error", "Central directory signature was not found at a bounded candidate offset.")
                directory_start = adjusted_start

        members: list[dict[str, Any]] = []
        examined_bytes = 0
        sample_limit = max(0, int(max_members))
        entry_count = min(member_count, sample_limit)
        for _ in range(entry_count):
            if examined_bytes + 46 > directory_size:
                raise AereError("zip_parse_error", "Central directory entry header exceeds the declared directory size.")
            f.seek(directory_start + examined_bytes)
            fixed = f.read(46)
            if len(fixed) != 46:
                raise AereError("zip_parse_error", "Central directory entry header is truncated.")
            fields = struct.unpack("<4s6H3L5H2L", fixed)
            if fields[0] != b"PK\x01\x02":
                raise AereError("zip_parse_error", "Central directory entry signature is invalid.")
            flags = fields[3]
            compression = fields[4]
            compressed_size = fields[8]
            uncompressed_size = fields[9]
            name_length, extra_length, comment_length = fields[10], fields[11], fields[12]
            entry_size = 46 + name_length + extra_length + comment_length
            if entry_size > directory_size - examined_bytes:
                raise AereError("zip_parse_error", "Central directory variable fields exceed the declared directory size.")
            raw_name = f.read(name_length)
            extra = f.read(extra_length)
            if len(raw_name) != name_length or len(extra) != extra_length:
                raise AereError("zip_parse_error", "Central directory name or extra field is truncated.")
            if comment_length:
                f.seek(comment_length, os.SEEK_CUR)
            try:
                name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", errors="replace")
            except LookupError:
                name = raw_name.decode("utf-8", errors="replace")
            compressed_size, uncompressed_size = _zip64_sizes(extra, compressed_size, uncompressed_size)
            members.append({
                "name": name,
                "size": uncompressed_size,
                "compressed_size": compressed_size,
                "compression": compression,
                "encrypted": bool(flags & 0x1),
                "unsafe_path": not _safe_member_name(name),
                "is_directory": name.endswith(("/", "\\")),
            })
            examined_bytes += entry_size
        unsafe = [member["name"] for member in members if member["unsafe_path"]]
        return {
            "member_count": member_count,
            "member_sample_count": len(members),
            "member_count_limited": len(members) < member_count,
            "unsafe_member_count_in_sample": len(unsafe),
            "unsafe_member_examples": unsafe[:10],
            "directory_bytes": directory_size,
            "directory_bytes_examined": examined_bytes,
            "directory_bytes_limited": False,
            "truncated": len(members) < member_count,
            "members": members,
        }


def _is_zip_candidate(path: Path, max_directory_bytes: int = 16_777_216) -> bool:
    try:
        _read_zip_metadata(path, 0, max_directory_bytes)
        return True
    except AereError:
        return False


def probe_file(path: Path, header: bytes, size: int, max_members: int = 20_000, max_directory_bytes: int = 16_777_216) -> dict[str, Any]:
    """Conservative signature and container probe; never extracts data."""
    fmt = "unknown"
    details: dict[str, Any] = {}
    suffix = path.suffix.lower()

    if header.startswith(b"\x7fELF"):
        fmt = "elf"
        if len(header) >= 20:
            elf_class = header[4]
            endian = "little" if header[5] == 1 else "big" if header[5] == 2 else "unknown"
            machine = None
            if endian != "unknown":
                machine = struct.unpack("<H" if endian == "little" else ">H", header[18:20])[0]
            details.update({"class_bits": {1: 32, 2: 64}.get(elf_class), "endianness": endian, "machine_id": machine})
    elif header.startswith(b"MZ"):
        fmt = "pe_candidate"
        details["signature"] = "MZ"
        try:
            fileobj, _ = _regular_open(path)
            with fileobj as f:
                f.seek(0x3C)
                raw = f.read(4)
                if len(raw) == 4:
                    offset = struct.unpack("<I", raw)[0]
                    if 0 <= offset <= max(size - 4, 0) and offset <= 16 * 1024 * 1024:
                        f.seek(offset)
                        details["pe_signature_valid"] = f.read(4) == b"PE\0\0"
                    else:
                        details["pe_signature_valid"] = False
                        details["limitation"] = "PE header offset is outside the bounded probe window."
        except OSError:
            details["pe_signature_valid"] = None
    elif header[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        fmt = "macho"
        details["macho_kind"] = "thin"
    elif header[:4] in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
        fmt = "macho_fat_candidate"
        details["macho_kind"] = "fat/universal candidate"
    elif header.startswith(b"\0asm"):
        fmt = "wasm"
    elif header.startswith(b"PK\x03\x04") or _is_zip_candidate(path, max_directory_bytes):
        fmt = "zip"
        try:
            archive = _read_zip_metadata(path, max_members, max_directory_bytes)
            names = {item["name"] for item in archive["members"]}
            details.update({key: value for key, value in archive.items() if key not in {"members", "truncated", "limitation"}})
            if archive.get("limitation"):
                details["limitation"] = archive["limitation"]
            if "AndroidManifest.xml" in names:
                fmt = "apk"
            elif "BundleConfig.pb" in names and any(name.endswith(".dex") for name in names):
                fmt = "aab_candidate"
            elif "META-INF/MANIFEST.MF" in names:
                fmt = "jar_or_jar_based_archive"
            elif any(name.endswith("globalgamemanagers") for name in names) or any("assets/bin/Data" in name for name in names):
                fmt = "unity_zip_candidate"
        except AereError as exc:
            details["zip_parse_error"] = exc.code
            details["limitation"] = "ZIP signature/candidate could not be confirmed from a bounded central-directory parse."
    elif suffix in {".apk"}:
        fmt = "apk_candidate"
    elif suffix in {".aab"}:
        fmt = "aab_candidate"
    elif suffix in {".jar", ".class"}:
        fmt = "jvm_candidate"
    elif suffix in {".pak", ".uasset", ".umap"}:
        fmt = "game_asset_candidate"
    elif suffix in {".pck"}:
        fmt = "godot_package_candidate"

    return {"format": fmt, "size": size, "suffix": suffix, "details": details, "classification": "signature_or_extension_candidate"}


class Workspace:
    """A local store with explicit roots and hash-bound artifact identity."""

    def __init__(self, home: str | os.PathLike[str] | None = None):
        configured = home or os.environ.get("AERE_HOME") or (Path.home() / ".aere")
        self.home = _abs_path(configured)
        self.home.mkdir(parents=True, exist_ok=True)
        if self.home.is_symlink():
            raise AereError("workspace_symlink_rejected", "Workspace directory must not be a symlink.")
        self.config_path = self.home / "config.json"
        self.db_path = self.home / "state.sqlite3"
        if self.config_path.is_symlink() or self.db_path.is_symlink():
            raise AereError("workspace_symlink_rejected", "Workspace config and database paths must not be symlinks.")
        if not self.config_path.exists():
            self._write_config(DEFAULT_CONFIG)
        self.config = self._load_config()
        self._init_db()

    def _write_config(self, config: dict[str, Any]) -> None:
        tmp = self.config_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.config_path)

    def _load_config(self) -> dict[str, Any]:
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AereError("config_invalid", "Workspace configuration is unreadable or invalid JSON.", {"reason": str(exc)}) from exc
        if not isinstance(data, dict):
            raise AereError("config_invalid", "Workspace configuration must be a JSON object.")
        if data.get("schema_version") != 1:
            raise AereError("config_version_unsupported", "Unsupported workspace configuration version.", {"schema_version": data.get("schema_version")})
        roots = data.get("allowed_roots", [])
        limits = data.get("limits", {})
        policy = data.get("policy", {})
        excluded = data.get("exclude_directory_names", DEFAULT_CONFIG["exclude_directory_names"])
        if not isinstance(roots, list) or not all(isinstance(item, str) for item in roots):
            raise AereError("config_invalid", "allowed_roots must be a list of path strings.")
        if not isinstance(limits, dict) or not isinstance(policy, dict):
            raise AereError("config_invalid", "limits and policy must be JSON objects.")
        if not isinstance(excluded, list) or not all(isinstance(item, str) for item in excluded):
            raise AereError("config_invalid", "exclude_directory_names must be a list of strings.")
        merged_limits = {**DEFAULT_CONFIG["limits"], **limits}
        for key, value in merged_limits.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise AereError("config_invalid", "Every configured limit must be a positive integer.", {"limit": key})
        merged_policy = {**DEFAULT_CONFIG["policy"], **policy}
        if not all(isinstance(value, bool) for value in merged_policy.values()):
            raise AereError("config_invalid", "Every policy value must be boolean.")
        config = json.loads(json.dumps(DEFAULT_CONFIG))
        config.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
        config["limits"] = merged_limits
        config["policy"] = merged_policy
        config["allowed_roots"] = roots
        config["exclude_directory_names"] = excluded
        return config

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _init_db(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    format TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    probe_json TEXT NOT NULL,
                    imported_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS locations (
                    location_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
                    source_path TEXT NOT NULL,
                    stat_json TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    UNIQUE(artifact_id, source_path)
                );
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    workflow TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    finished_at TEXT
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    kind TEXT NOT NULL CHECK(kind IN ('observation','inference','hypothesis','unknown')),
                    claim TEXT NOT NULL,
                    source_tool TEXT NOT NULL,
                    source_version TEXT,
                    locator_json TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    supports_json TEXT NOT NULL,
                    caveats_json TEXT NOT NULL,
                    confidence REAL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS coverage (
                    coverage_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    subject TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('complete','partial','unsupported','not_attempted','unknown')),
                    scope TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    provider_version TEXT,
                    operation_id TEXT NOT NULL,
                    units_examined INTEGER,
                    units_total INTEGER,
                    excluded_json TEXT NOT NULL,
                    limitations_json TEXT NOT NULL,
                    notes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_locations_artifact ON locations(artifact_id);
                CREATE INDEX IF NOT EXISTS idx_runs_artifact ON runs(artifact_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);
                CREATE INDEX IF NOT EXISTS idx_coverage_run ON coverage(run_id);
                """
            )
            coverage_columns = {row[1] for row in db.execute("PRAGMA table_info(coverage)")}
            if "provider_version" not in coverage_columns:
                db.execute("ALTER TABLE coverage ADD COLUMN provider_version TEXT")

    def _limits(self) -> dict[str, int]:
        return self.config["limits"]

    def _input_path(self, raw_path: str | os.PathLike[str], expected: str | None = None) -> Path:
        path = _abs_path(raw_path)
        _assert_no_symlink_components(path)
        roots = [_abs_path(item) for item in self.config.get("allowed_roots", [])]
        allowed = False
        for root in roots:
            _assert_no_symlink_components(root)
            if root.is_dir() and _inside(path, root):
                allowed = True
                break
        if not allowed:
            raise AereError("outside_allowed_roots", "Input path is outside every configured allowed root.", {"approved_root_count": len(roots)})
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise AereError("path_error", "Could not inspect input path.", {"reason": str(exc)}) from exc
        if stat.S_ISLNK(mode):
            raise AereError("symlink_rejected", "Symlink inputs are rejected.")
        if expected == "file" and not stat.S_ISREG(mode):
            raise AereError("not_regular_file", "This operation requires a regular file.")
        if expected == "directory" and not stat.S_ISDIR(mode):
            raise AereError("not_directory", "This operation requires a directory.")
        if expected is None and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise AereError("unsupported_path_type", "Only regular files and directories are accepted.")
        return path

    def allow_root(self, raw_path: str | os.PathLike[str]) -> dict[str, Any]:
        path = _abs_path(raw_path)
        _assert_no_symlink_components(path)
        if not path.is_dir():
            raise AereError("not_directory", "An allowed root must be an existing directory.")
        roots = self.config.setdefault("allowed_roots", [])
        value = str(path)
        if value not in roots:
            roots.append(value)
            roots.sort()
            self._write_config(self.config)
            self.config = self._load_config()
        return {"allowed_roots": list(self.config["allowed_roots"])}

    def status(self) -> dict[str, Any]:
        with self._connect() as db:
            counts = {
                "artifacts": db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0],
                "runs": db.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
                "evidence": db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
                "coverage": db.execute("SELECT COUNT(*) FROM coverage").fetchone()[0],
            }
        return {
            "product": "AERE Workbench",
            "version": __version__,
            "home": str(self.home),
            "allowed_root_count": len(self.config.get("allowed_roots", [])),
            "counts": counts,
            "policy": dict(self.config.get("policy", {})),
            "target_execution_available": False,
            "network_access_available": False,
        }

    def _stored_artifact(self, artifact_id: str) -> sqlite3.Row:
        with self._connect() as db:
            row = db.execute("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise AereError("artifact_not_found", "Artifact ID is not registered in this workspace.", {"artifact_id": artifact_id})
        return row

    def import_file(self, raw_path: str | os.PathLike[str]) -> dict[str, Any]:
        path = self._input_path(raw_path, expected="file")
        max_bytes = int(self._limits()["max_file_bytes"])
        digest, size, header, signature = _hash_stable_file(path, max_bytes)
        probe = _redact_json(probe_file(path, header, size, int(self._limits()["max_archive_members"]), int(self._limits()["max_archive_directory_bytes"])))
        display_name = self._redact(path.name)[0]
        verify_digest, verify_size, _, now_sig = _hash_stable_file(path, max_bytes)
        if digest != verify_digest or size != verify_size or signature != now_sig:
            raise AereError("artifact_changed", "File identity changed during import.", {"before": signature, "after": now_sig})
        artifact_id = f"sha256:{digest}"
        imported = utc_now()
        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO artifacts(artifact_id,sha256,display_name,format,size,probe_json,imported_at) VALUES(?,?,?,?,?,?,?)",
                (artifact_id, digest, display_name, probe["format"], size, _json_dump(probe), imported),
            )
            db.execute(
                "INSERT INTO locations(location_id,artifact_id,source_path,stat_json,added_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(artifact_id,source_path) DO UPDATE SET stat_json=excluded.stat_json, added_at=excluded.added_at",
                (f"loc_{uuid.uuid4().hex}", artifact_id, str(path), _json_dump(signature), imported),
            )
        return self.artifact(artifact_id)

    def artifact(self, artifact_id: str) -> dict[str, Any]:
        row = self._stored_artifact(artifact_id)
        return {
            "artifact_id": row["artifact_id"],
            "sha256": row["sha256"],
            "display_name": row["display_name"],
            "format": row["format"],
            "size": row["size"],
            "probe": json.loads(row["probe_json"]),
            "imported_at": row["imported_at"],
        }

    def list_artifacts(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise AereError("invalid_limit", "Artifact list limit must be between 1 and 1000.")
        with self._connect() as db:
            rows = db.execute("SELECT * FROM artifacts ORDER BY imported_at DESC LIMIT ?", (limit,)).fetchall()
        return [
            {"artifact_id": r["artifact_id"], "sha256": r["sha256"], "display_name": r["display_name"], "format": r["format"], "size": r["size"], "imported_at": r["imported_at"]}
            for r in rows
        ]

    def _resolve_artifact_path(self, artifact_id: str) -> tuple[Path, dict[str, Any]]:
        artifact = self._stored_artifact(artifact_id)
        with self._connect() as db:
            locations = db.execute("SELECT source_path FROM locations WHERE artifact_id=? ORDER BY added_at DESC", (artifact_id,)).fetchall()
        changed: list[str] = []
        for row in locations:
            try:
                path = self._input_path(row["source_path"], expected="file")
                digest, size, _, signature = _hash_stable_file(path, int(self._limits()["max_file_bytes"]))
            except AereError as exc:
                changed.append(exc.code)
                continue
            if digest == artifact["sha256"] and size == artifact["size"]:
                return path, signature
            changed.append("digest_mismatch")
        raise AereError("artifact_changed", "No registered source location still matches the imported artifact digest.", {"artifact_id": artifact_id, "checked_locations": len(locations), "reasons": changed})

    def probe(self, artifact_id: str) -> dict[str, Any]:
        path, _ = self._resolve_artifact_path(artifact_id)
        artifact = self._stored_artifact(artifact_id)
        fileobj, _ = _regular_open(path)
        with fileobj as f:
            header = f.read(4096)
        result = probe_file(path, header, int(artifact["size"]), int(self._limits()["max_archive_members"]), int(self._limits()["max_archive_directory_bytes"]))
        self._resolve_artifact_path(artifact_id)
        result["artifact_id"] = artifact_id
        result["sha256"] = artifact["sha256"]
        return _redact_json(result)

    def inventory(self, raw_path: str | os.PathLike[str]) -> dict[str, Any]:
        path = self._input_path(raw_path)
        max_files = int(self._limits()["max_inventory_files"])
        max_total = int(self._limits()["max_inventory_bytes"])
        max_file = int(self._limits()["max_file_bytes"])
        files: list[tuple[Path, str]] = []
        skipped: list[dict[str, str]] = []
        skipped_count = 0
        max_skipped_samples = int(self._limits()["max_inventory_skip_samples"])

        def record_skip(relative_path: str, reason: str) -> None:
            nonlocal skipped_count
            skipped_count += 1
            if len(skipped) < max_skipped_samples:
                skipped.append({"path": self._redact(relative_path)[0], "reason": reason})

        truncated = False
        entries_seen = 0
        max_entries = int(self._limits()["max_inventory_entries"])
        if path.is_file():
            files.append((path, path.name))
        else:
            stack: list[Path] = [path]
            excluded = set(self.config.get("exclude_directory_names", []))
            while stack:
                current = stack.pop()
                try:
                    with os.scandir(current) as entries:
                        for entry in entries:
                            entries_seen += 1
                            if entries_seen > max_entries:
                                truncated = True
                                record_skip(current.relative_to(path).as_posix(), "inventory_entry_limit")
                                stack.clear()
                                break
                            child = Path(entry.path)
                            rel = child.relative_to(path).as_posix()
                            try:
                                if entry.is_symlink():
                                    record_skip(rel, "symlink_not_followed")
                                elif entry.is_dir(follow_symlinks=False):
                                    if entry.name not in excluded:
                                        stack.append(child)
                                elif entry.is_file(follow_symlinks=False):
                                    if len(files) >= max_files:
                                        truncated = True
                                        record_skip(rel, "file_count_limit")
                                        stack.clear()
                                        break
                                    files.append((child, rel))
                            except OSError as exc:
                                record_skip(rel, f"stat_error:{type(exc).__name__}")
                except OSError as exc:
                    record_skip(current.relative_to(path).as_posix(), f"read_error:{type(exc).__name__}")
        results: list[dict[str, Any]] = []
        total = 0
        for file_path, relative in sorted(files, key=lambda pair: pair[1].casefold()):
            try:
                declared_size = int(file_path.lstat().st_size)
                if declared_size > max_file:
                    record_skip(relative, "size_limit")
                    continue
                if total + declared_size > max_total:
                    truncated = True
                    record_skip(relative, "total_inventory_byte_limit")
                    break
                digest, size, header, _ = _hash_stable_file(file_path, max_file)
                if total + size > max_total:
                    truncated = True
                    record_skip(relative, "total_inventory_byte_limit")
                    break
                total += size
                probe = probe_file(file_path, header, size, min(int(self._limits()["max_archive_members"]), 2000), int(self._limits()["max_archive_directory_bytes"]))
                verify_digest, verify_size, _, _ = _hash_stable_file(file_path, max_file)
                if digest != verify_digest or size != verify_size:
                    raise AereError("artifact_changed", "File identity changed during inventory.")
                results.append({"relative_path": relative, "size": size, "sha256": digest, "format": probe["format"], "classification": probe["classification"]})
            except AereError as exc:
                record_skip(relative, exc.code)
            except OSError as exc:
                record_skip(relative, f"stat_error:{type(exc).__name__}")
        inventory = _redact_json({"root_name": path.name or "(root)", "files": results, "skipped": skipped, "skipped_count": skipped_count, "skipped_samples_truncated": skipped_count > len(skipped), "file_count": len(results), "total_bytes": total, "truncated": truncated, "limits": {"max_files": max_files, "max_entries": max_entries, "max_skipped_samples": max_skipped_samples, "max_total_bytes": max_total, "max_file_bytes": max_file}})
        if len(_json_dump(inventory).encode("utf-8")) > int(self._limits()["max_report_bytes"]):
            raise AereError("inventory_too_large", "Inventory result exceeds the configured response size limit.")
        return inventory

    def strings(self, artifact_id: str, min_length: int = 6, limit: int = 200) -> dict[str, Any]:
        if not 3 <= min_length <= 256:
            raise AereError("invalid_min_length", "min_length must be between 3 and 256.")
        max_limit = int(self._limits()["max_string_results"])
        if not 1 <= limit <= max_limit:
            raise AereError("invalid_limit", f"limit must be between 1 and {max_limit}.")
        path, _ = self._resolve_artifact_path(artifact_id)
        artifact_size = int(self._stored_artifact(artifact_id)["size"])
        max_bytes = int(self._limits()["max_string_scan_bytes"])
        max_string_length = int(self._limits()["max_string_length"])
        scan_target = min(artifact_size, max_bytes)
        results: list[dict[str, Any]] = []
        current = bytearray()
        current_length = 0
        start = 0
        offset = 0
        scanned = 0
        truncated = artifact_size > max_bytes

        def flush(end_offset: int) -> None:
            nonlocal current, current_length, start
            if current_length >= min_length and len(results) < limit:
                sample = current.decode("ascii", errors="replace")
                redacted, is_sensitive = self._redact(sample)
                results.append({
                    "offset": start,
                    "end_offset": end_offset,
                    "byte_length": current_length,
                    "value": redacted,
                    "sample_truncated": current_length > len(current),
                    "sample_sha256": hashlib.sha256(redacted.encode("utf-8", errors="replace")).hexdigest(),
                    "secret_like": is_sensitive,
                })
            current = bytearray()
            current_length = 0
            start = end_offset

        try:
            fileobj, _ = _regular_open(path)
            with fileobj as f:
                while scanned < scan_target:
                    block = f.read(min(64 * 1024, scan_target - scanned))
                    if not block:
                        break
                    processed = 0
                    stop_for_limit = False
                    for byte in block:
                        if byte in _ASCII_PRINTABLE:
                            if current_length == 0:
                                start = offset
                            current_length += 1
                            if len(current) < max_string_length:
                                current.append(byte)
                        else:
                            flush(offset)
                            if len(results) >= limit:
                                offset += 1
                                processed += 1
                                stop_for_limit = True
                                break
                        offset += 1
                        processed += 1
                    scanned += processed
                    if stop_for_limit:
                        truncated = offset < artifact_size
                        break
                    if processed < len(block):
                        truncated = True
                        break
            flush(offset)
            if scanned < scan_target:
                truncated = True
        except OSError as exc:
            raise AereError("read_failed", "Could not extract bounded strings from artifact.", {"reason": str(exc)}) from exc
        # Verify again to avoid returning findings for a file modified during the scan.
        self._resolve_artifact_path(artifact_id)
        result = {
            "artifact_id": artifact_id,
            "strings": results,
            "count": len(results),
            "bytes_scanned": scanned,
            "truncated": truncated or scanned < artifact_size,
            "encoding": "printable ASCII only",
            "redaction": "secret-like key/value and bearer strings redacted",
            "max_sample_length": max_string_length,
        }
        if len(_json_dump(result).encode("utf-8")) > int(self._limits()["max_report_bytes"]):
            raise AereError("response_too_large", "String results exceed the configured response size limit.")
        return result

    @staticmethod
    def _redact(value: str) -> tuple[str, bool]:
        redacted, n1 = _SECRET_ASSIGN.subn(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value)
        redacted, n2 = _BEARER.subn(lambda m: f"{m.group(1)}[REDACTED]", redacted)
        return redacted, bool(n1 or n2)

    def archive_members(self, artifact_id: str, limit: int = 1000) -> dict[str, Any]:
        max_members = int(self._limits()["max_archive_members"])
        if not 1 <= limit <= max_members:
            raise AereError("invalid_limit", f"limit must be between 1 and {max_members}.")
        path, _ = self._resolve_artifact_path(artifact_id)
        metadata = _read_zip_metadata(path, limit, int(self._limits()["max_archive_directory_bytes"]))
        members = []
        for item in metadata["members"]:
            member = dict(item)
            member["name"] = self._redact(member["name"])[0]
            members.append(member)
        self._resolve_artifact_path(artifact_id)
        result = {
            "artifact_id": artifact_id,
            "member_count": metadata["member_count"],
            "member_sample_count": metadata["member_sample_count"],
            "directory_bytes": metadata["directory_bytes"],
            "directory_bytes_examined": metadata["directory_bytes_examined"],
            "directory_bytes_limited": metadata["directory_bytes_limited"],
            "members": members,
            "truncated": metadata["truncated"],
            "limitation": metadata.get("limitation"),
            "extracted": False,
        }
        if len(_json_dump(result).encode("utf-8")) > int(self._limits()["max_report_bytes"]):
            raise AereError("response_too_large", "ZIP metadata listing exceeds the configured response size limit.")
        return result

    def create_run(self, artifact_id: str, workflow: str, provider_id: str = "builtin.triage", config: dict[str, Any] | None = None) -> dict[str, Any]:
        self._stored_artifact(artifact_id)
        if not isinstance(workflow, str) or not isinstance(provider_id, str):
            raise AereError("invalid_run_metadata", "workflow and provider_id must be strings.")
        workflow = self._redact(workflow)[0]
        provider_id = self._redact(provider_id)[0]
        if not workflow.strip() or len(workflow) > 120:
            raise AereError("invalid_workflow", "Workflow name must contain 1-120 characters.")
        if not provider_id.strip() or len(provider_id) > 200:
            raise AereError("invalid_provider_id", "provider_id must contain 1-200 characters.")
        config = _redact_json(config or {})
        if not isinstance(config, dict):
            raise AereError("invalid_run_config", "Run config must be a JSON object.")
        encoded = _json_dump(config)
        if len(encoded.encode("utf-8")) > int(self._limits()["max_evidence_json_bytes"]):
            raise AereError("payload_too_large", "Run config exceeds the configured JSON payload limit.")
        run_id = f"run_{uuid.uuid4().hex}"
        created = utc_now()
        with self._connect() as db:
            db.execute("INSERT INTO runs(run_id,artifact_id,workflow,provider_id,status,config_json,created_at) VALUES(?,?,?,?,?,?,?)", (run_id, artifact_id, workflow, provider_id, "created", encoded, created))
        return {"run_id": run_id, "artifact_id": artifact_id, "workflow": workflow, "provider_id": provider_id, "status": "created", "created_at": created}

    def _stored_run(self, run_id: str) -> sqlite3.Row:
        with self._connect() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise AereError("run_not_found", "Run ID is not present in this workspace.", {"run_id": run_id})
        return row

    def finish_run(self, run_id: str, status: str = "complete") -> dict[str, Any]:
        if not isinstance(status, str) or status not in {"complete", "partial", "failed", "cancelled"}:
            raise AereError("invalid_run_status", "Run status must be complete, partial, failed, or cancelled.")
        self._stored_run(run_id)
        finished = utc_now()
        with self._connect() as db:
            db.execute("UPDATE runs SET status=?,finished_at=? WHERE run_id=?", (status, finished, run_id))
        return {"run_id": run_id, "status": status, "finished_at": finished}

    def add_evidence(
        self,
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
        if not isinstance(kind, str) or kind not in {"observation", "inference", "hypothesis", "unknown"}:
            raise AereError("invalid_evidence_kind", "kind must be observation, inference, hypothesis, or unknown.")
        if not isinstance(claim, str) or not isinstance(source_tool, str):
            raise AereError("invalid_evidence_text", "claim and source_tool must be strings.")
        claim = self._redact(claim)[0]
        source_tool = self._redact(source_tool)[0]
        if source_version is not None and not isinstance(source_version, str):
            raise AereError("invalid_evidence_text", "source_version must be a string or null.")
        if source_version is not None:
            source_version = self._redact(source_version)[0]
        if not claim.strip() or len(claim) > 4000:
            raise AereError("invalid_claim", "Evidence claim must contain 1-4000 characters.")
        if not source_tool.strip() or len(source_tool) > 200:
            raise AereError("invalid_source_tool", "source_tool must contain 1-200 characters.")
        if confidence is not None:
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or kind not in {"inference", "hypothesis"} or not 0.0 <= float(confidence) <= 1.0:
                raise AereError("invalid_confidence", "confidence is only accepted for inference/hypothesis and must be 0..1.")
            confidence = float(confidence)
        run = self._stored_run(run_id)
        locator = {} if locator is None else locator
        data = {} if data is None else data
        supports = [] if supports is None else supports
        caveats = [] if caveats is None else caveats
        if not isinstance(locator, dict) or not isinstance(data, dict):
            raise AereError("invalid_evidence_payload", "locator and data must be JSON objects.")
        if not isinstance(supports, list) or not all(isinstance(item, str) for item in supports):
            raise AereError("invalid_evidence_payload", "supports must be a list of evidence ID strings.")
        if not isinstance(caveats, list) or not all(isinstance(item, str) for item in caveats):
            raise AereError("invalid_evidence_payload", "caveats must be a list of strings.")
        if len(supports) > 500:
            raise AereError("payload_too_large", "At most 500 supporting evidence IDs are accepted per record.")
        locator = _redact_json(locator)
        data = _redact_json(data)
        caveats = _redact_json(caveats)
        limit = int(self._limits()["max_evidence_json_bytes"])
        payload_bytes = sum(len(_json_dump(value).encode("utf-8")) for value in (locator, data, supports, caveats))
        if payload_bytes > limit:
            raise AereError("payload_too_large", "Combined evidence locator/data/support/caveat payload exceeds the configured JSON limit.", {"payload_bytes": payload_bytes, "limit": limit})
        with self._connect() as db:
            evidence_count = db.execute("SELECT COUNT(*) FROM evidence WHERE run_id=?", (run_id,)).fetchone()[0]
        if evidence_count >= int(self._limits()["max_evidence_records_per_run"]):
            raise AereError("record_limit", "Run has reached the configured evidence record limit.")
        if supports:
            with self._connect() as db:
                marks = ",".join("?" for _ in supports)
                rows = db.execute(f"SELECT evidence_id,artifact_id FROM evidence WHERE evidence_id IN ({marks})", supports).fetchall()
            if len(rows) != len(set(supports)):
                raise AereError("support_not_found", "Every supporting evidence ID must exist before it is referenced.")
            if any(r["artifact_id"] != run["artifact_id"] for r in rows):
                raise AereError("cross_artifact_support", "Cross-artifact evidence links are not supported in this workspace schema.")
        evidence_id = f"ev_{uuid.uuid4().hex}"
        created = utc_now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO evidence(evidence_id,run_id,artifact_id,kind,claim,source_tool,source_version,locator_json,data_json,supports_json,caveats_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (evidence_id, run_id, run["artifact_id"], kind, claim.strip(), source_tool, source_version, _json_dump(locator), _json_dump(data), _json_dump(supports), _json_dump(caveats), confidence, created),
            )
        return {"evidence_id": evidence_id, "run_id": run_id, "artifact_id": run["artifact_id"], "kind": kind, "claim": claim.strip(), "source_tool": source_tool, "source_version": source_version, "locator": locator, "data": data, "supports": supports, "caveats": caveats, "confidence": confidence, "created_at": created}

    def list_evidence(self, run_id: str) -> list[dict[str, Any]]:
        self._stored_run(run_id)
        result: list[dict[str, Any]] = []
        output_bytes = 2
        max_bytes = int(self._limits()["max_report_bytes"])
        with self._connect() as db:
            cursor = db.execute("SELECT * FROM evidence WHERE run_id=? ORDER BY created_at,evidence_id", (run_id,))
            for row in cursor:
                item = self._evidence_row(row)
                output_bytes += len(_json_dump(item).encode("utf-8")) + 1
                if output_bytes > max_bytes:
                    raise AereError("report_too_large", "Evidence query exceeds the configured response size limit.")
                result.append(item)
        return result

    @staticmethod
    def _evidence_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "evidence_id": row["evidence_id"],
            "run_id": row["run_id"],
            "artifact_id": row["artifact_id"],
            "kind": row["kind"],
            "claim": row["claim"],
            "source_tool": row["source_tool"],
            "source_version": row["source_version"],
            "locator": json.loads(row["locator_json"]),
            "data": json.loads(row["data_json"]),
            "supports": json.loads(row["supports_json"]),
            "caveats": json.loads(row["caveats_json"]),
            "confidence": row["confidence"],
            "created_at": row["created_at"],
        }

    def add_coverage(
        self,
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
        self._stored_run(run_id)
        allowed_statuses = {"complete", "partial", "unsupported", "not_attempted", "unknown"}
        if not isinstance(status, str) or status not in allowed_statuses:
            raise AereError("invalid_coverage_status", "Coverage status must be complete, partial, unsupported, not_attempted, or unknown.")
        text_fields = (("subject", subject, 1, 200), ("scope", scope, 1, 2000), ("provider_id", provider_id, 1, 200), ("operation_id", operation_id, 1, 200))
        for label, value, minimum, maximum in text_fields:
            if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
                raise AereError("invalid_coverage_text", f"{label} must contain {minimum}-{maximum} characters.")
        if provider_version is not None and (not isinstance(provider_version, str) or len(provider_version) > 200):
            raise AereError("invalid_coverage_text", "provider_version must be a string of at most 200 characters or null.")
        subject = self._redact(subject)[0]
        scope = self._redact(scope)[0]
        provider_id = self._redact(provider_id)[0]
        operation_id = self._redact(operation_id)[0]
        if provider_version is not None:
            provider_version = self._redact(provider_version)[0]
        for label, value in (("units_examined", units_examined), ("units_total", units_total)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise AereError("invalid_coverage_count", f"{label} must be a non-negative integer or null.")
        if units_examined is not None and units_total is not None and units_examined > units_total:
            raise AereError("invalid_coverage_count", "units_examined cannot exceed units_total.")
        excluded = [] if excluded is None else excluded
        limitations = [] if limitations is None else limitations
        notes = [] if notes is None else notes
        for label, value in (("excluded", excluded), ("limitations", limitations), ("notes", notes)):
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise AereError("invalid_coverage_payload", f"{label} must be a list of strings.")
        excluded = _redact_json(excluded)
        limitations = _redact_json(limitations)
        notes = _redact_json(notes)
        max_json = int(self._limits()["max_evidence_json_bytes"])
        payload_bytes = sum(len(_json_dump(value).encode("utf-8")) for value in (excluded, limitations, notes))
        if payload_bytes > max_json:
            raise AereError("payload_too_large", "Combined coverage exclusions/limitations/notes exceed the configured JSON limit.", {"payload_bytes": payload_bytes, "limit": max_json})
        with self._connect() as db:
            coverage_count = db.execute("SELECT COUNT(*) FROM coverage WHERE run_id=?", (run_id,)).fetchone()[0]
        if coverage_count >= int(self._limits()["max_coverage_records_per_run"]):
            raise AereError("record_limit", "Run has reached the configured coverage record limit.")
        coverage_id = f"cov_{uuid.uuid4().hex}"
        created = utc_now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO coverage(coverage_id,run_id,subject,status,scope,provider_id,provider_version,operation_id,units_examined,units_total,excluded_json,limitations_json,notes_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (coverage_id, run_id, subject.strip(), status, scope.strip(), provider_id.strip(), provider_version, operation_id.strip(), units_examined, units_total, _json_dump(excluded), _json_dump(limitations), _json_dump(notes), created),
            )
        return {
            "coverage_id": coverage_id,
            "run_id": run_id,
            "subject": subject.strip(),
            "status": status,
            "scope": scope.strip(),
            "provider_id": provider_id.strip(),
            "provider_version": provider_version,
            "operation_id": operation_id.strip(),
            "units_examined": units_examined,
            "units_total": units_total,
            "excluded": excluded,
            "limitations": limitations,
            "notes": notes,
            "created_at": created,
        }

    def list_coverage(self, run_id: str) -> list[dict[str, Any]]:
        self._stored_run(run_id)
        result: list[dict[str, Any]] = []
        output_bytes = 2
        max_bytes = int(self._limits()["max_report_bytes"])
        with self._connect() as db:
            cursor = db.execute("SELECT * FROM coverage WHERE run_id=? ORDER BY created_at,coverage_id", (run_id,))
            for row in cursor:
                item = {
                    "coverage_id": row["coverage_id"],
                    "run_id": row["run_id"],
                    "subject": row["subject"],
                    "status": row["status"],
                    "scope": row["scope"],
                    "provider_id": row["provider_id"],
                    "provider_version": row["provider_version"],
                    "operation_id": row["operation_id"],
                    "units_examined": row["units_examined"],
                    "units_total": row["units_total"],
                    "excluded": json.loads(row["excluded_json"]),
                    "limitations": json.loads(row["limitations_json"]),
                    "notes": json.loads(row["notes_json"]),
                    "created_at": row["created_at"],
                }
                output_bytes += len(_json_dump(item).encode("utf-8")) + 1
                if output_bytes > max_bytes:
                    raise AereError("report_too_large", "Coverage query exceeds the configured response size limit.")
                result.append(item)
        return result

    def export_run(self, run_id: str) -> dict[str, Any]:
        run = self._stored_run(run_id)
        artifact = self.artifact(run["artifact_id"])
        bundle = {
            "schema": "aere.evidence-bundle",
            "schema_version": 1,
            "exported_at": utc_now(),
            "artifact": artifact,
            "run": {
                "run_id": run["run_id"],
                "workflow": run["workflow"],
                "provider_id": run["provider_id"],
                "status": run["status"],
                "config": json.loads(run["config_json"]),
                "created_at": run["created_at"],
                "finished_at": run["finished_at"],
            },
            "evidence": self.list_evidence(run_id),
            "coverage": self.list_coverage(run_id),
            "export_policy": {"absolute_source_paths_included": False, "target_bytes_included": False},
        }
        sanitized = _redact_export_paths(_redact_json(bundle))
        if len(_json_dump(sanitized).encode("utf-8")) > int(self._limits()["max_report_bytes"]):
            raise AereError("report_too_large", "Evidence bundle exceeds the configured export size limit.")
        return sanitized

    def render_markdown_report(self, run_id: str) -> str:
        bundle = self.export_run(run_id)
        artifact = bundle["artifact"]
        run = bundle["run"]
        lines = [
            "# AERE evidence report",
            "",
            f"- **Artifact:** `{artifact['display_name']}`",
            f"- **SHA-256:** `{artifact['sha256']}`",
            f"- **Format candidate:** `{artifact['format']}`",
            f"- **Size:** {artifact['size']} bytes",
            f"- **Run:** `{run['run_id']}` ({run['workflow']}; provider `{run['provider_id']}`; status `{run['status']}`)",
            f"- **Created:** {run['created_at']}",
            "",
            "> This report is generated from the local evidence ledger. It does not claim original-source recovery or runtime coverage not recorded below.",
            "",
            "## Evidence",
            "",
        ]
        evidence = bundle["evidence"]
        if not evidence:
            lines.append("No evidence records are attached to this run yet.")
        for item in evidence:
            lines.extend([
                f"### {item['evidence_id']} — {item['kind']}",
                "",
                item["claim"],
                "",
                f"- **Source:** `{item['source_tool']}`" + (f" version `{item['source_version']}`" if item["source_version"] else ""),
            ])
            if item["locator"]:
                lines.append(f"- **Locator:** `{_json_dump(item['locator'])}`")
            if item["supports"]:
                lines.append(f"- **Supported by:** {', '.join(f'`{x}`' for x in item['supports'])}")
            if item["confidence"] is not None:
                lines.append(f"- **Confidence (agent-supplied):** {item['confidence']:.2f}")
            if item["caveats"]:
                lines.append("- **Caveats:** " + "; ".join(item["caveats"]))
            if item["data"]:
                lines.extend(["", "```json", json.dumps(item["data"], ensure_ascii=False, indent=2), "```"])
            lines.append("")
        lines.extend(["## Coverage", ""])
        coverage = bundle["coverage"]
        if not coverage:
            lines.append("No explicit coverage records were attached. Treat unreported areas as unknown, not as negative findings.")
        for item in coverage:
            lines.extend([
                f"### {item['subject']} — {item['status']}",
                "",
                f"- **Scope:** {item['scope']}",
                f"- **Provider / operation:** `{item['provider_id']}`" + (f" version `{item['provider_version']}`" if item["provider_version"] else "") + f" / `{item['operation_id']}`",
            ])
            if item["units_examined"] is not None or item["units_total"] is not None:
                lines.append(f"- **Units examined / total:** {item['units_examined']} / {item['units_total']}")
            if item["excluded"]:
                lines.append("- **Excluded:** " + "; ".join(item["excluded"]))
            if item["limitations"]:
                lines.append("- **Limitations:** " + "; ".join(item["limitations"]))
            if item["notes"]:
                lines.append("- **Notes:** " + "; ".join(item["notes"]))
            lines.append("")
        lines.extend(["## Export limits", "", "- Absolute local source paths are omitted.", "- Artifact bytes are not included.", "- Unsupported provider capabilities and untested runtime behavior must be recorded as unsupported, not attempted, or unknown.", ""])
        report = "\n".join(lines)
        if len(report.encode("utf-8")) > int(self._limits()["max_report_bytes"]):
            raise AereError("report_too_large", "Markdown report exceeds the configured export size limit.")
        return report

    def discover_providers(self) -> list[dict[str, Any]]:
        from .providers import catalog

        return catalog()
