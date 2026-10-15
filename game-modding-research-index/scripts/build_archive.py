#!/usr/bin/env python3
"""Build and verify a reproducible ZIP distribution of the research index."""

from __future__ import annotations

import argparse
import hashlib
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_ARCHIVE_FILES = (
    ".gitignore",
    ".github/workflows/validate.yml",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "ECOSYSTEM_COVERAGE.md",
    "README.md",
    "resources.json",
    "scripts/build_archive.py",
    "scripts/build_categories.py",
    "scripts/validate_catalog.py",
    "categories/README.md",
    "platforms/README.md",
    "platforms/android/README.md",
    "platforms/android-steam-tool-map.html",
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def archive_files() -> tuple[str, ...]:
    category_pages = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "categories").glob("*/README.md")
        if path.is_file()
    )
    return (*BASE_ARCHIVE_FILES, *category_pages)


def build(output: Path) -> tuple[int, str]:
    files = archive_files()
    category_check = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_categories.py"), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if category_check.returncode:
        detail = (category_check.stderr or category_check.stdout).strip()
        raise RuntimeError(f"category pages must be regenerated before packaging: {detail}")

    output = output.expanduser().resolve()
    source_paths = {(ROOT / relative).resolve() for relative in files}
    if output in source_paths:
        raise ValueError("archive output path must not overwrite a project source file")
    output.parent.mkdir(parents=True, exist_ok=True)

    missing = [relative for relative in files if not (ROOT / relative).is_file()]
    if missing:
        raise FileNotFoundError(f"missing files required by the archive: {', '.join(missing)}")

    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for relative in files:
            info = zipfile.ZipInfo(relative, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.extra = b""
            info.comment = b""
            archive.writestr(
                info,
                (ROOT / relative).read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )

    with zipfile.ZipFile(output, mode="r") as archive:
        names = archive.namelist()
        if names != list(files):
            raise RuntimeError(f"archive file list/order mismatch: {names!r}")
        corrupt_member = archive.testzip()
        if corrupt_member is not None:
            raise RuntimeError(f"archive integrity check failed at {corrupt_member}")
        for relative in files:
            if archive.read(relative) != (ROOT / relative).read_bytes():
                raise RuntimeError(f"archive payload does not match project file: {relative}")

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return output.stat().st_size, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT.parent / f"{ROOT.name}.zip",
        help="output ZIP path (default: a sibling archive next to the project directory)",
    )
    args = parser.parse_args()

    try:
        size, digest = build(args.output)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Archive build failed: {exc}", file=sys.stderr)
        return 1

    output = args.output.expanduser().resolve()
    print(f"Archive verified: {output}")
    print(f"Files: {len(archive_files())}")
    print(f"Size: {size} bytes")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
