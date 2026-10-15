#!/usr/bin/env python3
"""Generate one browsable Markdown page per catalog category."""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "resources.json"
CATEGORY_ROOT = ROOT / "categories"


def category_slug(category: str) -> str:
    value = category.casefold().replace(".net", "dotnet").replace("&", " and ")
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    if not value:
        raise ValueError(f"category has no characters suitable for a folder name: {category!r}")
    return value


def escape_link_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def render_pages() -> dict[Path, str]:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    grouped: dict[str, list[dict]] = defaultdict(list)
    for resource in data["resources"]:
        grouped[resource["category"]].append(resource)

    slugs: dict[str, str] = {}
    for category in grouped:
        slug = category_slug(category)
        if slug in slugs:
            raise ValueError(
                f"category folder slug collision: {category!r} and {slugs[slug]!r} -> {slug!r}"
            )
        slugs[slug] = category

    pages: dict[Path, str] = {}
    category_rows: list[str] = []
    categories = sorted(grouped, key=str.casefold)

    for category in categories:
        slug = category_slug(category)
        resources = sorted(
            grouped[category], key=lambda resource: (resource["name"].casefold(), resource["id"])
        )
        category_rows.append(
            f"- [{category}]({slug}/README.md) — {len(resources)} resources"
        )

        lines = [
            f"# {category}",
            "",
            "<!-- Generated from resources.json by scripts/build_categories.py; edit the catalog, not this file. -->",
            "",
            f"**{len(resources)} resources.** [Category index](../README.md) · [Main README](../../README.md) · [JSON catalog](../../resources.json)",
            "",
        ]
        for resource in resources:
            name = escape_link_label(resource["name"])
            url = resource["url"].replace(" ", "%20").replace("<", "%3C").replace(">", "%3E")
            summary = " ".join(resource["summary"].split())
            lines.append(f"- **[{name}](<{url}>)** — {summary}")
            if resource["tags"]:
                lines.append(f"  - Tags: {', '.join(resource['tags'])}")
        lines.append("")
        pages[Path("categories") / slug / "README.md"] = "\n".join(lines)

    index_lines = [
        "# Browse by category",
        "",
        "<!-- Generated from resources.json by scripts/build_categories.py. -->",
        "",
        f"This directory groups all {len(data['resources'])} catalog records into {len(categories)} categories. Each category page is alphabetized by resource name; `resources.json` remains the canonical data source.",
        "",
        *category_rows,
        "",
    ]
    pages[Path("categories") / "README.md"] = "\n".join(index_lines)
    return pages


def write_pages(pages: dict[Path, str]) -> None:
    expected = set(pages)
    existing = {
        path.relative_to(ROOT)
        for path in CATEGORY_ROOT.rglob("README.md")
        if path.is_file()
    } if CATEGORY_ROOT.exists() else set()

    for stale in sorted(existing - expected, key=lambda path: path.as_posix()):
        stale_path = ROOT / stale
        stale_path.unlink()
        parent = stale_path.parent
        while parent != CATEGORY_ROOT and parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent

    for relative, content in pages.items():
        path = ROOT / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    for directory in sorted(CATEGORY_ROOT.glob("*/"), key=lambda path: path.as_posix()):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()


def check_pages(pages: dict[Path, str]) -> list[str]:
    expected = set(pages)
    existing = {
        path.relative_to(ROOT)
        for path in CATEGORY_ROOT.rglob("README.md")
        if path.is_file()
    } if CATEGORY_ROOT.exists() else set()
    issues: list[str] = []

    for relative in sorted(expected - existing, key=lambda path: path.as_posix()):
        issues.append(f"missing generated page: {relative.as_posix()}")
    for relative in sorted(existing - expected, key=lambda path: path.as_posix()):
        issues.append(f"stale generated page: {relative.as_posix()}")
    for relative in sorted(expected & existing, key=lambda path: path.as_posix()):
        actual = (ROOT / relative).read_text(encoding="utf-8")
        if actual != pages[relative]:
            issues.append(f"out-of-date generated page: {relative.as_posix()}")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="check generated pages without writing them",
    )
    args = parser.parse_args()

    try:
        pages = render_pages()
        if args.check:
            issues = check_pages(pages)
            if issues:
                print("Category pages are not up to date:", file=sys.stderr)
                for issue in issues:
                    print(f"- {issue}", file=sys.stderr)
                print("Run `python scripts/build_categories.py` to regenerate them.", file=sys.stderr)
                return 1
            print(f"Category pages are up to date: {len(pages) - 1} categories.")
        else:
            write_pages(pages)
            index = (ROOT / "categories/README.md").read_text(encoding="utf-8")
            match = re.search(r"all (\d+) catalog records", index)
            record_count = match.group(1) if match else "an unknown number of"
            print(f"Generated {len(pages) - 1} category folders covering {record_count} records.")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Category generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
