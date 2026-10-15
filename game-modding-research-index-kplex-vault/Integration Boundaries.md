---
Parent: "[[Repository Overview]]"
---
# Integration Boundaries

## Android/Steam map is now packaged and checked

`platforms/android-steam-tool-map.html` is included in `scripts/build_archive.py` → `BASE_ARCHIVE_FILES` and in `scripts/validate_catalog.py` → `TEXT_FILES_TO_CHECK`. The dependency-free validator checks its UTF-8/text hygiene, duplicate IDs, local file targets, and local fragment targets. It does not fetch external links or syntax-check embedded JavaScript.

The map also has an adjacent, explicitly non-analyzer aria2 reference. That map-only mention is not a separate record in the canonical `resources.json` catalog.

## Separate K-Plex vault boundary

This vault lives at `/home/user/game-modding-research-index-kplex-vault`, outside `/home/user/game-modding-research-index`. It contains architecture notes and 21 category-group notes with K-Plex relationship metadata; it does not copy source code or individual catalog records and is not part of the project's ZIP or CI.
