---
Parent: "[[Automation Pipeline]]"
---
# Reproducible Archive Builder

**Repository path:** `scripts/build_archive.py`

Builds a ZIP from an explicit base-file allowlist plus the sorted generated category pages. The script fixes ZIP timestamps and file metadata, checks that generated pages are fresh, then verifies the member list/order and archive contents.

The allowlist now includes `platforms/android-steam-tool-map.html`. This remains a curated distribution, not a recursive copy of the repository; the separate K-Plex vault is outside it. See [[Integration Boundaries]].
