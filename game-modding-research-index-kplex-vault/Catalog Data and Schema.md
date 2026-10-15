---
Parent: "[[Repository Overview]]"
---
# Catalog Data and Schema

**Repository path:** `resources.json`

This is the single canonical data source for the curated resource index. Its top-level fields are `schema_version`, `last_reviewed`, and `resources`. The current schema is version `1`; each resource record has `id`, `name`, `url`, `category`, `summary`, and `tags`.

## Current snapshot

- **384** records
- **21** distinct categories
- **Last reviewed:** `2026-10-11`
- **Content model:** external links plus curated descriptions and tags; no vendored project source code or submodules

The 2026-10-11 update added ELDEN RING Combat Rewrite and Faith Runner under `Reference projects (not tools)`. The category pages are generated views of this data. Changes to a catalog entry belong in `resources.json`, not in generated Markdown. The main README is hand-maintained; the validator checks its resource-URL parity against the catalog.

The K-Plex vault represents all 21 categories as group notes and does **not** create a note for every resource.
