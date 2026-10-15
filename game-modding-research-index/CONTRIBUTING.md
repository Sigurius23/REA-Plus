# Contributing

Suggestions and corrections are welcome. This repository is a curated link-only index; contributions should keep entries useful, concise, and verifiable. AI agents working on the catalog should follow the repository's [AGENTS.md](AGENTS.md) catalog and tool-selection guidance.

## Adding or updating a resource

1. Prefer the project's canonical upstream repository or official documentation URL.
2. Add the resource to `resources.json` and the user-facing `README.md`; keep the entry's role and technical scope clear.
3. Regenerate the category folders with `python scripts/build_categories.py`. These pages are generated from the JSON catalog and should not be edited directly.
4. Keep JSON fields consistent with the existing catalog: `id`, `name`, `url`, `category`, `summary`, and `tags`.
5. Describe documented project support, maintenance status, license, and compatibility. Link to upstream material, note uncertainty where present, and label archived or otherwise inactive projects as historical.
6. Treat game-version, loader, and AI-provider details as volatile. Add a review date when a status claim materially affects whether a resource is useful.
7. Keep the repository link-only: do not copy upstream source code, vendor projects, or use submodules.
8. Platform notes under `platforms/` are hand-maintained technical summaries. Keep them aligned with the matching row in `ECOSYSTEM_COVERAGE.md`, and do not infer general support from a title-integrated UGC service.

## Checks

After editing the catalog, regenerate the category folders and run the dependency-free validator before opening a pull request:

```sh
python scripts/build_categories.py
python scripts/validate_catalog.py
git diff --check
```

The validator checks the catalog structure, unique IDs and URLs, required fields, README URL parity, generated category-page parity, text whitespace, catalog snapshot count, and the finite game/engine crosswalk dispositions. It also checks the Android/Steam HTML map for duplicate IDs, broken local file references, and local fragment targets. If intentionally changing the finite checklist or catalog schema version, update the validator's explicit guards and audit documentation in the same change.

Build and verify the standard project archive with:

```sh
python scripts/build_archive.py
```

By default, the ZIP is written next to the project directory; use `--output PATH` to choose another location. The builder fixes archive ordering and timestamps, then checks ZIP integrity and byte-for-byte parity with the included project files.

Keep the README and JSON catalog in sync. Summaries should be original descriptions, not copied blocks from project documentation.
