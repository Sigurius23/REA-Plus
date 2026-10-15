---
Parent: "[[Automation Pipeline]]"
---
# Category Generator

**Repository path:** `scripts/build_categories.py`

Reads `resources.json`, groups records by category, and writes the generated category index and one alphabetized page per category under `categories/`.

- Regenerate after catalog edits with `python scripts/build_categories.py`.
- Verify without writing with `python scripts/build_categories.py --check`.
- The script detects category-slug collisions and produces deterministic output.

Generated pages are views, not independent sources of truth.
