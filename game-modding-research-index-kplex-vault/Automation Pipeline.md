---
Children:
  - "[[Category Generator]]"
  - "[[Validator and CI]]"
  - "[[Reproducible Archive Builder]]"
Parent: "[[Repository Overview]]"
---
# Automation Pipeline

The `scripts/` directory contains three small Python utilities:

1. `build_categories.py` renders category pages from the canonical JSON.
2. `validate_catalog.py` checks catalog/document consistency and the HTML map's local links and IDs.
3. `build_archive.py` creates and verifies the fixed-file-list ZIP distribution, including the standalone Android/Steam map.

The GitHub Actions workflow runs the validator, then builds the archive. The archive builder also runs the category generator in `--check` mode before packaging.
