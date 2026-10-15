---
Parent: "[[Automation Pipeline]]"
---
# Validator and CI

**Repository paths:** `scripts/validate_catalog.py` and `.github/workflows/validate.yml`

The dependency-free validator checks the catalog schema and record fields, identifiers and URLs, README/catalog URL parity, generated category output, the finite coverage crosswalk, and text-file hygiene for its declared file list.

The Android/Steam HTML map is in `TEXT_FILES_TO_CHECK`. A standard-library HTML parser also checks duplicate IDs, local `href`/`src` file targets, and local fragment targets. It does not make network requests or syntax-check the embedded JavaScript.

The GitHub Actions workflow runs on pushes, pull requests, and manual dispatch. It uses Python 3.12, runs the validator, then asks the archive builder to produce a ZIP under the runner’s temporary directory.
