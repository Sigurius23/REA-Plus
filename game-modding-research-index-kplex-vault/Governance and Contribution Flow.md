---
Parent: "[[Repository Overview]]"
---
# Governance and Contribution Flow

**Repository paths:** `AGENTS.md` and `CONTRIBUTING.md`

These documents define the working and contribution rules for a link-only catalog. The project records and describes external resources; it does not vendor their source code or use submodules. Tool roles and compatibility claims should remain factual and bounded to the evidence for the relevant title, release, store, platform, or runtime.

Typical catalog flow:

1. Edit or add the resource record in `resources.json`.
2. Regenerate `categories/` with `scripts/build_categories.py`.
3. Update the hand-maintained README or coverage/platform documentation only when its contents need to change.
4. Run `scripts/validate_catalog.py` and `scripts/build_archive.py`.

The platform notes and HTML decision map are maintained separately from the JSON-generated pages.
