from __future__ import annotations

import json
from pathlib import Path

from aere.cli import main


def test_cli_init_import_triage_and_export(tmp_path: Path, capsys):
    home = tmp_path / "aere-home"
    root = tmp_path / "approved-inputs"
    root.mkdir()
    target = root / "sample.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 24 + b"\x00hello world\x00")

    assert main(["--home", str(home), "init", "--allow-root", str(root)]) == 0
    capsys.readouterr()
    assert main(["--home", str(home), "import", str(target)]) == 0
    imported = json.loads(capsys.readouterr().out)
    artifact_id = imported["artifact_id"]

    assert main(["--home", str(home), "triage", artifact_id, "--include-strings"]) == 0
    bundle = json.loads(capsys.readouterr().out)
    assert bundle["run"]["status"] == "complete"
    assert len(bundle["evidence"]) == 2
    assert {item["status"] for item in bundle["coverage"]} >= {"complete", "not_attempted", "unsupported"}
    run_id = bundle["run"]["run_id"]

    assert main(["--home", str(home), "report", run_id, "--format", "markdown"]) == 0
    report = capsys.readouterr().out
    assert "AERE evidence report" in report
    assert "hello world" in report


def test_cli_reports_clear_json_error_for_unapproved_input(tmp_path: Path, capsys):
    workspace = tmp_path / "workspace"
    unapproved = tmp_path / "unapproved.bin"
    unapproved.write_bytes(b"x")
    assert main(["--home", str(workspace), "import", str(unapproved)]) == 2
    captured = capsys.readouterr()
    error = json.loads(captured.err)
    assert error["error"]["code"] == "outside_allowed_roots"
