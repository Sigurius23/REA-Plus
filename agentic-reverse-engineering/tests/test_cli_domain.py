from __future__ import annotations

import json
from pathlib import Path

from aere.cli import main
from .test_android import _apk
from .test_steam import _steam_fixture


def test_cli_android_inspect_and_offline_report(tmp_path: Path, capsys):
    home = tmp_path / "workspace"
    root = tmp_path / "inputs"
    root.mkdir()
    apk = root / "sample.apk"
    _apk(apk)
    assert main(["--home", str(home), "init", "--allow-root", str(root)]) == 0
    capsys.readouterr()
    assert main(["--home", str(home), "import", str(apk)]) == 0
    artifact = json.loads(capsys.readouterr().out)

    assert main(["--home", str(home), "android", "inspect", artifact["artifact_id"]]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["manifest"]["package"] == "com.example.game"
    assert inspected["run_id"]

    out = tmp_path / "reports" / "android.html"
    out.parent.mkdir()
    assert main(["--home", str(home), "android", "report", artifact["artifact_id"], "--out", str(out)]) == 0
    written = json.loads(capsys.readouterr().out)
    assert written["format"] == "html"
    assert out.exists()
    assert "data:image/png;base64," in out.read_text(encoding="utf-8")


def test_cli_steam_inspect_and_offline_report(tmp_path: Path, capsys):
    workspace, game, _ = _steam_fixture(tmp_path)
    home = workspace.home

    assert main(["--home", str(home), "steam", "inspect", str(game)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["steam_manifest"]["appid"] == "12345"
    assert result["run_id"]

    out = tmp_path / "reports" / "steam.html"
    out.parent.mkdir()
    assert main(["--home", str(home), "steam", "report", str(game), "--out", str(out)]) == 0
    written = json.loads(capsys.readouterr().out)
    assert written["format"] == "html"
    assert out.exists()
    report = out.read_text(encoding="utf-8")
    assert "Source/Source 2" in report
    assert "data:image/png;base64," in report
    assert str(tmp_path) not in report
