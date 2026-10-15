from __future__ import annotations

from pathlib import Path

from aere.providers import catalog


def test_path_presence_is_not_reported_as_a_connected_or_verified_adapter(tmp_path: Path, monkeypatch):
    discovered = tmp_path / "gdb-placeholder"
    discovered.write_text("not an executable or analyzer", encoding="utf-8")
    monkeypatch.setenv("AERE_TOOL_GDB", str(discovered))

    item = next(provider for provider in catalog() if provider["id"] == "tool.gdb")

    assert item["status"] == "discovered-not-integrated"
    assert item["present_on_path"] is True
    assert item["adapter_connected"] is False
    assert item["verified"] is False


def test_android_and_steam_builtin_parsers_are_advertised_as_implemented():
    providers = {item["id"]: item for item in catalog()}
    assert providers["builtin.android.apk"]["status"] == "implemented"
    assert "DEX identifier tables" in " ".join(providers["builtin.android.apk"]["capabilities"])
    assert providers["builtin.steam.install"]["status"] == "implemented"
    assert "VPK" in " ".join(providers["builtin.steam.install"]["capabilities"])
