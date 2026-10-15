from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

from aere.core import AereError, Workspace


@pytest.fixture()
def sandbox(tmp_path: Path):
    root = tmp_path / "inputs"
    root.mkdir()
    home = tmp_path / "workspace"
    workspace = Workspace(home)
    workspace.allow_root(root)
    return workspace, root, home


def test_import_hashes_file_and_does_not_copy_it(sandbox):
    workspace, root, home = sandbox
    source = root / "sample.bin"
    source.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40)

    artifact = workspace.import_file(source)

    assert artifact["artifact_id"] == f"sha256:{artifact['sha256']}"
    assert artifact["format"] == "elf"
    assert artifact["probe"]["details"]["class_bits"] == 64
    assert not (home / "artifacts").exists()
    assert str(source) not in json.dumps(artifact)


@pytest.mark.parametrize(
    ("filename", "payload", "expected"),
    [
        ("sample.wasm", b"\x00asm\x01\x00\x00\x00", "wasm"),
        ("sample.macho", b"\xcf\xfa\xed\xfe" + b"\x00" * 32, "macho"),
        ("sample.exe", b"MZ" + b"\x00" * 62, "pe_candidate"),
    ],
)
def test_signature_candidates_are_explicitly_conservative(sandbox, filename, payload, expected):
    workspace, root, _ = sandbox
    source = root / filename
    source.write_bytes(payload)
    artifact = workspace.import_file(source)
    assert artifact["format"] == expected


def test_apk_zip_candidate_is_not_decoded(sandbox):
    workspace, root, _ = sandbox
    source = root / "synthetic.apk"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic bytes")
        archive.writestr("classes.dex", b"not real DEX")
    artifact = workspace.import_file(source)
    assert artifact["format"] == "apk"
    assert artifact["probe"]["classification"] == "signature_or_extension_candidate"
    assert workspace.archive_members(artifact["artifact_id"])["member_count"] == 2


def test_input_must_be_inside_approved_root(sandbox, tmp_path):
    workspace, _, _ = sandbox
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"data")
    with pytest.raises(AereError, match="outside every configured allowed root"):
        workspace.import_file(outside)


def test_symlink_input_is_rejected(sandbox):
    workspace, root, _ = sandbox
    actual = root / "real.bin"
    actual.write_bytes(b"data")
    link = root / "alias.bin"
    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(AereError) as error:
        workspace.import_file(link)
    assert error.value.code == "symlink_rejected"


def test_registered_artifact_fails_closed_after_mutation(sandbox):
    workspace, root, _ = sandbox
    source = root / "change.bin"
    source.write_bytes(b"original data")
    artifact = workspace.import_file(source)
    source.write_bytes(b"changed data!")
    with pytest.raises(AereError) as error:
        workspace.probe(artifact["artifact_id"])
    assert error.value.code == "artifact_changed"


def test_inventory_entry_limit_bounds_directory_walk(sandbox):
    workspace, root, _ = sandbox
    workspace.config["limits"]["max_inventory_entries"] = 2
    workspace._write_config(workspace.config)
    workspace.config = workspace._load_config()
    for name in ("a.bin", "b.bin", "c.bin", "d.bin"):
        (root / name).write_bytes(b"x")

    result = workspace.inventory(root)

    assert result["truncated"] is True
    assert result["limits"]["max_entries"] == 2
    assert result["file_count"] <= 2


def test_string_scan_has_offsets_and_redacts_secret_like_values(sandbox):
    workspace, root, _ = sandbox
    source = root / "strings.bin"
    payload = b"\x00api_key=THIS_IS_A_SECRET_VALUE\x00hello world\x00"
    source.write_bytes(payload)
    artifact = workspace.import_file(source)

    found = workspace.strings(artifact["artifact_id"], min_length=6, limit=10)

    assert found["bytes_scanned"] == len(payload)
    assert found["truncated"] is False
    assert found["strings"][0]["offset"] == 1
    assert found["strings"][0]["secret_like"] is True
    assert "THIS_IS_A_SECRET_VALUE" not in json.dumps(found)
    assert found["strings"][0]["value"] == "api_key=[REDACTED]"
    assert found["strings"][1]["value"] == "hello world"


def test_string_scan_bounds_sample_and_scan(sandbox):
    workspace, root, _ = sandbox
    workspace.config["limits"]["max_string_scan_bytes"] = 64
    workspace.config["limits"]["max_string_length"] = 8
    workspace._write_config(workspace.config)
    workspace.config = workspace._load_config()
    source = root / "long.bin"
    source.write_bytes(b"A" * 200)
    artifact = workspace.import_file(source)

    found = workspace.strings(artifact["artifact_id"], min_length=3, limit=5)

    assert found["bytes_scanned"] == 64
    assert found["truncated"] is True
    assert found["strings"][0]["byte_length"] == 64
    assert found["strings"][0]["sample_truncated"] is True
    assert len(found["strings"][0]["value"]) == 8


def test_zip_members_are_listed_without_extraction_and_flag_unsafe_paths(sandbox):
    workspace, root, _ = sandbox
    archive_path = root / "sample.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("folder/readme.txt", "hello")
        archive.writestr("../outside.txt", "should not be extracted")
    artifact = workspace.import_file(archive_path)

    result = workspace.archive_members(artifact["artifact_id"])

    assert result["member_count"] == 2
    assert result["extracted"] is False
    assert [item["unsafe_path"] for item in result["members"]] == [False, True]
    assert result["members"][0]["size"] == 5
    assert result["members"][0]["compressed_size"] == 5
    assert not (root.parent / "outside.txt").exists()


def test_zip_central_directory_byte_limit_is_enforced(sandbox):
    workspace, root, _ = sandbox
    workspace.config["limits"]["max_archive_directory_bytes"] = 1
    workspace._write_config(workspace.config)
    workspace.config = workspace._load_config()
    archive_path = root / "limited.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "1")
        archive.writestr("two.txt", "2")
    artifact = workspace.import_file(archive_path)

    probe = workspace.probe(artifact["artifact_id"])
    listing = workspace.archive_members(artifact["artifact_id"], limit=10)

    assert probe["format"] == "zip"
    assert probe["details"]["directory_bytes_limited"] is True
    assert listing["directory_bytes_limited"] is True
    assert listing["members"] == []
    assert listing["truncated"] is True


def test_inventory_skips_symlinks_and_reports_candidates(sandbox):
    workspace, root, _ = sandbox
    (root / "native.bin").write_bytes(b"\x7fELF" + b"\x00" * 24)
    (root / "sub").mkdir()
    (root / "sub" / "readme.txt").write_text("not a binary", encoding="utf-8")
    link = root / "linked.bin"
    try:
        link.symlink_to(root / "native.bin")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")

    result = workspace.inventory(root)

    assert result["file_count"] == 2
    assert {item["format"] for item in result["files"]} == {"elf", "unknown"}
    assert {item["reason"] for item in result["skipped"]} == {"symlink_not_followed"}


def test_evidence_support_and_report_provenance(sandbox):
    workspace, root, _ = sandbox
    source = root / "app.bin"
    source.write_bytes(b"\x7fELF" + b"\x00" * 32)
    artifact = workspace.import_file(source)
    run = workspace.create_run(artifact["artifact_id"], "native-static-triage", "builtin.probe", {"mode": "read-only"})
    observation = workspace.add_evidence(
        run["run_id"],
        "observation",
        "The first four bytes match the ELF magic value.",
        "aere.builtin.probe",
        "0.2.0",
        {"offset": 0},
        {"magic_hex": "7f454c46"},
        caveats=["A magic value does not prove the file is valid or executable."],
    )
    inference = workspace.add_evidence(
        run["run_id"],
        "inference",
        "The file is likely an ELF-family artifact.",
        "agent",
        supports=[observation["evidence_id"]],
        confidence=0.8,
    )
    workspace.finish_run(run["run_id"])

    bundle = workspace.export_run(run["run_id"])
    report = workspace.render_markdown_report(run["run_id"])

    assert len(bundle["evidence"]) == 2
    assert inference["supports"] == [observation["evidence_id"]]
    assert str(source) not in json.dumps(bundle)
    assert str(source) not in report
    assert observation["evidence_id"] in report
    assert "does not claim original-source recovery" in report


def test_coverage_is_structured_and_reported_without_overclaiming(sandbox):
    workspace, root, _ = sandbox
    source = root / "partial.bin"
    source.write_bytes(b"x" * 80)
    artifact = workspace.import_file(source)
    run = workspace.create_run(artifact["artifact_id"], "bounded-test")
    coverage = workspace.add_coverage(
        run["run_id"],
        subject="Printable strings",
        status="partial",
        scope="Offsets 0-63 only; printable ASCII and result count limits apply.",
        provider_id="aere.builtin.strings.ascii",
        operation_id="extract",
        units_examined=64,
        units_total=80,
        limitations=["UTF-16 and compressed data were not scanned."],
    )

    bundle = workspace.export_run(run["run_id"])
    report = workspace.render_markdown_report(run["run_id"])

    assert bundle["coverage"][0]["coverage_id"] == coverage["coverage_id"]
    assert bundle["coverage"][0]["status"] == "partial"
    assert "64 / 80" in report
    assert "No explicit coverage records" not in report


def test_coverage_rejects_impossible_counts(sandbox):
    workspace, root, _ = sandbox
    source = root / "counts.bin"
    source.write_bytes(b"x")
    artifact = workspace.import_file(source)
    run = workspace.create_run(artifact["artifact_id"], "coverage-test")
    with pytest.raises(AereError) as error:
        workspace.add_coverage(run["run_id"], "scope", "partial", "narrow", "provider", "op", 2, 1)
    assert error.value.code == "invalid_coverage_count"


def test_evidence_rejects_cross_artifact_support(sandbox):
    workspace, root, _ = sandbox
    a = root / "a.bin"
    b = root / "b.bin"
    a.write_bytes(b"a")
    b.write_bytes(b"b")
    first = workspace.import_file(a)
    second = workspace.import_file(b)
    run_a = workspace.create_run(first["artifact_id"], "test")
    run_b = workspace.create_run(second["artifact_id"], "test")
    evidence_a = workspace.add_evidence(run_a["run_id"], "observation", "A", "test")
    with pytest.raises(AereError) as error:
        workspace.add_evidence(run_b["run_id"], "inference", "B", "agent", supports=[evidence_a["evidence_id"]], confidence=0.5)
    assert error.value.code == "cross_artifact_support"


def test_evidence_and_export_redact_obvious_secrets(sandbox):
    workspace, root, _ = sandbox
    source = root / "secret.bin"
    source.write_bytes(b"sample")
    artifact = workspace.import_file(source)
    run = workspace.create_run(artifact["artifact_id"], "secret=never-export-this", config={"api_key": "run-secret-value"})
    evidence = workspace.add_evidence(
        run["run_id"],
        "observation",
        "Observed bearer: Bearer abcdefghijklmnop123456",
        "test-tool",
        data={"password": "do-not-export", "text": "token=another-secret", "local_path": str(source), "windows_path": r"C:\Users\researcher\app.exe", "url": "https://example.org/path", "image_data_uri": "data:image/png;base64,/not-a-local-path=="}, 
    )

    bundle = workspace.export_run(run["run_id"])
    serialized = json.dumps(bundle)

    assert "never-export-this" not in serialized
    assert "run-secret-value" not in serialized
    assert "do-not-export" not in serialized
    assert "another-secret" not in serialized
    assert "abcdefghijklmnop123456" not in serialized
    assert str(source) not in serialized
    assert r"C:\Users\researcher\app.exe" not in serialized
    assert "[LOCAL_PATH]" in serialized
    assert "https://example.org/path" in serialized
    assert "data:image/png;base64,/not-a-local-path==" in serialized
    assert evidence["data"]["password"] == "[REDACTED]"


def test_config_rejects_nonpositive_limits(tmp_path):
    home = tmp_path / "workspace"
    ws = Workspace(home)
    config = json.loads((home / "config.json").read_text(encoding="utf-8"))
    config["limits"]["max_file_bytes"] = 0
    (home / "config.json").write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(AereError) as error:
        Workspace(home)
    assert error.value.code == "config_invalid"


def test_archive_limit_is_enforced(sandbox):
    workspace, root, _ = sandbox
    archive_path = root / "many.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "1")
        archive.writestr("two.txt", "2")
    artifact = workspace.import_file(archive_path)
    result = workspace.archive_members(artifact["artifact_id"], limit=1)
    assert result["member_count"] == 2
    assert result["truncated"] is True
    assert len(result["members"]) == 1
