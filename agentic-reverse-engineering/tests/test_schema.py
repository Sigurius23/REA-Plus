from __future__ import annotations

import json
from pathlib import Path

import pytest

from aere.core import Workspace


def test_export_validates_against_versioned_json_schema(tmp_path: Path):
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "evidence-bundle.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    root = tmp_path / "inputs"
    root.mkdir()
    target = root / "fixture.bin"
    target.write_bytes(b"fixture")
    workspace = Workspace(tmp_path / "workspace")
    workspace.allow_root(root)
    artifact = workspace.import_file(target)
    run = workspace.create_run(artifact["artifact_id"], "schema-test")
    workspace.add_evidence(run["run_id"], "observation", "Synthetic fixture imported.", "test", source_version="1")
    workspace.add_coverage(run["run_id"], "format probe", "complete", "Fixed signatures only.", "aere.builtin.probe", "probe", provider_version="0.2.0")
    workspace.finish_run(run["run_id"])

    jsonschema.validate(workspace.export_run(run["run_id"]), schema, format_checker=jsonschema.FormatChecker())
