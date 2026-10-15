from __future__ import annotations

from dataclasses import dataclass

import pytest

from aere.provider_api import (
    CoverageReport,
    EvidenceDraft,
    ProviderManifest,
    ProviderOperation,
    ProviderRegistry,
    ProviderRequest,
    ProviderResult,
)


DIGEST = "a" * 64


@dataclass
class FakeProvider:
    manifest: ProviderManifest

    def analyze(self, request: ProviderRequest) -> ProviderResult:
        return ProviderResult(
            artifact_id=request.artifact_id,
            sha256=request.sha256,
            provider_id=self.manifest.provider_id,
            provider_version=self.manifest.version,
            operation_id=request.operation_id,
            status="complete",
            coverage=(CoverageReport("function list", "complete", "All emitted function records."),),
            evidence=(EvidenceDraft("observation", "Provider emitted one function record.", self.manifest.provider_id),),
        )


def test_registry_binds_provider_result_to_request_and_manifest():
    manifest = ProviderManifest(
        "test.provider",
        "Test provider",
        "1.2.3",
        "experimental",
        (ProviderOperation("functions", "List functions", "read_local", ("ELF",)),),
    )
    provider = FakeProvider(manifest)
    registry = ProviderRegistry()
    registry.register(provider)
    request = ProviderRequest(f"sha256:{DIGEST}", DIGEST, "functions")
    result = provider.analyze(request)

    registry.validate_result(request, result)

    mismatched = ProviderResult(
        artifact_id=request.artifact_id,
        sha256="b" * 64,
        provider_id=manifest.provider_id,
        provider_version=manifest.version,
        operation_id=request.operation_id,
        status="complete",
        coverage=(CoverageReport("function list", "complete", "All emitted function records."),),
    )
    with pytest.raises(ValueError, match="artifact identity"):
        registry.validate_result(request, mismatched)


def test_provider_contract_rejects_duplicate_operations_and_unsafe_runtime_defaults():
    operation = ProviderOperation("analyze", "Analyze", "read_local")
    with pytest.raises(ValueError, match="unique"):
        ProviderManifest("dup", "Duplicate", "1", "experimental", (operation, operation))
    with pytest.raises(ValueError, match="explicit opt-in"):
        ProviderOperation("observe", "Observe owned process", "observe_owned_process")


def test_provider_request_requires_matching_sha256_identity():
    with pytest.raises(ValueError, match="differ"):
        ProviderRequest(f"sha256:{DIGEST}", "b" * 64, "functions")
