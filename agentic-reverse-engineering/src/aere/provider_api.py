"""Typed contracts for explicitly registered external analysis adapters.

AERE v0.2 ships no third-party analyzer adapter. This module defines the
versioned data boundary future adapters must satisfy; it does not discover,
import, or execute provider code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Effect = Literal["read_local", "analyze_copy", "observe_owned_process"]
ProviderStatus = Literal["verified", "experimental", "unavailable"]
CoverageStatus = Literal["complete", "partial", "unsupported", "not_attempted", "unknown"]
EvidenceKind = Literal["observation", "inference", "hypothesis", "unknown"]
ResultStatus = Literal["complete", "partial", "failed", "cancelled"]

_EFFECTS = {"read_local", "analyze_copy", "observe_owned_process"}
_PROVIDER_STATUSES = {"verified", "experimental", "unavailable"}
_COVERAGE_STATUSES = {"complete", "partial", "unsupported", "not_attempted", "unknown"}
_EVIDENCE_KINDS = {"observation", "inference", "hypothesis", "unknown"}
_RESULT_STATUSES = {"complete", "partial", "failed", "cancelled"}


@dataclass(frozen=True)
class ProviderOperation:
    operation_id: str
    description: str
    effect: Effect
    supported_formats: tuple[str, ...] = ()
    supported_architectures: tuple[str, ...] = ()
    timeout_seconds: int = 120
    max_output_bytes: int = 1_048_576
    requires_explicit_opt_in: bool = False

    def __post_init__(self) -> None:
        if not self.operation_id or len(self.operation_id) > 100:
            raise ValueError("operation_id must contain 1-100 characters")
        if self.effect not in _EFFECTS:
            raise ValueError(f"unsupported effect: {self.effect}")
        if not 1 <= self.timeout_seconds <= 86_400:
            raise ValueError("timeout_seconds must be in 1..86400")
        if not 1 <= self.max_output_bytes <= 1_073_741_824:
            raise ValueError("max_output_bytes must be in 1..1073741824")
        if self.effect == "observe_owned_process" and not self.requires_explicit_opt_in:
            raise ValueError("observe_owned_process operations require explicit opt-in")


@dataclass(frozen=True)
class ProviderManifest:
    provider_id: str
    name: str
    version: str
    status: ProviderStatus
    operations: tuple[ProviderOperation, ...]
    upstream: str | None = None
    host_constraints: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.provider_id or len(self.provider_id) > 200:
            raise ValueError("provider_id must contain 1-200 characters")
        if not self.name or not self.version:
            raise ValueError("provider name and version are required")
        if self.status not in _PROVIDER_STATUSES:
            raise ValueError(f"unsupported provider status: {self.status}")
        operation_ids = [operation.operation_id for operation in self.operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("operation IDs must be unique within a provider")


@dataclass(frozen=True)
class ProviderRequest:
    artifact_id: str
    sha256: str
    operation_id: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.artifact_id.startswith("sha256:"):
            raise ValueError("artifact_id must be a sha256:<digest> identity")
        digest = self.artifact_id.removeprefix("sha256:")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError("artifact_id must contain a 64-hex SHA-256 digest")
        if digest.lower() != self.sha256.lower():
            raise ValueError("artifact_id digest and sha256 field differ")
        if not self.operation_id:
            raise ValueError("operation_id is required")


@dataclass(frozen=True)
class CoverageReport:
    subject: str
    status: CoverageStatus
    scope: str
    units_examined: int | None = None
    units_total: int | None = None
    excluded: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in _COVERAGE_STATUSES:
            raise ValueError(f"unsupported coverage status: {self.status}")
        if not self.subject.strip() or not self.scope.strip():
            raise ValueError("coverage subject and scope are required")
        for label, value in (("units_examined", self.units_examined), ("units_total", self.units_total)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{label} must be a non-negative integer or None")
        if self.units_examined is not None and self.units_total is not None and self.units_examined > self.units_total:
            raise ValueError("units_examined cannot exceed units_total")


@dataclass(frozen=True)
class EvidenceDraft:
    kind: EvidenceKind
    claim: str
    source_tool: str
    locator: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    supports: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()
    confidence: float | None = None

    def __post_init__(self) -> None:
        if self.kind not in _EVIDENCE_KINDS:
            raise ValueError(f"unsupported evidence kind: {self.kind}")
        if not self.claim.strip() or not self.source_tool.strip():
            raise ValueError("claim and source_tool are required")
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or self.kind not in {"inference", "hypothesis"} or not 0.0 <= float(self.confidence) <= 1.0:
                raise ValueError("confidence is only valid for inference/hypothesis and must be 0..1")


@dataclass(frozen=True)
class ProviderResult:
    artifact_id: str
    sha256: str
    provider_id: str
    provider_version: str
    operation_id: str
    status: ResultStatus
    coverage: tuple[CoverageReport, ...] = ()
    evidence: tuple[EvidenceDraft, ...] = ()
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in _RESULT_STATUSES:
            raise ValueError(f"unsupported result status: {self.status}")
        if not self.provider_id or not self.provider_version or not self.operation_id:
            raise ValueError("provider_id, provider_version, and operation_id are required")
        if self.status == "complete" and self.errors:
            raise ValueError("a complete result cannot include errors; use partial or failed")
        if self.status in {"complete", "partial"} and not self.coverage:
            raise ValueError("complete/partial provider results must include structured coverage")
        if self.status == "complete" and any(item.status != "complete" for item in self.coverage):
            raise ValueError("complete provider result cannot include partial/unsupported/unknown coverage")


class Provider(Protocol):
    """Shape for a provider instance explicitly trusted and registered by a host."""

    manifest: ProviderManifest

    def analyze(self, request: ProviderRequest) -> ProviderResult:
        """Run one named operation and return provenance-bound results."""
        ...


class ProviderRegistry:
    """In-memory registry; it deliberately performs no plugin or PATH discovery."""

    def __init__(self) -> None:
        self._providers: dict[str, Provider] = {}

    def register(self, provider: Provider) -> None:
        manifest = provider.manifest
        if manifest.provider_id in self._providers:
            raise ValueError(f"provider already registered: {manifest.provider_id}")
        self._providers[manifest.provider_id] = provider

    def get(self, provider_id: str) -> Provider:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise KeyError(f"provider not registered: {provider_id}") from exc

    def validate_result(self, request: ProviderRequest, result: ProviderResult) -> None:
        """Reject cross-artifact, undeclared-operation, or misidentified results."""
        provider = self.get(result.provider_id)
        manifest = provider.manifest
        if result.artifact_id != request.artifact_id or result.sha256.lower() != request.sha256.lower():
            raise ValueError("provider result does not match the requested artifact identity")
        if result.operation_id != request.operation_id:
            raise ValueError("provider result operation does not match the request")
        if result.provider_id != manifest.provider_id or result.provider_version != manifest.version:
            raise ValueError("provider result identity/version does not match its manifest")
        if result.operation_id not in {operation.operation_id for operation in manifest.operations}:
            raise ValueError("provider returned an undeclared operation")
        if result.status == "complete" and any(item.status in {"partial", "unknown"} for item in result.coverage):
            raise ValueError("complete result conflicts with partial/unknown coverage; report partial")
