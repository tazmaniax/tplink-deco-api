"""Model-specific evidence for one catalogued operation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from .._json import JsonValue
    from ..endpoint_spec import AuthenticationMode

Availability: TypeAlias = Literal[
    "supported",
    "rejected",
    "not_found",
    "transport_error",
    "invalid_response",
    "untested",
]
CompatibilityConfidence: TypeAlias = Literal[
    "observed",
    "asset_declared",
    "inferred",
    "unverified",
]
EvidenceSource: TypeAlias = Literal[
    "catalog",
    "full_manifest",
    "web_asset",
    "live_asset_probe",
    "sensitive_schema_probe",
    "bootstrap_probe",
    "binary_digest_probe",
    "same_form_inference",
    "mutation_probe",
]
MutationTestScope: TypeAlias = Literal["none", "noop_only", "general"]


@dataclass(frozen=True)
class OperationCompatibility:
    """Describe what is known about one operation on a specific model."""

    name: str
    availability: Availability
    evidence: tuple[EvidenceSource, ...]
    returned_data: bool | None = None
    asset_present: bool = False
    mutation_tested: bool = False
    mutation_test_scope: MutationTestScope = "none"
    error_code: int | None = None
    http_status: int | None = None
    schema_paths: tuple[str, ...] = ()
    schema_sha256: str = ""
    transport_override: AuthenticationMode | None = None

    @property
    def confidence(self) -> CompatibilityConfidence:
        """Return the strongest evidence level without implying unsupported writes work."""
        if (
            "full_manifest" in self.evidence
            or "live_asset_probe" in self.evidence
            or "sensitive_schema_probe" in self.evidence
            or "bootstrap_probe" in self.evidence
            or "binary_digest_probe" in self.evidence
            or "mutation_probe" in self.evidence
        ):
            return "observed"
        if "web_asset" in self.evidence:
            return "asset_declared"
        if "same_form_inference" in self.evidence:
            return "inferred"
        return "unverified"

    @property
    def verified_callable(self) -> bool:
        """Return whether a live call verified this exact operation on the model."""
        return self.availability == "supported" and (
            self.mutation_tested
            or "full_manifest" in self.evidence
            or "live_asset_probe" in self.evidence
            or "sensitive_schema_probe" in self.evidence
            or "bootstrap_probe" in self.evidence
            or "binary_digest_probe" in self.evidence
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Return JSON-compatible model evidence for MCP and diagnostics."""
        return {
            "name": self.name,
            "availability": self.availability,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "returned_data": self.returned_data,
            "asset_present": self.asset_present,
            "mutation_tested": self.mutation_tested,
            "mutation_test_scope": self.mutation_test_scope,
            "error_code": self.error_code,
            "http_status": self.http_status,
            "schema_paths": list(self.schema_paths),
            "schema_sha256": self.schema_sha256,
            "transport_override": self.transport_override,
            "verified_callable": self.verified_callable,
        }
