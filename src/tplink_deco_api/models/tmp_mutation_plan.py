"""Offline safety plan for one reverse-engineered TMP mutation opcode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class TmpMutationPlan:
    """Describe TMP mutation evidence without providing an execution path."""

    code: int
    name: str
    safety: str
    safety_evidence: str
    category: str
    sensitivity: str
    app_set_dispatch_review: str
    preflight_code: int | None
    preflight_name: str
    preflight_observation: str
    preflight_relationship_evidence: str
    verification_code: int | None
    verification_name: str
    verification_relationship_evidence: str
    rollback_code: int | None
    rollback_name: str
    rollback_relationship_evidence: str
    rollback_requires_preflight: bool
    parameter_contract: str
    parameter_contract_evidence: str
    p9_parameter_contract_verified: bool
    p9_mutation_observation: str
    p9_mutation_firmware_error_code: int | None
    p9_mutation_parameter_keys: tuple[str, ...]
    p9_mutation_state_unchanged: bool | None
    p9_mutation_rollback_attempted: bool
    p9_mutation_rollback_verified: bool | None
    p9_mutation_request_count: int
    p9_mutation_evidence_artifact: str
    app_analysis_sources: tuple[str, ...]
    app_contract_sources: tuple[str, ...]
    app_dispatch_methods: tuple[str, ...]
    app_contract_provenance: str
    app_request_models: tuple[str, ...]
    app_candidate_parameter_keys: tuple[str, ...]
    app_call_site_count: int
    app_contract_sha256: str
    evidence: str
    warnings: tuple[str, ...]
    preflight_result_keys: tuple[str, ...] = ()
    preflight_missing_candidate_keys: tuple[str, ...] = ()

    @property
    def complete_safety_contract(self) -> bool:
        """Return whether all requirements for controlled execution are evidenced."""
        return (
            self.preflight_code is not None
            and self.preflight_observation == "returned_data"
            and self.verification_code is not None
            and self.rollback_code is not None
            and self.parameter_contract != "unknown"
            and self.p9_parameter_contract_verified
            and not self.preflight_missing_candidate_keys
        )

    @property
    def p9_opcode_tested(self) -> bool:
        """Return whether this exact mutation was exercised on the P9."""
        return self.p9_mutation_observation != "untested"

    def to_dict(self) -> dict[str, JsonValue]:
        """Return agent-readable planning metadata."""
        return {
            "code": self.code,
            "hex_code": f"0x{self.code:04X}",
            "name": self.name,
            "safety": self.safety,
            "safety_evidence": self.safety_evidence,
            "category": self.category,
            "sensitivity": self.sensitivity,
            "app_set_dispatch_review": self.app_set_dispatch_review,
            "p9_opcode_tested": self.p9_opcode_tested,
            "parameter_contract": self.parameter_contract,
            "parameter_contract_evidence": self.parameter_contract_evidence,
            "p9_parameter_contract_verified": self.p9_parameter_contract_verified,
            "p9_mutation_observation": self.p9_mutation_observation,
            "p9_mutation_firmware_error_code": self.p9_mutation_firmware_error_code,
            "p9_mutation_parameter_keys": self.p9_mutation_parameter_keys,
            "p9_mutation_state_unchanged": self.p9_mutation_state_unchanged,
            "p9_mutation_rollback_attempted": self.p9_mutation_rollback_attempted,
            "p9_mutation_rollback_verified": self.p9_mutation_rollback_verified,
            "p9_mutation_request_count": self.p9_mutation_request_count,
            "p9_mutation_evidence_artifact": self.p9_mutation_evidence_artifact,
            "app_analysis_sources": self.app_analysis_sources,
            "app_contract_sources": self.app_contract_sources,
            "app_dispatch_methods": self.app_dispatch_methods,
            "app_contract_provenance": self.app_contract_provenance,
            "app_request_models": self.app_request_models,
            "app_candidate_parameter_keys": self.app_candidate_parameter_keys,
            "app_call_site_count": self.app_call_site_count,
            "app_contract_sha256": self.app_contract_sha256,
            "preflight_code": self.preflight_code,
            "preflight_hex_code": (
                f"0x{self.preflight_code:04X}" if self.preflight_code is not None else ""
            ),
            "preflight_name": self.preflight_name,
            "preflight_observation": self.preflight_observation,
            "preflight_relationship_evidence": self.preflight_relationship_evidence,
            "preflight_result_keys": self.preflight_result_keys,
            "preflight_missing_candidate_keys": self.preflight_missing_candidate_keys,
            "verification_code": self.verification_code,
            "verification_name": self.verification_name,
            "verification_relationship_evidence": (self.verification_relationship_evidence),
            "rollback_code": self.rollback_code,
            "rollback_hex_code": (
                f"0x{self.rollback_code:04X}" if self.rollback_code is not None else ""
            ),
            "rollback_name": self.rollback_name,
            "rollback_relationship_evidence": self.rollback_relationship_evidence,
            "rollback_requires_preflight": self.rollback_requires_preflight,
            "evidence": self.evidence,
            "complete_safety_contract": self.complete_safety_contract,
            "execution_eligible": False,
            "warnings": list(self.warnings),
        }
