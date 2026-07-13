"""Metadata for one reverse-engineered Deco TMP/AppV2 opcode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from .._json import JsonValue
    from ..endpoint_spec import SafetyLevel, SensitivityLevel

TmpP9Observation: TypeAlias = Literal[
    "untested",
    "accepted",
    "returned_data",
    "returned_binary",
    "rejected",
    "payload_rejected",
]
TmpAppContractStatus: TypeAlias = Literal[
    "no_app_call_site",
    "static_keys_recovered",
    "static_model_recovered",
    "static_null_payload",
]
TmpAppContractProvenance: TypeAlias = Literal[
    "none",
    "direct",
    "indirect_virtual_dispatch",
]
TmpP9MutationObservation: TypeAlias = Literal[
    "untested",
    "verified_noop",
    "same_value_immediate_verification_passed",
    "write_rejected",
    "rollback_confirmed",
    "rollback_unconfirmed",
]
TmpP9MutationSafetyStatus: TypeAlias = Literal[
    "untested",
    "safety_not_established",
]


@dataclass(frozen=True)
class TmpOpcodeSpec:
    """Describe one TMP/AppV2 operation without implying P9 compatibility."""

    code: int
    name: str
    aliases: tuple[str, ...]
    safety: SafetyLevel
    safety_evidence: str
    sensitivity: SensitivityLevel
    category: str
    opcode_registry_source: str
    opcode_registry_mapping_occurrences: int
    app_analysis_sources: tuple[str, ...]
    app_contract_sources: tuple[str, ...]
    app_dispatch_methods: tuple[str, ...]
    app_contract_provenance: TmpAppContractProvenance
    app_contract_status: TmpAppContractStatus
    app_request_models: tuple[str, ...]
    app_candidate_parameter_keys: tuple[str, ...]
    app_call_site_count: int
    app_contract_sha256: str
    app_set_dispatch_review: str
    p9_observation: TmpP9Observation = "untested"
    p9_appv2_error_code: int | None = None
    p9_firmware_error_code: int | None = None
    p9_tested_variants: tuple[str, ...] = ()
    p9_confirmed_parameter_sets: tuple[tuple[str, ...], ...] = ()
    p9_parameter_value_source: str = ""
    p9_schema_paths: tuple[str, ...] = ()
    p9_response_size: int | None = None
    p9_response_sha256: str = ""
    p9_fuzzy_status: str = ""
    p9_mutation_observation: TmpP9MutationObservation = "untested"
    p9_mutation_safety_status: TmpP9MutationSafetyStatus = "untested"
    p9_mutation_firmware_error_code: int | None = None
    p9_mutation_parameter_keys: tuple[str, ...] = ()
    p9_mutation_state_unchanged: bool | None = None
    p9_mutation_rollback_attempted: bool = False
    p9_mutation_rollback_verified: bool | None = None
    p9_mutation_request_count: int = 0
    p9_mutation_evidence_artifact: str = ""

    @property
    def hex_code(self) -> str:
        """Return the conventional four-digit hexadecimal opcode."""
        return f"0x{self.code:04X}"

    @property
    def p9_opcode_tested(self) -> bool:
        """Return whether this exact opcode was exercised on the P9."""
        return self.p9_observation != "untested" or self.p9_mutation_observation != "untested"

    def to_dict(self) -> dict[str, JsonValue]:
        """Return JSON-compatible discovery metadata."""
        return {
            "code": self.code,
            "hex_code": self.hex_code,
            "name": self.name,
            "aliases": self.aliases,
            "safety": self.safety,
            "safety_evidence": self.safety_evidence,
            "sensitivity": self.sensitivity,
            "category": self.category,
            "opcode_registry_source": self.opcode_registry_source,
            "opcode_registry_mapping_occurrences": (self.opcode_registry_mapping_occurrences),
            "app_analysis_sources": self.app_analysis_sources,
            "app_contract_sources": self.app_contract_sources,
            "app_dispatch_methods": self.app_dispatch_methods,
            "app_contract_provenance": self.app_contract_provenance,
            "app_contract_status": self.app_contract_status,
            "app_request_models": self.app_request_models,
            "app_candidate_parameter_keys": self.app_candidate_parameter_keys,
            "app_call_site_count": self.app_call_site_count,
            "app_contract_sha256": self.app_contract_sha256,
            "app_set_dispatch_review": self.app_set_dispatch_review,
            "app_contract_source": "; ".join(
                self.app_contract_sources or self.app_analysis_sources
            ),
            "transport": "tmp_appv2_over_ssh",
            "p9_transport_detected": True,
            "p9_opcode_tested": self.p9_opcode_tested,
            "p9_observation": self.p9_observation,
            "p9_appv2_error_code": self.p9_appv2_error_code,
            "p9_firmware_error_code": self.p9_firmware_error_code,
            "p9_tested_variants": self.p9_tested_variants,
            "p9_confirmed_parameter_sets": [
                list(parameter_set) for parameter_set in self.p9_confirmed_parameter_sets
            ],
            "p9_parameter_value_source": self.p9_parameter_value_source,
            "p9_schema_paths": self.p9_schema_paths,
            "p9_response_size": self.p9_response_size,
            "p9_response_sha256": self.p9_response_sha256,
            "p9_fuzzy_status": self.p9_fuzzy_status,
            "p9_mutation_observation": self.p9_mutation_observation,
            "p9_mutation_safety_status": self.p9_mutation_safety_status,
            "p9_mutation_firmware_error_code": self.p9_mutation_firmware_error_code,
            "p9_mutation_parameter_keys": self.p9_mutation_parameter_keys,
            "p9_mutation_state_unchanged": self.p9_mutation_state_unchanged,
            "p9_mutation_rollback_attempted": self.p9_mutation_rollback_attempted,
            "p9_mutation_rollback_verified": self.p9_mutation_rollback_verified,
            "p9_mutation_request_count": self.p9_mutation_request_count,
            "p9_mutation_evidence_artifact": self.p9_mutation_evidence_artifact,
            "wire_protocol_supported": True,
            "read_only_session_supported": self.safety == "read_only",
            "read_probe_eligible": (
                self.safety == "read_only" and "set" not in self.app_dispatch_methods
            ),
            "read_probe_exclusion_reason": self.app_set_dispatch_review,
            "generic_call_supported": self.p9_observation == "returned_data",
            "binary_call_supported": self.p9_observation == "returned_binary",
            "evidence": (
                "signed TP-Link Deco Android 1.10.5 and 3.10.215 static analysis; "
                "value-free P9 live audit 2026-07-11"
            ),
        }
