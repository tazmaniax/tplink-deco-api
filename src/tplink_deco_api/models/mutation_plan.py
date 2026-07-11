"""Dry-run safety plan for one catalogued mutation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class MutationPlan:
    """Describe validation, evidence, verification, and rollback without writing."""

    name: str
    params: dict[str, JsonValue]
    safety: str
    model: str
    model_availability: str
    model_confidence: str
    model_verified: bool
    model_test_scope: str
    parameters_valid: bool
    missing_params: tuple[str, ...]
    transport_supported: bool
    gate_enabled: bool
    preflight_read: str
    preflight_condition: str
    verification_read: str
    success_condition: str
    rollback_operation: str
    rollback_params: dict[str, JsonValue] | None
    rollback_requires_preflight: bool
    confirmation_sha256: str
    warnings: tuple[str, ...]

    @property
    def ready_for_explicit_test(self) -> bool:
        """Return whether mechanics and server policy permit a separately confirmed test."""
        return (
            self.parameters_valid
            and self.transport_supported
            and self.gate_enabled
            and bool(self.preflight_read)
            and bool(self.verification_read)
            and bool(self.rollback_operation)
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Return JSON-compatible planning metadata without contacting the router."""
        return {
            "name": self.name,
            "params": self.params,
            "safety": self.safety,
            "model": self.model,
            "model_availability": self.model_availability,
            "model_confidence": self.model_confidence,
            "model_verified": self.model_verified,
            "model_test_scope": self.model_test_scope,
            "parameters_valid": self.parameters_valid,
            "missing_params": list(self.missing_params),
            "transport_supported": self.transport_supported,
            "gate_enabled": self.gate_enabled,
            "preflight_read": self.preflight_read,
            "preflight_condition": self.preflight_condition,
            "verification_read": self.verification_read,
            "success_condition": self.success_condition,
            "rollback_operation": self.rollback_operation,
            "rollback_params": self.rollback_params,
            "rollback_requires_preflight": self.rollback_requires_preflight,
            "confirmation_sha256": self.confirmation_sha256,
            "warnings": list(self.warnings),
            "ready_for_explicit_test": self.ready_for_explicit_test,
        }
