"""Routing contract for one protocol-neutral Deco capability."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from .._json import JsonValue
    from ..endpoint_spec import SensitivityLevel

CapabilityInterface: TypeAlias = Literal["http_luci", "tmp_appv2"]
CapabilityFallbackPolicy: TypeAlias = Literal["none", "equivalent_read_only"]


@dataclass(frozen=True)
class CapabilityRoute:
    """Describe protocol selection without exposing it as an agent decision."""

    name: str
    description: str
    sensitivity: SensitivityLevel
    primary_interface: CapabilityInterface
    primary_operation: str
    fallback_interface: CapabilityInterface | None
    fallback_operation: str
    fallback_policy: CapabilityFallbackPolicy
    equivalence_evidence: str
    schema_version: int = 1

    def to_dict(self) -> dict[str, JsonValue]:
        """Return agent-readable routing metadata without contacting the router."""
        return {
            "name": self.name,
            "description": self.description,
            "sensitivity": self.sensitivity,
            "primary_interface": self.primary_interface,
            "primary_operation": self.primary_operation,
            "fallback_interface": self.fallback_interface,
            "fallback_operation": self.fallback_operation,
            "fallback_policy": self.fallback_policy,
            "equivalence_evidence": self.equivalence_evidence,
            "schema_version": self.schema_version,
            "read_only": True,
            "automatic_mutation_fallback": False,
        }
