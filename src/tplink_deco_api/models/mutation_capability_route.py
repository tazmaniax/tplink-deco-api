"""Routing contract for one protocol-neutral Deco mutation capability."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue
    from .capability_route import CapabilityInterface


@dataclass(frozen=True)
class MutationCapabilityRoute:
    """Bind one semantic mutation to a fixed verified implementation."""

    name: str
    description: str
    interface: CapabilityInterface
    operation: str
    preflight_operation: str
    confirmation: str
    required_environment_gates: tuple[str, ...]
    evidence: str
    schema_version: int = 1

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the fixed mutation route without contacting the router."""
        return {
            "name": self.name,
            "description": self.description,
            "interface": self.interface,
            "operation": self.operation,
            "preflight_operation": self.preflight_operation,
            "execution_scope": "verified_current_value_noop_only",
            "confirmation": self.confirmation,
            "required_environment_gates": list(self.required_environment_gates),
            "evidence": self.evidence,
            "fallback_policy": "none",
            "automatic_fallback": False,
            "schema_version": self.schema_version,
        }
