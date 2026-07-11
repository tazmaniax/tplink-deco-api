"""Compatibility overlay for one model and firmware build."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue
    from .operation_compatibility import OperationCompatibility


@dataclass(frozen=True)
class ModelCompatibilityProfile:
    """Expose catalog-wide model evidence without changing generic endpoint metadata."""

    model: str
    hardware_versions: tuple[str, ...]
    firmware_version: str
    system_mode: str
    observed_at: str
    catalog_version: int
    operations: tuple[OperationCompatibility, ...]

    def get(self, name: str) -> OperationCompatibility:
        """Return compatibility evidence for one stable operation name."""
        for operation in self.operations:
            if operation.name == name:
                return operation
        raise KeyError(f"Unknown model compatibility operation: {name}")

    def summary(self) -> dict[str, JsonValue]:
        """Return aggregate availability and evidence counts."""
        availability = Counter(operation.availability for operation in self.operations)
        confidence = Counter(operation.confidence for operation in self.operations)
        return {
            "operation_count": len(self.operations),
            "availability": dict(sorted(availability.items())),
            "confidence": dict(sorted(confidence.items())),
            "asset_present": sum(operation.asset_present for operation in self.operations),
            "returned_data": sum(operation.returned_data is True for operation in self.operations),
            "accepted_empty": sum(
                operation.availability == "supported" and operation.returned_data is False
                for operation in self.operations
            ),
            "mutation_tested": sum(operation.mutation_tested for operation in self.operations),
            "sensitive_schema_observed": sum(
                "sensitive_schema_probe" in operation.evidence for operation in self.operations
            ),
            "bootstrap_observed": sum(
                "bootstrap_probe" in operation.evidence for operation in self.operations
            ),
            "transport_overrides": sum(
                operation.transport_override is not None for operation in self.operations
            ),
        }

    def to_dict(self, *, include_operations: bool = True) -> dict[str, JsonValue]:
        """Return JSON-compatible model metadata and optionally every operation overlay."""
        result: dict[str, JsonValue] = {
            "model": self.model,
            "hardware_versions": list(self.hardware_versions),
            "firmware_version": self.firmware_version,
            "system_mode": self.system_mode,
            "observed_at": self.observed_at,
            "catalog_version": self.catalog_version,
            "summary": self.summary(),
        }
        if include_operations:
            result["operations"] = [operation.to_dict() for operation in self.operations]
        return result
