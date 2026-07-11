"""Capability report for an observed Deco firmware instance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue
    from .endpoint_probe_result import EndpointProbeResult


@dataclass(frozen=True)
class CapabilityReport:
    """Collect versioned endpoint observations for one router session."""

    host: str
    observed_at: str
    probes: tuple[EndpointProbeResult, ...]

    @property
    def supported_names(self) -> tuple[str, ...]:
        """Return stable names for operations observed to work."""
        return tuple(probe.endpoint.name for probe in self.probes if probe.status == "supported")

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a JSON-compatible report for persistence or MCP resources."""
        return {
            "host": self.host,
            "observed_at": self.observed_at,
            "supported": list(self.supported_names),
            "probes": [probe.to_dict() for probe in self.probes],
        }
