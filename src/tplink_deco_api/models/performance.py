"""CPU / memory usage snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_float


@dataclass(frozen=True)
class Performance:
    """Normalized CPU and memory usage (each in the [0.0, 1.0] range)."""

    cpu_usage: float
    mem_usage: float

    @classmethod
    def from_api(cls, data: JsonObject) -> Performance:
        """Build ``Performance`` from a router payload."""
        return cls(
            cpu_usage=get_float(data, "cpu_usage"),
            mem_usage=get_float(data, "mem_usage"),
        )
