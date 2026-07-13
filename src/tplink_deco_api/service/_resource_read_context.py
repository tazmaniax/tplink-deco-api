"""Internal single-interface context for one semantic resource read."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject
    from ..models.capability_route import CapabilityInterface


@dataclass(frozen=True)
class _ResourceReadContext:
    """Bind a compound resource to one selected data-producing interface."""

    interface: CapabilityInterface
    source_operation: str
    attempts: tuple[JsonObject, ...]
    identity_attempts: tuple[JsonObject, ...]
    fallback_used: bool

    def provenance(self) -> JsonObject:
        """Return transport-neutral source selection evidence."""
        return {
            "source_interface": self.interface,
            "source_operation": self.source_operation,
            "fallback_used": self.fallback_used,
            "attempts": [dict(attempt) for attempt in self.attempts],
            "identity_attempts": [dict(attempt) for attempt in self.identity_attempts],
            "single_source_interface": True,
        }
