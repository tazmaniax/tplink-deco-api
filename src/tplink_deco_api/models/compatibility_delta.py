"""Difference between two Deco compatibility observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class CompatibilityDelta:
    """Describe endpoint and schema changes between firmware observations."""

    previous_firmware: str
    current_firmware: str
    added_operations: tuple[str, ...]
    removed_operations: tuple[str, ...]
    newly_supported: tuple[str, ...]
    no_longer_supported: tuple[str, ...]
    status_changed: tuple[str, ...]
    schema_changed: tuple[str, ...]
    fuzzy_added: tuple[str, ...] = ()
    fuzzy_removed: tuple[str, ...] = ()
    fuzzy_changed: tuple[str, ...] = ()

    @property
    def has_changes(self) -> bool:
        """Return whether any compatibility-relevant difference was observed."""
        return any(
            (
                self.previous_firmware != self.current_firmware,
                self.added_operations,
                self.removed_operations,
                self.newly_supported,
                self.no_longer_supported,
                self.status_changed,
                self.schema_changed,
                self.fuzzy_added,
                self.fuzzy_removed,
                self.fuzzy_changed,
            )
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Return JSON-compatible compatibility differences."""
        return {
            "previous_firmware": self.previous_firmware,
            "current_firmware": self.current_firmware,
            "has_changes": self.has_changes,
            "added_operations": list(self.added_operations),
            "removed_operations": list(self.removed_operations),
            "newly_supported": list(self.newly_supported),
            "no_longer_supported": list(self.no_longer_supported),
            "status_changed": list(self.status_changed),
            "schema_changed": list(self.schema_changed),
            "fuzzy_added": list(self.fuzzy_added),
            "fuzzy_removed": list(self.fuzzy_removed),
            "fuzzy_changed": list(self.fuzzy_changed),
        }
