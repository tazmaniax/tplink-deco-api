"""Paginated system-log response returned by Deco web firmware."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .._json import get_int
from .system_log_entry import SystemLogEntry

if TYPE_CHECKING:
    from .._json import JsonObject


@dataclass(frozen=True)
class SystemLogPage:
    """Describe one firmware-defined page of system-log entries."""

    current_index: int
    total_pages: int
    entries: tuple[SystemLogEntry, ...]

    @classmethod
    def from_api(cls, data: JsonObject) -> SystemLogPage:
        """Build a system-log page from a router payload."""
        rows = data.get("logList")
        entries = (
            tuple(SystemLogEntry.from_api(row) for row in rows if isinstance(row, dict))
            if isinstance(rows, list)
            else ()
        )
        return cls(
            current_index=get_int(data, "currentIndex"),
            total_pages=get_int(data, "totalNum"),
            entries=entries,
        )

    def to_dict(self) -> JsonObject:
        """Return normalized pagination metadata and entries."""
        return {
            "current_index": self.current_index,
            "total_pages": self.total_pages,
            "entries": [entry.to_dict() for entry in self.entries],
        }
