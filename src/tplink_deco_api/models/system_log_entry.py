"""One structured entry returned by the Deco system-log reader."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .._json import get_str

if TYPE_CHECKING:
    from .._json import JsonObject


@dataclass(frozen=True)
class SystemLogEntry:
    """Preserve one log entry across firmware-specific response shapes."""

    content: str
    time: str = ""
    level: str = ""
    log_type: str = ""

    @classmethod
    def from_api(cls, data: JsonObject) -> SystemLogEntry:
        """Build a system-log entry from a router payload."""
        return cls(
            content=get_str(data, "content"),
            time=get_str(data, "time"),
            level=get_str(data, "level"),
            log_type=get_str(data, "type"),
        )

    def to_dict(self) -> JsonObject:
        """Return the firmware field names in a JSON-compatible mapping."""
        return {
            "content": self.content,
            "time": self.time,
            "level": self.level,
            "type": self.log_type,
        }
