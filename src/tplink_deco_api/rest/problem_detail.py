"""RFC 9457 problem-detail model for REST failures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class ProblemDetail:
    """Describe a stable public REST failure without exposing router payloads."""

    type: str
    title: str
    status: int
    detail: str
    instance: str
    code: str
    request_id: str
    blockers: list[str] | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a JSON representation suitable for an RFC 9457 response."""
        result: dict[str, JsonValue] = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "instance": self.instance,
            "code": self.code,
            "request_id": self.request_id,
        }
        if self.blockers is not None:
            result["blockers"] = self.blockers
        return result
