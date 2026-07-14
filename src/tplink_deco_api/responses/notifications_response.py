"""Response contract for Deco notifications."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class NotificationsResponse(ResponseDto):
    """Describe notifications from the Deco message centre."""

    schema_version: int
    status: str
    notifications: list[JsonObject]
    notification_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
