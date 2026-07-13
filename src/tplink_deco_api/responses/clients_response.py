"""Response contract for normalized client-device inventory."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import (  # noqa: TC001 - FastAPI resolves these annotations at runtime.
    JsonObject,
    JsonValue,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ClientsResponse(ResponseDto):
    """Describe one filtered view of known client devices."""

    schema_version: int
    view: str
    devices: list[JsonObject]
    device_count: int
    all_device_count: int
    source_counts: JsonObject
    provenance: JsonValue
    unavailable_sections: list[JsonObject]
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
