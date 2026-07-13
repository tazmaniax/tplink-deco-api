"""Response contract for normalized traffic data."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class TrafficResponse(ResponseDto):
    """Describe per-device and aggregate traffic rates."""

    schema_version: int
    device_speeds: list[JsonObject]
    device_count: int
    aggregate_speed: JsonObject
    status: str
    unavailable_sections: list[JsonObject]
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
