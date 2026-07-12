"""Response contract for normalized traffic data."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import JsonRecord  # noqa: TC001 - FastAPI resolves this at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class TrafficResponse(ResponseDto):
    """Describe per-device and aggregate traffic rates."""

    schema_version: int
    device_speeds: list[JsonRecord]
    device_count: int
    aggregate_speed: JsonRecord
    status: str
    unavailable_sections: list[JsonRecord]
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
