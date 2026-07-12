"""Response contract for normalized client-device inventory."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import (  # noqa: TC001 - FastAPI resolves these at runtime.
    JsonData,
    JsonRecord,
    JsonSection,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ClientsResponse(ResponseDto):
    """Describe one filtered view of known client devices."""

    schema_version: int
    view: str
    devices: list[JsonSection]
    device_count: int
    all_device_count: int
    source_counts: JsonRecord
    provenance: JsonData
    unavailable_sections: list[JsonRecord]
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
