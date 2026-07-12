"""Response contract for normalized network health."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import (  # noqa: TC001 - FastAPI resolves these at runtime.
    JsonData,
    JsonRecord,
    JsonSection,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class NetworkStatusResponse(ResponseDto):
    """Describe current controller, internet and mesh health."""

    schema_version: int
    status: str
    controller: JsonRecord
    internet: JsonData
    mesh: JsonSection
    performance: JsonData
    firmware: JsonData
    speed_test: JsonData
    client_count: JsonData
    client_count_status: str
    warnings: list[JsonRecord]
    unavailable_sections: list[JsonRecord]
    observed_at_epoch_seconds: float
    passwords_included: bool
    client_identities_included: bool
    router_contacted: bool
    mutation_invoked: bool
