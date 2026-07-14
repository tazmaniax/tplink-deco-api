"""Response contract for normalized network health."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import (  # noqa: TC001 - FastAPI resolves these annotations at runtime.
    JsonObject,
    JsonValue,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class NetworkStatusResponse(ResponseDto):
    """Describe current controller, internet and mesh health."""

    schema_version: int
    status: str
    controller: JsonObject
    internet: JsonValue
    mesh: JsonObject
    performance: JsonValue
    firmware: JsonValue
    speed_test: JsonValue
    client_count: JsonValue
    client_count_status: str
    provenance: JsonObject
    warnings: list[JsonObject]
    unavailable_sections: list[JsonObject]
    observed_at_epoch_seconds: float
    passwords_included: bool
    client_identities_included: bool
    router_contacted: bool
    mutation_invoked: bool
