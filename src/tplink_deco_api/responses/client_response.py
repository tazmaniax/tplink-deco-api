"""Response contract for one enriched client device."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import (  # noqa: TC001 - FastAPI resolves these annotations at runtime.
    JsonObject,
    JsonValue,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ClientResponse(ResponseDto):
    """Describe one client device enriched from every available source."""

    schema_version: int
    device: JsonObject
    source_counts: JsonObject
    provenance: JsonValue
    unavailable_sections: list[JsonObject]
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
