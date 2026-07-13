"""Response contract for gated WLAN state."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class WlanResponse(ResponseDto):
    """Describe WLAN bands and features with explicit password inclusion state."""

    schema_version: int
    status: str
    passwords_included: bool
    is_eg: bool
    bands: JsonObject
    iot: JsonObject
    mlo: JsonObject
    features: JsonObject
    provenance: JsonObject
    unavailable_sections: list[JsonObject]
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
