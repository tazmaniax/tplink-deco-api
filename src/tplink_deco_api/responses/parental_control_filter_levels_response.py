"""Response contract for parental-control filter levels."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ParentalControlFilterLevelsResponse(ResponseDto):
    """Describe default parental-control filter levels."""

    schema_version: int
    status: str
    filter_levels: list[JsonObject]
    filter_level_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
