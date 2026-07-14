"""Response contract for parental-control profiles."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ParentalControlsResponse(ResponseDto):
    """Describe parental-control profile policies."""

    schema_version: int
    status: str
    profiles: list[JsonObject]
    profile_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
