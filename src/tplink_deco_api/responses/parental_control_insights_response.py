"""Response contract for parental-control insights."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ParentalControlInsightsResponse(ResponseDto):
    """Describe online-usage insights for one parental-control profile."""

    schema_version: int
    status: str
    owner_id: str
    insights: list[JsonObject]
    insight_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
