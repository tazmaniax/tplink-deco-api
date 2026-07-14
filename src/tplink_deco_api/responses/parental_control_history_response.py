"""Response contract for parental-control browsing history."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ParentalControlHistoryResponse(ResponseDto):
    """Describe browsing-history entries for one parental-control profile."""

    schema_version: int
    status: str
    owner_id: str
    history: list[JsonObject]
    history_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
