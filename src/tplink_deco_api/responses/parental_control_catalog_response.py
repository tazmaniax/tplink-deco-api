"""Response contract for the parental-control filter catalogue."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ParentalControlCatalogResponse(ResponseDto):
    """Describe website and application filtering catalogue entries."""

    schema_version: int
    status: str
    has_app_filter: bool
    needs_update: bool
    version: int
    entries: list[JsonObject]
    entry_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
