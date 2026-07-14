"""Response contract for semantic WAN MAC-clone state."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MacCloneResponse(ResponseDto):
    """Describe current WAN MAC-clone state."""

    schema_version: int
    status: str
    enabled: bool
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
