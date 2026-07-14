"""Response contract for one parental-control profile."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ParentalControlProfileResponse(ResponseDto):
    """Describe one parental-control profile policy."""

    schema_version: int
    status: str
    profile: JsonObject
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
