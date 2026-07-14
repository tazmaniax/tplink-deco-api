"""Response contract for semantic system LED configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class LedConfigurationResponse(ResponseDto):
    """Describe the current LED state and night-mode schedule."""

    schema_version: int
    status: str
    enabled: bool
    night_mode: JsonObject
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
