"""Response contract for normalized Wi-Fi Protected Setup status."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class WpsStatusResponse(ResponseDto):
    """Describe the current WPS scan timer and per-node sessions."""

    schema_version: int
    status: str
    scanning_time: int
    sessions: list[JsonObject]
    session_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
