"""Response contract for speed-test server selection."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class SpeedTestServersResponse(ResponseDto):
    """Describe automatic selection and available speed-test servers."""

    schema_version: int
    status: str
    automatic_selection: bool
    servers: list[JsonObject]
    server_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
