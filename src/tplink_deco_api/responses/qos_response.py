"""Response contract for semantic quality-of-service state."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class QosResponse(ResponseDto):
    """Describe QoS mode details and configured bandwidth values."""

    schema_version: int
    status: str
    mode: JsonObject
    bandwidth: JsonObject
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
