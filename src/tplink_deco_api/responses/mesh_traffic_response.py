"""Response contract for normalized mesh-node traffic data."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MeshTrafficResponse(ResponseDto):
    """Describe current firmware-native traffic rates for each mesh node."""

    schema_version: int
    status: str
    node_speeds: list[JsonObject]
    node_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
