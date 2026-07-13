"""Response contract for one semantic capability read."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import (  # noqa: TC001 - FastAPI resolves these annotations at runtime.
    JsonObject,
    JsonValue,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class CapabilityResponse(ResponseDto):
    """Describe one capability value and the route used to obtain it."""

    capability: str
    schema_version: int
    data: JsonValue
    provenance: JsonObject
    mutation_invoked: bool
