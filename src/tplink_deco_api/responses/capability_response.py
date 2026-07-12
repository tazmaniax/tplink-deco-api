"""Response contract for one semantic capability read."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import (  # noqa: TC001 - FastAPI resolves these at runtime.
    JsonData,
    JsonDocument,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class CapabilityResponse(ResponseDto):
    """Describe one capability value and the route used to obtain it."""

    capability: str
    schema_version: int
    data: JsonData
    provenance: JsonDocument
    mutation_invoked: bool
