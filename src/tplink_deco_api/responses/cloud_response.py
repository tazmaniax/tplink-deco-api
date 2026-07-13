"""Response contract for gated cloud-related router state."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import (  # noqa: TC001 - FastAPI resolves these annotations at runtime.
    JsonObject,
    JsonValue,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class CloudResponse(ResponseDto):
    """Describe observed DDNS and cloud-manager state."""

    schema_version: int
    status: str
    ddns: JsonValue
    manager: JsonValue
    provenance: JsonObject
    unavailable_sections: list[JsonObject]
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
