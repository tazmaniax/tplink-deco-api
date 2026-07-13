"""Response contract for semantic capability discovery."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class CapabilitiesResponse(ResponseDto):
    """Describe readable semantic capabilities for the connected controller."""

    schema_version: int
    resolution_status: str
    controller: JsonObject
    profile_match: str
    capabilities: list[JsonObject]
    supported_count: int
    unknown_count: int
    unsupported_count: int
    router_contacted: bool
    mutation_invoked: bool
