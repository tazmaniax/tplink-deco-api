"""Response contract for semantic capability discovery."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import JsonSection  # noqa: TC001 - FastAPI resolves this at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class CapabilitiesResponse(ResponseDto):
    """Describe readable semantic capabilities for the connected controller."""

    schema_version: int
    resolution_status: str
    controller: JsonSection
    profile_match: str
    capabilities: list[JsonSection]
    supported_count: int
    unknown_count: int
    unsupported_count: int
    router_contacted: bool
    mutation_invoked: bool
