"""Response contract for semantic mutation discovery."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .mutation_response import (  # noqa: TC001 - FastAPI resolves this at runtime.
    MutationResponse,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MutationsResponse(ResponseDto):
    """Describe every known mutation intent and current gate state."""

    schema_version: int
    resolution_status: str
    controller: JsonObject
    profile_match: str
    mutations: list[MutationResponse]
    candidate_count: int
    execution_counts: JsonObject
    mutation_gate_status: JsonObject
    router_contacted: bool
    mutation_invoked: bool
