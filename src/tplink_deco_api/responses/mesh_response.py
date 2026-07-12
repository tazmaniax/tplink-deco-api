"""Response contract for controller and mesh inventory."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import JsonSection  # noqa: TC001 - FastAPI resolves this at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MeshResponse(ResponseDto):
    """Describe the resolved controller and mesh-node inventory."""

    schema_version: int
    resolution_status: str
    controller: JsonSection
    nodes: list[JsonSection]
    node_count: int
    mixed_model_mesh: bool
    identity_source: str
    profile_match: str
    profile_name: str | None
    cached: bool
    router_contacted: bool
    mutation_invoked: bool
