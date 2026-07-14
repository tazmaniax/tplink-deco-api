"""Response contract for manager access permissions."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class AccessPermissionsResponse(ResponseDto):
    """Describe manager roles and component-access policies."""

    schema_version: int
    status: str
    roles: list[JsonObject]
    role_count: int
    permission_profiles: list[JsonObject]
    permission_profile_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
