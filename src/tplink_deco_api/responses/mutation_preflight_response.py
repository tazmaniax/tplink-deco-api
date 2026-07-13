"""Response contract for non-creating mutation preflight."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import (  # noqa: TC001 - FastAPI resolves these annotations at runtime.
    JsonObject,
    JsonValue,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MutationPreflightResponse(ResponseDto):
    """Describe mutation eligibility without creating process state."""

    schema_version: int
    mutation: str
    mode: str
    changes: JsonObject
    model: str
    profile_match: str
    validation_status: JsonValue
    execution_scope: JsonValue
    execution_allowed: bool
    plan_id: None
    expires_in_seconds: None
    required_confirmation: None
    required_gates: JsonValue
    preflight_available: JsonValue
    verification_available: JsonValue
    rollback_available: JsonValue
    blockers: list[str]
    router_contacted: bool
    mutation_invoked: bool
    fallback_policy: str
