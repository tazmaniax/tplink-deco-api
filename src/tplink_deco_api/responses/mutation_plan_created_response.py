"""Response contract for a newly created mutation plan."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import (  # noqa: TC001 - FastAPI resolves these at runtime.
    JsonData,
    JsonDocument,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MutationPlanCreatedResponse(ResponseDto):
    """Describe one executable, expiring and controller-bound mutation plan."""

    schema_version: int
    mutation: str
    mode: str
    changes: JsonDocument
    model: str
    profile_match: str
    validation_status: JsonData
    execution_scope: JsonData
    execution_allowed: bool
    plan_id: str
    expires_in_seconds: float
    required_confirmation: str
    required_gates: JsonData
    preflight_available: JsonData
    verification_available: JsonData
    rollback_available: JsonData
    blockers: list[str]
    router_contacted: bool
    mutation_invoked: bool
    fallback_policy: str
