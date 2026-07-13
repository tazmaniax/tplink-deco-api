"""Response contract for one semantic mutation candidate."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MutationResponse(ResponseDto):
    """Describe one stable mutation intent and its execution eligibility."""

    name: str
    description: str
    category: str
    risk: str
    sensitivity: str
    scope: str
    changes_schema: JsonObject
    support_status: str
    validation_status: str
    execution_scope: str
    execution_status: str
    required_gates: list[str]
    confirmation_required: bool
    preflight_available: bool
    verification_available: bool
    rollback_available: bool
    plan_operation: str
    execute_operation: str | None
    blockers: list[str]
