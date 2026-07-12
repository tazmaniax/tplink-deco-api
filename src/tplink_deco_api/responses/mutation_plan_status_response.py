"""Response contract for pending mutation-plan status."""

from __future__ import annotations

from dataclasses import dataclass

from .response_dto import ResponseDto


@dataclass(frozen=True)
class MutationPlanStatusResponse(ResponseDto):
    """Describe pending plan state without repeating its exact confirmation."""

    schema_version: int
    plan_id: str
    mutation: str
    mode: str
    status: str
    expires_in_seconds: float
    fallback_policy: str
