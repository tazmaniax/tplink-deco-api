"""One process-local semantic mutation plan awaiting execution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _PendingMutationPlan:
    """Bind a one-shot mutation authorization to one connected controller."""

    plan_id: str
    mutation: str
    mode: str
    confirmation: str
    controller_identity: str
    expires_at: float
