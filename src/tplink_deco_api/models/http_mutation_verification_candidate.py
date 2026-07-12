"""Offline verification classification for one HTTP mutation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue
    from ..endpoint_spec import EndpointSpec
    from .mutation_plan import MutationPlan
    from .operation_compatibility import OperationCompatibility


@dataclass(frozen=True)
class HttpMutationVerificationCandidate:
    """Rank one HTTP mutation without granting an execution path."""

    endpoint: EndpointSpec
    compatibility: OperationCompatibility
    plan: MutationPlan
    tier: str
    priority_score: int
    verification_strategy: str
    risk_flags: tuple[str, ...]
    blocking_gaps: tuple[str, ...]
    live_preflight_supported: bool

    @property
    def verification_candidate(self) -> bool:
        """Return whether evidence supports requesting a bounded verification."""
        return self.tier in {"priority_noop_candidate", "roundtrip_candidate"}

    def to_dict(self) -> dict[str, JsonValue]:
        """Return value-free agent-readable ranking evidence."""
        return {
            "name": self.endpoint.name,
            "tier": self.tier,
            "priority_score": self.priority_score,
            "verification_strategy": self.verification_strategy,
            "verification_candidate": self.verification_candidate,
            "risk_flags": self.risk_flags,
            "blocking_gaps": self.blocking_gaps,
            "live_preflight_supported": self.live_preflight_supported,
            "explicit_authorization_required": True,
            "router_contacted": False,
            "mutation_invoked": False,
            "execution_eligible": False,
            "endpoint": self.endpoint.to_dict(),
            "compatibility": self.compatibility.to_dict(),
            "plan": self.plan.to_dict(),
        }
