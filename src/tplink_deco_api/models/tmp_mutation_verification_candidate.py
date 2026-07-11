"""Offline verification priority for one TMP mutation plan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue
    from .tmp_mutation_plan import TmpMutationPlan


@dataclass(frozen=True)
class TmpMutationVerificationCandidate:
    """Rank one mutation for future explicit, bounded hardware verification."""

    plan: TmpMutationPlan
    tier: str
    priority_score: int
    verification_strategy: str
    risk_flags: tuple[str, ...]
    blocking_gaps: tuple[str, ...]

    @property
    def verification_candidate(self) -> bool:
        """Return whether evidence supports requesting a bounded verification."""
        return self.tier in {
            "priority_noop_candidate",
            "secondary_noop_candidate",
            "roundtrip_candidate",
        }

    def to_dict(self) -> dict[str, JsonValue]:
        """Return agent-readable ranking evidence without execution capability."""
        return {
            "code": self.plan.code,
            "hex_code": f"0x{self.plan.code:04X}",
            "name": self.plan.name,
            "tier": self.tier,
            "priority_score": self.priority_score,
            "verification_strategy": self.verification_strategy,
            "verification_candidate": self.verification_candidate,
            "risk_flags": self.risk_flags,
            "blocking_gaps": self.blocking_gaps,
            "explicit_authorization_required": True,
            "live_preflight_required": True,
            "same_session_verification_required": True,
            "rollback_required": True,
            "parameter_values_included": False,
            "router_contacted": False,
            "mutation_invoked": False,
            "execution_eligible": False,
            "plan": self.plan.to_dict(),
        }
