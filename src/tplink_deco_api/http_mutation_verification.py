"""Prioritize bounded HTTP mutation verification without contacting a router."""

from __future__ import annotations

from .endpoint_catalog import P9_MUTATION_CANDIDATES
from .model_compatibility import P9_COMPATIBILITY_PROFILE
from .models import HttpMutationVerificationCandidate, MutationPlan
from .mutation_planner import build_mutation_plan

_HTTP_LIVE_PREFLIGHT_NAMES: frozenset[str] = frozenset(
    {
        "admin.network.wan_mode.write",
        "admin.wireless.ieee80211r.write",
        "admin.wireless.beamforming.write",
        "admin.wireless.operation_mode.write",
        "admin.device.timesetting.write",
        "admin.client.black_list.add",
        "admin.client.black_list.remove",
        "admin.client.addr_reservation.add",
        "admin.client.addr_reservation.modify",
        "admin.client.addr_reservation.remove",
    }
)
_CANDIDATE_TIERS: frozenset[str] = frozenset({"priority_noop_candidate", "roundtrip_candidate"})
_CONNECTIVITY_NAMES: frozenset[str] = frozenset(
    {
        "admin.network.wan_mode.write",
        "admin.network.lan_ip.write",
        "admin.network.vlan.write",
        "admin.network.vlan.set_vlan",
        "admin.network.mac_clone.write",
        "admin.wireless.operation_mode.write",
    }
)
_ACTIVE_ACTION_NAMES: frozenset[str] = frozenset(
    {
        "admin.device.speedtest.write",
        "admin.device.speedtest.stop",
        "admin.device.timesetting.gmt",
    }
)
_ACCESS_POLICY_NAMES: frozenset[str] = frozenset(
    {"admin.client.black_list.add", "admin.client.black_list.remove"}
)
_STRUCTURED_STATE_NAMES: frozenset[str] = frozenset(
    {
        "admin.device.device_list.remove",
        "admin.client.addr_reservation.add",
        "admin.client.addr_reservation.modify",
        "admin.client.addr_reservation.remove",
    }
)
_REGIONAL_NAMES: frozenset[str] = frozenset({"locale.lang.write", "locale.country.write"})
_HIGH_RISK_FLAGS: frozenset[str] = frozenset(
    {
        "active_runtime_action",
        "client_access_policy_change",
        "network_connectivity_change",
        "p9_observed_collection_at_capacity",
        "regional_or_regulatory_change",
        "structured_state_change",
    }
)


def build_http_mutation_verification_queue(
    *,
    include_deferred: bool = False,
    include_destructive: bool = False,
    include_verified: bool = False,
    limit: int | None = 20,
) -> tuple[HttpMutationVerificationCandidate, ...]:
    """Return ranked P9 HTTP mutations for separately authorized verification."""
    if limit is not None and limit <= 0:
        raise ValueError("Failed to rank HTTP mutations: limit must be positive")
    ranked = sorted(
        (_candidate(endpoint.name) for endpoint in P9_MUTATION_CANDIDATES), key=_sort_key
    )
    selected = tuple(
        candidate
        for candidate in ranked
        if (
            candidate.tier in _CANDIDATE_TIERS
            or (include_verified and candidate.tier == "verified_noop")
            or (include_deferred and candidate.tier in {"high_risk_deferred", "evidence_blocked"})
            or (include_destructive and candidate.tier == "destructive_excluded")
        )
    )
    return selected if limit is None else selected[:limit]


def _candidate(name: str) -> HttpMutationVerificationCandidate:
    endpoint = next(endpoint for endpoint in P9_MUTATION_CANDIDATES if endpoint.name == name)
    compatibility = P9_COMPATIBILITY_PROFILE.get(name)
    plan = build_mutation_plan(
        endpoint,
        compatibility,
        None,
        model="P9",
        gate_enabled=False,
    )
    risk_flags = _risk_flags(name, endpoint.safety, endpoint.sensitivity)
    blocking_gaps = _blocking_gaps(plan, endpoint.contract_source)
    strategy = _verification_strategy(plan)
    tier = _tier(
        compatibility.mutation_test_scope,
        endpoint.safety,
        risk_flags,
        blocking_gaps,
        strategy,
    )
    return HttpMutationVerificationCandidate(
        endpoint=endpoint,
        compatibility=compatibility,
        plan=plan,
        tier=tier,
        priority_score=_priority_score(tier, risk_flags, blocking_gaps),
        verification_strategy=strategy,
        risk_flags=risk_flags,
        blocking_gaps=blocking_gaps,
        live_preflight_supported=name in _HTTP_LIVE_PREFLIGHT_NAMES,
    )


def _risk_flags(name: str, safety: str, sensitivity: str) -> tuple[str, ...]:
    flags: list[str] = []
    if safety == "destructive":
        flags.append("destructive_operation")
    if sensitivity != "normal":
        flags.append("private_state")
    if name in _CONNECTIVITY_NAMES:
        flags.append("network_connectivity_change")
    if name in _ACTIVE_ACTION_NAMES:
        flags.append("active_runtime_action")
    if name in _ACCESS_POLICY_NAMES:
        flags.append("client_access_policy_change")
    if name in _STRUCTURED_STATE_NAMES:
        flags.append("structured_state_change")
    if name in _REGIONAL_NAMES:
        flags.append("regional_or_regulatory_change")
    if name == "admin.client.addr_reservation.add":
        flags.append("p9_observed_collection_at_capacity")
    return tuple(flags)


def _blocking_gaps(plan: MutationPlan, contract_source: str) -> tuple[str, ...]:
    gaps: list[str] = []
    if not plan.preflight_read:
        gaps.append("preflight_read_missing")
    if not plan.verification_read:
        gaps.append("verification_read_missing")
    if not plan.rollback_operation:
        gaps.append("rollback_operation_missing")
    if plan.name not in _HTTP_LIVE_PREFLIGHT_NAMES:
        gaps.append("live_preflight_not_implemented")
    if contract_source == "none":
        gaps.append("parameter_contract_missing")
    if plan.preflight_read:
        availability = P9_COMPATIBILITY_PROFILE.get(plan.preflight_read).availability
        if availability != "supported":
            gaps.append(f"preflight_p9_{availability}")
    return tuple(gaps)


def _verification_strategy(plan: MutationPlan) -> str:
    if not plan.rollback_operation:
        return "none"
    if plan.rollback_operation == plan.name:
        return "same_value_noop_then_restore"
    return "bounded_roundtrip_then_restore"


def _tier(
    mutation_test_scope: str,
    safety: str,
    risk_flags: tuple[str, ...],
    blocking_gaps: tuple[str, ...],
    strategy: str,
) -> str:
    if mutation_test_scope == "noop_only":
        return "verified_noop"
    if safety == "destructive":
        return "destructive_excluded"
    if _HIGH_RISK_FLAGS.intersection(risk_flags):
        return "high_risk_deferred"
    if blocking_gaps:
        return "evidence_blocked"
    if strategy == "same_value_noop_then_restore":
        return "priority_noop_candidate"
    if strategy == "bounded_roundtrip_then_restore":
        return "roundtrip_candidate"
    return "evidence_blocked"


def _priority_score(
    tier: str,
    risk_flags: tuple[str, ...],
    blocking_gaps: tuple[str, ...],
) -> int:
    tier_base = {
        "verified_noop": 100,
        "priority_noop_candidate": 80,
        "roundtrip_candidate": 60,
        "high_risk_deferred": 30,
        "evidence_blocked": 10,
        "destructive_excluded": 0,
    }[tier]
    return tier_base - len(risk_flags) - len(blocking_gaps)


def _sort_key(candidate: HttpMutationVerificationCandidate) -> tuple[int, int, str]:
    tier_order = {
        "verified_noop": -1,
        "priority_noop_candidate": 0,
        "roundtrip_candidate": 1,
        "high_risk_deferred": 2,
        "evidence_blocked": 3,
        "destructive_excluded": 4,
    }
    return (tier_order[candidate.tier], -candidate.priority_score, candidate.endpoint.name)
