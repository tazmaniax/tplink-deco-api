"""Prioritize bounded TMP mutation verification without contacting a router."""

from __future__ import annotations

from .models import TmpMutationPlan, TmpMutationVerificationCandidate
from .tmp_mutation_planner import build_tmp_mutation_plan
from .tmp_opcode_catalog import TMP_OPCODE_CATALOG

_CANDIDATE_TIERS: frozenset[str] = frozenset(
    {
        "priority_noop_candidate",
        "secondary_noop_candidate",
        "roundtrip_candidate",
    }
)
_CONNECTIVITY_MARKERS: tuple[str, ...] = (
    "_WAN_",
    "_WIRELESS_",
    "_LAN_IP_",
    "_DHCP_",
    "_VLAN_",
    "_IPTV_",
    "_IPV4_",
    "_IPV6_",
    "_MAC_CLONE_",
    "_OPERATION_MODE_",
    "_NETWORK_SEARCH_",
    "_BAND_SEARCH_",
)
_PRIVILEGE_MARKERS: tuple[str, ...] = (
    "_ACCOUNT_",
    "_CLOUD_ACCOUNT_",
    "_MANAGER_PERMISSION_",
    "_OWNER_LIST_",
    "_TRANSFER_OWNERSHIP",
)
_SECURITY_POLICY_MARKERS: tuple[str, ...] = (
    "_ACCESS_CONTROL_",
    "_BLACKLIST_",
    "_FIREWALL_",
    "_SECURITY_",
    "_WHITELIST_",
)
_P9_OBSERVED_AT_CAPACITY: frozenset[str] = frozenset({"TMP_APPV2_OP_IP_RESERVATION_LIST_ADD"})
_ACTIVE_ACTION_MARKERS: tuple[str, ...] = (
    "_WPS_",
    "_ONE_CLICK_",
    "_SCAN",
    "_START",
    "_STOP",
    "_OPTIMIZE",
    "_EXPORT",
    "_DOWNLOAD",
    "_WAKE",
    "_RING",
    "_REBOOT",
    "_SYNC",
    "_TRANSFER_OWNERSHIP",
)
_STRUCTURED_STATE_MARKERS: tuple[str, ...] = (
    "_AUTOMATION_",
    "_CLIENT_LIST_",
    "_FIREWALL_",
    "_IOT_SPACE_",
    "_OWNER_",
    "_PARENT_CTRL_",
    "_PORT_FORWARDING_",
    "_RESERVATION_",
    "_WHITELIST_",
)


def build_tmp_mutation_verification_queue(
    *,
    include_sensitive: bool = False,
    include_deferred: bool = False,
    include_destructive: bool = False,
    limit: int | None = 20,
) -> tuple[TmpMutationVerificationCandidate, ...]:
    """Return ranked offline candidates for separately authorized verification."""
    if limit is not None and limit <= 0:
        raise ValueError("Failed to rank TMP mutations: limit must be positive")
    ranked = sorted(
        (
            _candidate(build_tmp_mutation_plan(opcode.code))
            for opcode in TMP_OPCODE_CATALOG
            if opcode.safety in {"mutation", "destructive"}
        ),
        key=_sort_key,
    )
    selected = tuple(
        candidate
        for candidate in ranked
        if (include_sensitive or candidate.plan.sensitivity != "secret")
        and (
            include_deferred
            or candidate.tier in _CANDIDATE_TIERS
            or (include_destructive and candidate.tier == "destructive_excluded")
        )
        and (include_destructive or candidate.tier != "destructive_excluded")
    )
    return selected if limit is None else selected[:limit]


def _candidate(plan: TmpMutationPlan) -> TmpMutationVerificationCandidate:
    risk_flags = _risk_flags(plan)
    blocking_gaps = _blocking_gaps(plan)
    strategy = _verification_strategy(plan)
    tier = _tier(plan, strategy, risk_flags, blocking_gaps)
    return TmpMutationVerificationCandidate(
        plan=plan,
        tier=tier,
        priority_score=_priority_score(plan, tier, risk_flags, blocking_gaps),
        verification_strategy=strategy,
        risk_flags=risk_flags,
        blocking_gaps=blocking_gaps,
    )


def _risk_flags(plan: TmpMutationPlan) -> tuple[str, ...]:
    flags: list[str] = []
    if plan.safety == "destructive":
        flags.append("destructive_operation")
    if plan.sensitivity == "secret":
        flags.append("secret_state")
    if any(marker in plan.name for marker in _CONNECTIVITY_MARKERS):
        flags.append("network_connectivity_change")
    if any(marker in plan.name for marker in _ACTIVE_ACTION_MARKERS):
        flags.append("active_workflow_or_runtime_action")
    if any(marker in plan.name for marker in _STRUCTURED_STATE_MARKERS):
        flags.append("structured_state_change")
    if any(marker in plan.name for marker in _PRIVILEGE_MARKERS):
        flags.append("access_or_ownership_change")
    if any(marker in plan.name for marker in _SECURITY_POLICY_MARKERS):
        flags.append("security_policy_change")
    if plan.name in _P9_OBSERVED_AT_CAPACITY:
        flags.append("p9_observed_collection_at_capacity")
    if plan.app_set_dispatch_review:
        flags.append("signed_app_set_dispatched_side_effect")
    if plan.preflight_relationship_evidence == "signed_app_opcode_name_pair_inference":
        flags.append("inferred_preflight_relationship")
    if plan.rollback_relationship_evidence == "signed_app_inverse_name_pair_inference":
        flags.append("inferred_rollback_relationship")
    if len(plan.app_candidate_parameter_keys) > 3:
        flags.append("broad_static_parameter_union")
    return tuple(flags)


def _blocking_gaps(plan: TmpMutationPlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if plan.preflight_code is None:
        gaps.append("preflight_relationship_missing")
    elif plan.preflight_observation != "returned_data":
        gaps.append(f"preflight_observation_{plan.preflight_observation}")
    if plan.rollback_code is None:
        gaps.append("rollback_relationship_missing")
    if not plan.parameter_contract.startswith("static_app_candidate_keys:"):
        gaps.append("key_level_parameter_contract_missing")
    if plan.preflight_missing_candidate_keys:
        gaps.append(
            "preflight_missing_candidate_keys:" + ",".join(plan.preflight_missing_candidate_keys)
        )
    return tuple(gaps)


def _verification_strategy(plan: TmpMutationPlan) -> str:
    if plan.rollback_code == plan.code and plan.name.endswith(("_SET", "_MODIFY")):
        return "same_value_noop_then_restore"
    if plan.rollback_code is not None:
        return "bounded_roundtrip_then_restore"
    return "none"


def _tier(
    plan: TmpMutationPlan,
    strategy: str,
    risk_flags: tuple[str, ...],
    blocking_gaps: tuple[str, ...],
) -> str:
    if plan.p9_mutation_observation == "verified_noop":
        return "verified_noop"
    if plan.safety == "destructive":
        return "destructive_excluded"
    if {
        "active_workflow_or_runtime_action",
        "access_or_ownership_change",
        "network_connectivity_change",
        "p9_observed_collection_at_capacity",
        "security_policy_change",
        "signed_app_set_dispatched_side_effect",
    }.intersection(risk_flags):
        return "high_risk_deferred"
    if blocking_gaps:
        return "evidence_blocked"
    if strategy == "same_value_noop_then_restore":
        if (
            plan.sensitivity == "private"
            and "structured_state_change" not in risk_flags
            and len(plan.app_candidate_parameter_keys) <= 3
        ):
            return "priority_noop_candidate"
        return "secondary_noop_candidate"
    if strategy == "bounded_roundtrip_then_restore":
        return "roundtrip_candidate"
    return "evidence_blocked"


def _priority_score(
    plan: TmpMutationPlan,
    tier: str,
    risk_flags: tuple[str, ...],
    blocking_gaps: tuple[str, ...],
) -> int:
    tier_base = {
        "verified_noop": 120,
        "priority_noop_candidate": 100,
        "secondary_noop_candidate": 80,
        "roundtrip_candidate": 60,
        "high_risk_deferred": 30,
        "evidence_blocked": 10,
        "destructive_excluded": 0,
    }[tier]
    evidence_bonus = sum(
        (
            plan.preflight_observation == "returned_data",
            plan.rollback_code is not None,
            plan.parameter_contract.startswith("static_app_candidate_keys:"),
            plan.preflight_relationship_evidence == "curated_opcode_relationship",
        )
    )
    return tier_base + evidence_bonus - len(risk_flags) - len(blocking_gaps)


def _sort_key(candidate: TmpMutationVerificationCandidate) -> tuple[int, int, int, int]:
    tier_order = {
        "verified_noop": -1,
        "priority_noop_candidate": 0,
        "secondary_noop_candidate": 1,
        "roundtrip_candidate": 2,
        "high_risk_deferred": 3,
        "evidence_blocked": 4,
        "destructive_excluded": 5,
    }
    return (
        tier_order[candidate.tier],
        -candidate.priority_score,
        len(candidate.plan.app_candidate_parameter_keys),
        candidate.plan.code,
    )
