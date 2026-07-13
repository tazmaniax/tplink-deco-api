"""Tests for offline P9 HTTP mutation-verification ranking."""

from __future__ import annotations

import pytest

from tplink_deco_api import build_http_mutation_verification_queue


def test_default_http_queue_contains_no_unverified_safe_candidates() -> None:
    queue = build_http_mutation_verification_queue(limit=None)

    assert queue == ()


def test_complete_http_queue_preserves_evidence_and_risk_reasons() -> None:
    queue = build_http_mutation_verification_queue(
        include_deferred=True,
        include_destructive=True,
        include_verified=True,
        limit=None,
    )
    tier_counts = {
        tier: sum(candidate.tier == tier for candidate in queue)
        for tier in {candidate.tier for candidate in queue}
    }

    assert len(queue) == 24
    assert tier_counts == {
        "destructive_excluded": 3,
        "evidence_blocked": 2,
        "high_risk_deferred": 15,
        "verified_noop": 4,
    }
    assert not any(candidate.verification_candidate for candidate in queue)
    assert not any(candidate.to_dict()["execution_eligible"] for candidate in queue)
    assert {candidate.plan.name for candidate in queue if candidate.tier == "verified_noop"} == {
        "admin.client.addr_reservation.modify",
        "admin.device.timesetting.write",
        "admin.wireless.beamforming.write",
        "admin.wireless.ieee80211r.write",
    }

    wan = next(
        candidate for candidate in queue if candidate.plan.name == "admin.network.wan_mode.write"
    )
    assert wan.tier == "high_risk_deferred"
    assert wan.blocking_gaps == ()
    assert "network_connectivity_change" in wan.risk_flags

    blacklist = next(
        candidate for candidate in queue if candidate.plan.name == "admin.client.black_list.add"
    )
    assert "client_access_policy_change" in blacklist.risk_flags

    reservation = next(
        candidate
        for candidate in queue
        if candidate.plan.name == "admin.client.addr_reservation.add"
    )
    assert "p9_observed_collection_at_capacity" in reservation.risk_flags

    nickname = next(
        candidate for candidate in queue if candidate.plan.name == "admin.cloud.nickname.write"
    )
    assert nickname.tier == "evidence_blocked"
    assert "parameter_contract_missing" in nickname.blocking_gaps
    system_log = next(
        candidate
        for candidate in queue
        if candidate.plan.name == "admin.log_export.feedback_log.build"
    )
    assert system_log.tier == "evidence_blocked"
    assert system_log.plan.model_test_scope == "general"
    assert "rollback_operation_missing" in system_log.blocking_gaps


def test_http_queue_filters_are_explicit() -> None:
    verified = build_http_mutation_verification_queue(include_verified=True, limit=None)
    deferred = build_http_mutation_verification_queue(include_deferred=True, limit=None)
    destructive = build_http_mutation_verification_queue(
        include_destructive=True,
        limit=None,
    )

    assert len(verified) == 4
    assert all(candidate.tier == "verified_noop" for candidate in verified)
    assert len(deferred) == 17
    assert {candidate.tier for candidate in deferred} == {
        "evidence_blocked",
        "high_risk_deferred",
    }
    assert len(destructive) == 3
    assert all(candidate.tier == "destructive_excluded" for candidate in destructive)

    with pytest.raises(ValueError, match="limit must be positive"):
        build_http_mutation_verification_queue(limit=0)
