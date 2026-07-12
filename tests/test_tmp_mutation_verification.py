"""Tests for offline TMP mutation-verification prioritization."""

from __future__ import annotations

import pytest

from tplink_deco_api import build_tmp_mutation_verification_queue


def test_queue_omits_suspected_adverse_events_by_default() -> None:
    queue = build_tmp_mutation_verification_queue(limit=None)

    assert queue == ()


def test_complete_queue_retains_deferred_and_destructive_evidence() -> None:
    queue = build_tmp_mutation_verification_queue(
        include_sensitive=True,
        include_deferred=True,
        include_destructive=True,
        limit=None,
    )
    tier_counts = {
        tier: sum(candidate.tier == tier for candidate in queue)
        for tier in {candidate.tier for candidate in queue}
    }

    assert len(queue) == 348
    assert tier_counts == {
        "destructive_excluded": 71,
        "evidence_blocked": 193,
        "high_risk_deferred": 81,
        "adverse_event_suspected": 3,
    }
    adverse = next(candidate for candidate in queue if candidate.plan.code == 0x4209)
    assert adverse.tier == "adverse_event_suspected"
    assert "post_validation_adverse_event" in adverse.risk_flags
    assert not adverse.verification_candidate
    set_dispatched = next(candidate for candidate in queue if candidate.plan.code == 0x4097)
    assert set_dispatched.tier == "high_risk_deferred"
    assert "signed_app_set_dispatched_side_effect" in set_dispatched.risk_flags
    assert not set_dispatched.verification_candidate
    assert not any(candidate.to_dict()["execution_eligible"] for candidate in queue)
    qos = next(candidate for candidate in queue if candidate.plan.code == 0x4037)
    assert qos.tier == "evidence_blocked"
    assert qos.blocking_gaps == ("preflight_missing_candidate_keys:qos_mode",)
    assert not qos.verification_candidate
    ipv4 = next(candidate for candidate in queue if candidate.plan.code == 0x4005)
    assert ipv4.tier == "high_risk_deferred"
    assert "network_connectivity_change" in ipv4.risk_flags
    manager = next(candidate for candidate in queue if candidate.plan.code == 0x422A)
    assert manager.tier == "high_risk_deferred"
    assert "access_or_ownership_change" in manager.risk_flags
    reservation = next(candidate for candidate in queue if candidate.plan.code == 0x40C1)
    assert reservation.tier == "high_risk_deferred"
    assert "p9_observed_collection_at_capacity" in reservation.risk_flags


def test_queue_filters_and_limit_are_explicit() -> None:
    sensitive = build_tmp_mutation_verification_queue(
        include_sensitive=True,
        limit=None,
    )
    destructive = build_tmp_mutation_verification_queue(
        include_sensitive=True,
        include_destructive=True,
        limit=None,
    )
    limited = build_tmp_mutation_verification_queue(limit=3)

    deferred = build_tmp_mutation_verification_queue(
        include_sensitive=True,
        include_deferred=True,
        limit=None,
    )

    assert len(sensitive) == 0
    assert not any(candidate.plan.sensitivity == "secret" for candidate in sensitive)
    assert any(candidate.plan.sensitivity == "secret" for candidate in deferred)
    assert any(candidate.tier == "destructive_excluded" for candidate in destructive)
    assert len(limited) == 0

    with pytest.raises(ValueError, match="limit must be positive"):
        build_tmp_mutation_verification_queue(limit=0)
