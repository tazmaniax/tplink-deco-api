"""Tests for mutation planning that never contacts a router."""

from __future__ import annotations

from tplink_deco_api import (
    P9_MUTATION_CANDIDATES,
    MutationPlan,
    build_mutation_plan,
    get_compatibility_profile,
    get_endpoint,
)


def _plan(
    name: str,
    params: dict[str, str],
    *,
    gate_enabled: bool = False,
) -> MutationPlan:
    endpoint = get_endpoint(name)
    compatibility = get_compatibility_profile("P9").get(name)
    return build_mutation_plan(
        endpoint,
        compatibility,
        params,
        model="P9",
        gate_enabled=gate_enabled,
    )


def test_reservation_add_plan_has_preflight_verification_and_rollback() -> None:
    plan = _plan(
        "admin.client.addr_reservation.add",
        {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.68.10"},
        gate_enabled=True,
    )

    assert plan.preflight_read == "admin.client.addr_reservation.getlist"
    assert "table has capacity" in plan.preflight_condition
    assert plan.verification_read == "admin.client.addr_reservation.getlist"
    assert plan.rollback_operation == "admin.client.addr_reservation.remove"
    assert plan.rollback_params == {
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.168.68.10",
    }
    assert plan.rollback_requires_preflight
    assert plan.parameters_valid
    assert plan.ready_for_explicit_test
    assert plan.model_verified is False
    assert len(plan.confirmation_sha256) == 64
    assert "P9 mutation has not been tested" in plan.warnings


def test_reservation_modify_and_remove_require_preflight_snapshot_for_rollback() -> None:
    modify = _plan(
        "admin.client.addr_reservation.modify",
        {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.68.11"},
    )
    remove = _plan(
        "admin.client.addr_reservation.remove",
        {"mac": "AA:BB:CC:DD:EE:FF"},
    )

    assert modify.rollback_operation == "admin.client.addr_reservation.modify"
    assert modify.rollback_params is None
    assert modify.rollback_requires_preflight
    assert remove.rollback_operation == "admin.client.addr_reservation.add"
    assert remove.rollback_params is None
    assert remove.rollback_requires_preflight
    assert not modify.ready_for_explicit_test
    assert "mutation gate is disabled" in modify.warnings


def test_plan_reports_missing_parameters_and_unknown_rollback() -> None:
    plan = _plan("admin.network.lan_ip.write", {})
    serialized = plan.to_dict()

    assert plan.missing_params == ("ip", "mask")
    assert not plan.parameters_valid
    assert plan.rollback_operation == ""
    assert "missing required params: ip, mask" in plan.warnings
    assert "no automatic rollback contract is known" in plan.warnings
    assert "firmware asset and documented LAN IP parameter names conflict" in plan.warnings
    assert serialized["ready_for_explicit_test"] is False


def test_plan_confirmation_is_deterministic_and_binds_parameters() -> None:
    first = _plan(
        "admin.client.addr_reservation.add",
        {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.68.10"},
    )
    reordered = _plan(
        "admin.client.addr_reservation.add",
        {"ip": "192.168.68.10", "mac": "AA:BB:CC:DD:EE:FF"},
    )
    changed = _plan(
        "admin.client.addr_reservation.add",
        {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.68.11"},
    )

    assert first.confirmation_sha256 == reordered.confirmation_sha256
    assert first.confirmation_sha256 != changed.confirmation_sha256


def test_every_p9_mutation_candidate_has_same_form_preflight_and_verification() -> None:
    for endpoint in P9_MUTATION_CANDIDATES:
        compatibility = get_compatibility_profile("P9").get(endpoint.name)
        plan = build_mutation_plan(
            endpoint,
            compatibility,
            None,
            model="P9",
            gate_enabled=False,
        )

        assert plan.preflight_read
        assert plan.verification_read == plan.preflight_read


def test_documented_reversible_mutations_have_rollback_contracts() -> None:
    expected = {
        "admin.network.wan_mode.write": "admin.network.wan_mode.write",
        "admin.wireless.ieee80211r.write": "admin.wireless.ieee80211r.write",
        "admin.wireless.beamforming.write": "admin.wireless.beamforming.write",
        "admin.wireless.operation_mode.write": "admin.wireless.operation_mode.write",
        "admin.device.timesetting.write": "admin.device.timesetting.write",
        "admin.client.black_list.add": "admin.client.black_list.remove",
        "admin.client.black_list.remove": "admin.client.black_list.add",
    }

    for name, rollback in expected.items():
        endpoint = get_endpoint(name)
        params: dict[str, str | bool] = {key: "value" for key in endpoint.required_params}
        if "enable" in params:
            params["enable"] = True
        plan = build_mutation_plan(
            endpoint,
            get_compatibility_profile("P9").get(name),
            params,
            model="P9",
            gate_enabled=True,
        )

        assert plan.rollback_operation == rollback
        assert plan.rollback_requires_preflight
