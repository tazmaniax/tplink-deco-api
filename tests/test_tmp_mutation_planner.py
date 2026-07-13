"""Tests for conservative offline TMP mutation planning."""

from __future__ import annotations

import pytest

from tplink_deco_api import build_tmp_mutation_plan
from tplink_deco_api.tmp_opcode_catalog import TMP_OPCODE_CATALOG


def test_all_tmp_writes_remain_non_executable_with_static_app_contracts() -> None:
    plans = [
        build_tmp_mutation_plan(opcode.code)
        for opcode in TMP_OPCODE_CATALOG
        if opcode.safety in {"mutation", "destructive"}
    ]

    assert len(plans) == 348
    assert sum(plan.safety == "mutation" for plan in plans) == 277
    assert sum(plan.safety == "destructive" for plan in plans) == 71
    assert sum(plan.parameter_contract != "unknown" for plan in plans) == 315
    assert sum(plan.parameter_contract == "unknown" for plan in plans) == 33
    assert sum(bool(plan.app_candidate_parameter_keys) for plan in plans) == 274
    assert sum(plan.parameter_contract == "static_app_null_payload" for plan in plans) == 27
    assert (
        sum(plan.parameter_contract.startswith("static_app_request_models:") for plan in plans)
        == 14
    )
    assert sum(plan.p9_opcode_tested for plan in plans) == 3
    assert sum(plan.p9_parameter_contract_verified for plan in plans) == 0
    assert sum(plan.complete_safety_contract for plan in plans) == 0
    assert not any(plan.to_dict()["execution_eligible"] for plan in plans)
    assert sum(plan.preflight_code is not None for plan in plans) == 222
    assert sum(plan.rollback_code is not None for plan in plans) == 188


def test_set_plan_uses_observed_read_for_preflight_and_state_restore() -> None:
    plan = build_tmp_mutation_plan(0x4209)

    assert plan.name == "TMP_APPV2_OP_11R_SET"
    assert plan.preflight_code == 0x4208
    assert plan.preflight_observation == "returned_data"
    assert plan.verification_code == 0x4208
    assert plan.rollback_code == 0x4209
    assert plan.rollback_requires_preflight
    assert plan.parameter_contract == "static_app_candidate_keys:enable"
    assert plan.app_request_models == ("FastRoamingBean",)
    assert plan.app_candidate_parameter_keys == ("enable",)
    assert plan.parameter_contract_evidence == "signed_deco_android_static_call_site"
    assert plan.preflight_relationship_evidence == "curated_opcode_relationship"
    assert plan.preflight_result_keys == ("enable",)
    assert plan.preflight_missing_candidate_keys == ()
    assert plan.verification_relationship_evidence == "curated_opcode_relationship"
    assert plan.rollback_relationship_evidence == "preflight_state_restore"
    assert plan.p9_opcode_tested
    assert not plan.p9_parameter_contract_verified
    assert plan.p9_mutation_observation == "same_value_immediate_verification_passed"
    assert plan.p9_mutation_safety_status == "safety_not_established"
    assert plan.p9_mutation_firmware_error_code == 0
    assert plan.p9_mutation_parameter_keys == ("enable",)
    assert plan.p9_mutation_state_unchanged is True
    assert plan.p9_mutation_rollback_attempted is False
    assert plan.p9_mutation_request_count == 1
    assert not plan.complete_safety_contract
    assert "operational safety is not established" in " ".join(plan.warnings)
    assert plan.to_dict()["execution_eligible"] is False


def test_qos_plan_blocks_noop_when_preflight_omits_setter_candidate_key() -> None:
    plan = build_tmp_mutation_plan(0x4037)

    assert plan.preflight_result_keys == ("custom_detail",)
    assert plan.preflight_missing_candidate_keys == ("qos_mode",)
    assert "P9 preflight schema is missing setter candidate keys: qos_mode" in plan.warnings
    assert not plan.complete_safety_contract


def test_add_plan_uses_list_preflight_and_paired_remove_rollback() -> None:
    plan = build_tmp_mutation_plan(0x40C1)

    assert plan.name == "TMP_APPV2_OP_IP_RESERVATION_LIST_ADD"
    assert plan.preflight_code == 0x40C0
    assert plan.preflight_observation == "returned_data"
    assert plan.rollback_code == 0x40C3
    assert plan.rollback_name == "TMP_APPV2_OP_IP_RESERVATION_LIST_REMOVE"
    assert plan.app_request_models == ("ReservationListBean",)
    assert plan.app_candidate_parameter_keys == (
        "reservation_list",
        "reservation_list_max_count",
    )
    assert plan.app_call_site_count == 2
    assert len(plan.app_contract_sha256) == 64
    assert plan.rollback_relationship_evidence == "curated_opcode_relationship"


def test_new_signed_app_write_uses_unambiguous_name_pair_relationships() -> None:
    plan = build_tmp_mutation_plan(0x4255)

    assert plan.name == "TMP_APPV2_OP_CPE_INTERNET_INFO_SET"
    assert plan.preflight_code == 0x4254
    assert plan.preflight_observation == "rejected"
    assert plan.preflight_relationship_evidence == "signed_app_opcode_name_pair_inference"
    assert plan.verification_code == 0x4254
    assert plan.rollback_code == 0x4255
    assert plan.rollback_relationship_evidence == "preflight_state_restore"
    assert plan.app_contract_provenance == "indirect_virtual_dispatch"
    assert plan.parameter_contract == "static_app_request_models:CpeInternetInfoBean"
    assert plan.parameter_contract_evidence == "signed_deco_android_indirect_virtual_dispatch"
    assert "preflight relationship is inferred" in " ".join(plan.warnings)


def test_set_dispatched_get_name_builds_non_executable_mutation_plan() -> None:
    plan = build_tmp_mutation_plan(0x4097)

    assert plan.name == "TMP_APPV2_OP_SYNC_CONFIG_GET"
    assert plan.safety == "mutation"
    assert plan.sensitivity == "secret"
    assert plan.safety_evidence == "signed_app_set_dispatch_and_workflow_side_effect"
    assert "quick-setup configuration synchronization" in plan.app_set_dispatch_review
    assert plan.parameter_contract == "static_app_candidate_keys:check_link"
    assert plan.preflight_code is None
    assert plan.rollback_code is None
    assert plan.to_dict()["execution_eligible"] is False


def test_rejected_preflight_is_exposed_as_safety_gap() -> None:
    plan = build_tmp_mutation_plan(0x424D)

    assert plan.name == "TMP_APPV2_OP_PLC_PAIR_SET"
    assert plan.preflight_code == 0x424C
    assert plan.preflight_observation == "rejected"
    assert plan.rollback_code == 0x424D
    assert "P9 preflight read observation is rejected" in plan.warnings
    assert not plan.complete_safety_contract


def test_destructive_plan_without_relationships_has_explicit_warnings() -> None:
    plan = build_tmp_mutation_plan(0x4016)

    assert plan.safety == "destructive"
    assert plan.preflight_code is None
    assert plan.rollback_code is None
    assert "operation is classified destructive" in plan.warnings
    assert "no preflight read relationship is known" in plan.warnings
    assert "no rollback opcode relationship is known" in plan.warnings


@pytest.mark.parametrize("code", [0x4004, 0x0001])
def test_planner_rejects_read_and_internal_opcodes(code: int) -> None:
    with pytest.raises(ValueError, match="Failed to plan TMP mutation"):
        build_tmp_mutation_plan(code)
