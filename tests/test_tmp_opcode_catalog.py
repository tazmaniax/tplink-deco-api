"""Tests for the reverse-engineered TMP/AppV2 discovery catalogue."""

from __future__ import annotations

import pytest

from tplink_deco_api import TMP_OPCODE_CATALOG, get_tmp_opcode


def test_tmp_opcode_catalog_is_unique_and_complete_for_source_map() -> None:
    codes = [opcode.code for opcode in TMP_OPCODE_CATALOG]
    names = [opcode.name for opcode in TMP_OPCODE_CATALOG]

    assert len(TMP_OPCODE_CATALOG) == 600
    assert len(codes) == len(set(codes))
    assert len(names) == len(set(names))
    assert sum(opcode.p9_opcode_tested for opcode in TMP_OPCODE_CATALOG) == 251
    assert sum(opcode.safety == "read_only" for opcode in TMP_OPCODE_CATALOG) == 246
    assert sum(opcode.safety == "mutation" for opcode in TMP_OPCODE_CATALOG) == 277
    assert sum(opcode.safety == "destructive" for opcode in TMP_OPCODE_CATALOG) == 71
    assert sum(opcode.safety == "internal" for opcode in TMP_OPCODE_CATALOG) == 6
    assert (
        sum(opcode.app_contract_status == "static_keys_recovered" for opcode in TMP_OPCODE_CATALOG)
        == 317
    )
    assert (
        sum(opcode.app_contract_status == "static_null_payload" for opcode in TMP_OPCODE_CATALOG)
        == 188
    )
    assert (
        sum(opcode.app_contract_status == "static_model_recovered" for opcode in TMP_OPCODE_CATALOG)
        == 16
    )
    assert (
        sum(opcode.app_contract_status == "no_app_call_site" for opcode in TMP_OPCODE_CATALOG) == 79
    )
    assert (
        sum(
            opcode.app_contract_provenance == "indirect_virtual_dispatch"
            for opcode in TMP_OPCODE_CATALOG
        )
        == 24
    )
    assert all(len(opcode.app_contract_sha256) == 64 for opcode in TMP_OPCODE_CATALOG)
    assert all(
        opcode.opcode_registry_source == "TP-Link Deco Android 3.10.215 build 1484"
        for opcode in TMP_OPCODE_CATALOG
    )


def test_new_signed_app_registry_operations_retain_exact_p9_evidence() -> None:
    system_time = get_tmp_opcode(0x400E)
    traffic_usage = get_tmp_opcode(0x40F2)
    smart_dhcp = get_tmp_opcode(0x4092)

    assert system_time.name == "TMP_APPV2_OP_SYSTEM_TIME"
    assert system_time.aliases == ("TMP_APPV2_OP_TIME_SYNC",)
    assert traffic_usage.name == "TMP_APPV2_OP_TRAFFIC_USAGE_GET"
    assert traffic_usage.safety == "read_only"
    assert traffic_usage.category == "statistics"
    assert traffic_usage.p9_observation == "rejected"
    assert traffic_usage.p9_appv2_error_code == 12
    assert traffic_usage.p9_tested_variants == ("json_null", "json_empty_object")
    assert traffic_usage.app_request_models == ("TrafficUsageInfoParam",)
    assert traffic_usage.app_candidate_parameter_keys == (
        "amount",
        "client_mac",
        "end_date",
        "period_mode",
        "start_date",
        "start_index",
    )
    assert traffic_usage.app_contract_sources == ("TP-Link Deco Android 3.10.215 build 1484",)
    assert traffic_usage.app_dispatch_methods == ("get",)
    assert smart_dhcp.p9_observation == "rejected"
    assert smart_dhcp.p9_appv2_error_code == 12
    assert all(
        opcode.p9_opcode_tested for opcode in TMP_OPCODE_CATALOG if opcode.safety == "read_only"
    )


def test_set_dispatched_get_names_are_secret_mutations_with_review_evidence() -> None:
    expected = {
        0x4097: "quick-setup configuration synchronization",
        0x40A5: "TSS network-configuration synchronization",
        0x4369: "OpenVPN certificate export",
    }

    for code, evidence_fragment in expected.items():
        operation = get_tmp_opcode(code)
        assert operation.name.endswith("_GET")
        assert operation.safety == "mutation"
        assert operation.sensitivity == "secret"
        assert operation.safety_evidence == ("signed_app_set_dispatch_and_workflow_side_effect")
        assert operation.app_dispatch_methods == ("set",)
        assert evidence_fragment in operation.app_set_dispatch_review
        assert operation.to_dict()["read_probe_eligible"] is False
        assert operation.to_dict()["read_probe_exclusion_reason"] == (
            operation.app_set_dispatch_review
        )


def test_tmp_plc_opcodes_report_exact_p9_rejection_evidence() -> None:
    read = get_tmp_opcode(0x424C)
    write = get_tmp_opcode(0x424D)

    assert read.name == "TMP_APPV2_OP_PLC_PAIR_GET"
    assert read.hex_code == "0x424C"
    assert read.safety == "read_only"
    assert read.category == "plc"
    assert read.p9_opcode_tested is True
    assert read.p9_observation == "rejected"
    assert read.p9_appv2_error_code == 12
    assert read.p9_tested_variants == (
        "json_null",
        "json_empty_object",
        "json_default_device",
        "json_first_device_id",
        "raw_empty",
    )
    assert read.to_dict()["wire_protocol_supported"] is True
    assert read.to_dict()["generic_call_supported"] is False
    assert write.name == "TMP_APPV2_OP_PLC_PAIR_SET"
    assert write.safety == "mutation"
    assert write.category == "plc"


def test_tmp_catalog_separates_immediate_observation_from_safety() -> None:
    operation = get_tmp_opcode(0x4209)

    assert operation.p9_opcode_tested
    assert operation.p9_mutation_observation == "same_value_immediate_verification_passed"
    assert operation.p9_mutation_safety_status == "safety_not_established"
    assert operation.p9_mutation_firmware_error_code == 0
    assert operation.p9_mutation_parameter_keys == ("enable",)
    assert operation.p9_mutation_state_unchanged is True
    assert operation.p9_mutation_rollback_attempted is False
    assert operation.p9_mutation_rollback_verified is None
    assert operation.p9_mutation_request_count == 1
    assert operation.p9_mutation_evidence_artifact.endswith("p9-tmp-ieee80211r-noop.json")

    for code, artifact in (
        (0x421C, "p9-tmp-beamforming-noop.json"),
        (0x4223, "p9-tmp-monthly-report-noop.json"),
    ):
        additional = get_tmp_opcode(code)
        assert additional.p9_mutation_observation == ("same_value_immediate_verification_passed")
        assert additional.p9_mutation_safety_status == "safety_not_established"
        assert additional.p9_mutation_firmware_error_code == 0
        assert additional.p9_mutation_parameter_keys == ("enable",)
        assert additional.p9_mutation_state_unchanged is True
        assert additional.p9_mutation_rollback_attempted is False
        assert additional.p9_mutation_request_count == 1
        assert additional.p9_mutation_evidence_artifact.endswith(artifact)


def test_monthly_report_history_is_secret_despite_private_settings() -> None:
    history = get_tmp_opcode(0x40E0)
    settings = get_tmp_opcode(0x4222)

    assert history.sensitivity == "secret"
    assert settings.sensitivity == "private"


def test_tmp_catalog_recovers_indirect_virtual_set_contracts() -> None:
    base = get_tmp_opcode(0x42C1)
    hybrid = get_tmp_opcode(0x4351)

    for operation in (base, hybrid):
        assert operation.app_contract_provenance == "indirect_virtual_dispatch"
        assert operation.app_contract_status == "static_keys_recovered"
        assert operation.app_dispatch_methods == ("set",)
        assert operation.app_request_models == ("DataSettingBean",)
        assert operation.app_candidate_parameter_keys == (
            "alert",
            "data_allowance",
            "data_usage",
            "date_start",
            "downlink_rate",
            "enable",
            "limit_mode",
            "uplink_rate",
        )
        assert operation.app_call_site_count >= 1


def test_tmp_catalog_classifies_protocol_and_destructive_operations_conservatively() -> None:
    assert get_tmp_opcode(0x0001).safety == "internal"
    assert get_tmp_opcode(0x0001).p9_observation == "accepted"
    assert get_tmp_opcode(0x4001).p9_observation == "accepted"
    assert get_tmp_opcode(0x400F).p9_observation == "returned_data"
    assert "$.result.device_list[].support_plc:boolean" in get_tmp_opcode(0x400F).p9_schema_paths
    binary = get_tmp_opcode(0x401E)
    assert binary.p9_observation == "returned_binary"
    assert binary.p9_response_size == 67
    assert len(binary.p9_response_sha256) == 64
    assert binary.to_dict()["binary_call_supported"] is True
    bridge = get_tmp_opcode(0x400D)
    assert bridge.p9_fuzzy_status == "all_rejected"
    assert bridge.p9_tested_variants == (
        "json_null",
        "json_empty_object",
        "json_default_device",
        "json_first_device_id",
        "raw_empty",
    )
    scan = get_tmp_opcode(0x422B)
    assert scan.p9_fuzzy_status == "skipped_active_scan_risk"
    assert scan.p9_tested_variants == ("json_null",)
    by_module = get_tmp_opcode(0x404B)
    assert by_module.safety == "read_only"
    assert by_module.p9_observation == "payload_rejected"
    assert by_module.p9_firmware_error_code == 1
    assert by_module.p9_tested_variants == (
        "json_null",
        "json_empty_object",
        "raw_empty",
        "module_zigbee",
        "module_tpra",
        "module_ble",
        "module_nest",
        "module_hue",
        "module_cloud",
        "module_network",
        "module_network_device",
        "module_notification",
        "module_tapo",
        "module_matter",
    )
    assert get_tmp_opcode(0x4016).safety == "destructive"
    assert get_tmp_opcode(0x4022).safety == "destructive"
    assert get_tmp_opcode(0x4009).sensitivity == "secret"

    with pytest.raises(KeyError, match="0xFFFF"):
        get_tmp_opcode(0xFFFF)


def test_tmp_catalog_exposes_recovered_parameterized_read_contracts() -> None:
    owner = get_tmp_opcode(0x402D)
    insights = get_tmp_opcode(0x402F)
    history = get_tmp_opcode(0x4031)

    assert owner.p9_observation == "returned_data"
    assert owner.p9_firmware_error_code == 0
    assert owner.p9_confirmed_parameter_sets == (("owner_id",),)
    assert owner.p9_parameter_value_source == "owner_list.owner_id"
    assert "$.result.owner_id:string" in owner.p9_schema_paths
    assert owner.to_dict()["p9_confirmed_parameter_sets"] == [["owner_id"]]
    expected_sets = (
        ("owner_id",),
        ("end_time", "owner_id", "start_time"),
        ("owner_id", "page", "page_size"),
    )
    assert insights.p9_observation == "returned_data"
    assert insights.p9_confirmed_parameter_sets == expected_sets
    assert "$.result.insights:array" in insights.p9_schema_paths
    assert history.p9_observation == "returned_data"
    assert history.p9_confirmed_parameter_sets == expected_sets
    assert "$.result.history:array" in history.p9_schema_paths

    website_apps = get_tmp_opcode(0x403A)
    iot_client = get_tmp_opcode(0x4049)
    security_categories = get_tmp_opcode(0x4201)
    security_rules = get_tmp_opcode(0x4202)
    assert website_apps.p9_observation == "returned_data"
    assert website_apps.p9_confirmed_parameter_sets == (("version",),)
    assert "$.result.website_app_list:array" in website_apps.p9_schema_paths
    assert iot_client.p9_observation == "returned_data"
    assert iot_client.p9_confirmed_parameter_sets == (("iot_client_list",),)
    assert "$.result.iot_client_list:array" in iot_client.p9_schema_paths
    assert security_categories.p9_confirmed_parameter_sets == (("version",),)
    assert security_rules.p9_confirmed_parameter_sets == (("version",),)


def test_tmp_catalog_distinguishes_exact_app_payload_rejection_from_unknown_shape() -> None:
    for code in (0x403B, 0x4040, 0x4045):
        operation = get_tmp_opcode(code)
        assert operation.p9_observation == "payload_rejected"
        assert operation.app_contract_status == "static_null_payload"
        assert operation.app_request_models == ("null",)
        assert operation.app_call_site_count == 2
        assert operation.app_contract_sources == (
            "TP-Link Deco Android 1.10.5 build 112",
            "TP-Link Deco Android 3.10.215 build 1484",
        )

    by_module = get_tmp_opcode(0x404B)
    assert by_module.p9_observation == "payload_rejected"
    assert by_module.app_contract_status == "no_app_call_site"
    assert by_module.app_request_models == ()
    assert by_module.app_call_site_count == 0

    beamforming = get_tmp_opcode(0x421C)
    assert beamforming.app_contract_status == "static_keys_recovered"
    assert beamforming.app_request_models == ("BeamformingBean",)
    assert beamforming.app_candidate_parameter_keys == ("enable",)
    assert beamforming.to_dict()["app_contract_source"] == (
        "TP-Link Deco Android 1.10.5 build 112; TP-Link Deco Android 3.10.215 build 1484"
    )
