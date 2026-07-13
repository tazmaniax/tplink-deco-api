"""Tests for model-specific overlays on the generic endpoint catalogue."""

from __future__ import annotations

import pytest

from tplink_deco_api import (
    ENDPOINT_CATALOG,
    P9_COMPATIBILITY_PROFILE,
    P9_SENSITIVE_SCHEMA_ENDPOINTS,
    SENSITIVE_SCHEMA_ENDPOINTS,
    ModelCompatibilityProfile,
    OperationCompatibility,
    get_compatibility_profile,
)


def test_p9_profile_covers_every_catalogued_operation() -> None:
    profile = P9_COMPATIBILITY_PROFILE
    summary = profile.summary()

    assert profile is get_compatibility_profile("p9")
    assert len(profile.operations) == len(ENDPOINT_CATALOG) == 570
    assert summary["availability"] == {
        "invalid_response": 1,
        "not_found": 100,
        "rejected": 52,
        "supported": 65,
        "transport_error": 6,
        "untested": 346,
    }
    assert summary["returned_data"] == 32
    assert summary["accepted_empty"] == 28
    assert summary["asset_present"] == 94
    assert summary["mutation_tested"] == 5
    assert summary["transport_overrides"] == 1
    assert summary["sensitive_schema_observed"] == 55
    assert summary["bootstrap_observed"] == 4
    assert len(P9_SENSITIVE_SCHEMA_ENDPOINTS) == 11
    assert len(SENSITIVE_SCHEMA_ENDPOINTS) == 57
    assert {endpoint.name for endpoint in P9_SENSITIVE_SCHEMA_ENDPOINTS} < {
        endpoint.name for endpoint in SENSITIVE_SCHEMA_ENDPOINTS
    }
    assert all(endpoint.sensitivity == "secret" for endpoint in P9_SENSITIVE_SCHEMA_ENDPOINTS)
    assert all(endpoint.safety == "read_only" for endpoint in P9_SENSITIVE_SCHEMA_ENDPOINTS)
    assert all(endpoint.sensitivity == "secret" for endpoint in SENSITIVE_SCHEMA_ENDPOINTS)
    assert all(
        endpoint.generic_call_supported or endpoint.bootstrap_call_supported
        for endpoint in SENSITIVE_SCHEMA_ENDPOINTS
    )
    assert all(
        P9_COMPATIBILITY_PROFILE.get(endpoint.name).asset_present
        for endpoint in P9_SENSITIVE_SCHEMA_ENDPOINTS
    )


def test_p9_profile_records_digest_only_binary_audit_without_promoting_support() -> None:
    backup = P9_COMPATIBILITY_PROFILE.get("admin.firmware.config.backup")
    multipart = P9_COMPATIBILITY_PROFILE.get("admin.firmware.config_multipart.backup")
    log_export = P9_COMPATIBILITY_PROFILE.get("admin.log_export.save_log.download")

    assert backup.availability == multipart.availability == "transport_error"
    assert log_export.availability == "invalid_response"
    for operation in (backup, multipart, log_export):
        assert operation.confidence == "observed"
        assert "binary_digest_probe" in operation.evidence
        assert operation.verified_callable is False


def test_p9_profile_distinguishes_live_asset_and_inferred_evidence() -> None:
    performance = P9_COMPATIBILITY_PROFILE.get("admin.network.performance.read")
    locale = P9_COMPATIBILITY_PROFILE.get("locale.list.read")
    rejected = P9_COMPATIBILITY_PROFILE.get("admin.network.flow_control.read")
    wlan = P9_COMPATIBILITY_PROFILE.get("admin.wireless.wlan.read")
    cloud_ddns = P9_COMPATIBILITY_PROFILE.get("admin.cloud.ddns.get")
    account_token = P9_COMPATIBILITY_PROFILE.get("admin.cloud_account.get_token.read")
    reboot = P9_COMPATIBILITY_PROFILE.get("admin.device.system.reboot")
    inferred = P9_COMPATIBILITY_PROFILE.get("admin.network.wan_mode.write")
    generic = P9_COMPATIBILITY_PROFILE.get("admin.nat.dmz.write")
    reservation_modify = P9_COMPATIBILITY_PROFILE.get("admin.client.addr_reservation.modify")
    firmware_check = P9_COMPATIBILITY_PROFILE.get("admin.cloud.firmware_status.check")
    firmware_check_upgrade = P9_COMPATIBILITY_PROFILE.get(
        "admin.cloud.firmware_status.check_upgrade"
    )
    firmware_upgrade = P9_COMPATIBILITY_PROFILE.get("admin.firmware.upgrade.read")
    beamforming_write = P9_COMPATIBILITY_PROFILE.get("admin.wireless.beamforming.write")
    ieee80211r_write = P9_COMPATIBILITY_PROFILE.get("admin.wireless.ieee80211r.write")
    timesetting_write = P9_COMPATIBILITY_PROFILE.get("admin.device.timesetting.write")
    system_log_build = P9_COMPATIBILITY_PROFILE.get("admin.log_export.feedback_log.build")
    bootstrap_auth = P9_COMPATIBILITY_PROFILE.get("login.auth.read")
    bootstrap_keys = P9_COMPATIBILITY_PROFILE.get("login.keys.read")
    factory_default = P9_COMPATIBILITY_PROFILE.get("login.check_factory_default.read")
    default_info = P9_COMPATIBILITY_PROFILE.get("login.default_info.read")
    domain_login = P9_COMPATIBILITY_PROFILE.get("domain_login.dlogin.read")

    assert performance.availability == "supported"
    assert performance.returned_data is True
    assert performance.verified_callable
    assert "$.cpu_usage:number" in performance.schema_paths
    assert locale.availability == "supported"
    assert locale.returned_data is False
    assert "live_asset_probe" in locale.evidence
    assert domain_login.availability == "supported"
    assert domain_login.returned_data is False
    assert domain_login.schema_paths == ("$:null",)
    assert "live_asset_probe" in domain_login.evidence
    assert domain_login.verified_callable
    assert rejected.availability == "rejected"
    assert rejected.error_code == 1
    assert wlan.availability == "supported"
    assert wlan.returned_data is True
    assert "sensitive_schema_probe" in wlan.evidence
    assert "$.band2_4.host.password:string" in wlan.schema_paths
    assert "$.band5_1.guest.ssid:string" in wlan.schema_paths
    assert cloud_ddns.returned_data is True
    assert "$.ddns_info.domain_name:string" in cloud_ddns.schema_paths
    assert account_token.availability == "supported"
    assert account_token.returned_data is False
    assert account_token.schema_paths == ("$:null",)
    assert reboot.confidence == "asset_declared"
    assert not reboot.mutation_tested
    assert not reboot.verified_callable
    assert inferred.confidence == "inferred"
    assert generic.confidence == "unverified"
    assert reservation_modify.availability == "supported"
    assert reservation_modify.error_code == 0
    assert reservation_modify.mutation_tested
    assert reservation_modify.mutation_test_scope == "noop_only"
    assert "mutation_probe" in reservation_modify.evidence
    assert reservation_modify.verified_callable
    assert firmware_check.availability == "supported"
    assert firmware_check.returned_data is True
    assert "$.fw_list[].need_to_upgrade:boolean" in firmware_check.schema_paths
    assert firmware_check_upgrade.availability == "supported"
    assert firmware_check_upgrade.schema_paths == ("$.reboot_time:integer", "$:object")
    assert firmware_upgrade.availability == "not_found"
    assert firmware_upgrade.http_status == 404
    assert beamforming_write.availability == "supported"
    assert beamforming_write.error_code == 0
    assert beamforming_write.mutation_tested
    assert beamforming_write.mutation_test_scope == "noop_only"
    assert "mutation_probe" in beamforming_write.evidence
    assert beamforming_write.verified_callable
    assert ieee80211r_write.availability == "supported"
    assert ieee80211r_write.error_code == 0
    assert ieee80211r_write.mutation_tested
    assert ieee80211r_write.mutation_test_scope == "noop_only"
    assert "mutation_probe" in ieee80211r_write.evidence
    assert ieee80211r_write.verified_callable
    assert timesetting_write.availability == "supported"
    assert timesetting_write.error_code == 0
    assert timesetting_write.mutation_tested
    assert timesetting_write.mutation_test_scope == "noop_only"
    assert "mutation_probe" in timesetting_write.evidence
    assert timesetting_write.verified_callable
    assert system_log_build.availability == "supported"
    assert system_log_build.error_code == 0
    assert system_log_build.mutation_tested
    assert system_log_build.mutation_test_scope == "general"
    assert "mutation_probe" in system_log_build.evidence
    assert system_log_build.verified_callable
    assert bootstrap_auth.availability == "supported"
    assert bootstrap_auth.returned_data is True
    assert "bootstrap_probe" in bootstrap_auth.evidence
    assert bootstrap_auth.verified_callable
    assert "$.seq:integer" in bootstrap_auth.schema_paths
    assert bootstrap_keys.availability == "supported"
    assert "$.username:string" in bootstrap_keys.schema_paths
    assert factory_default.availability == "supported"
    assert factory_default.schema_paths == ("$.is_default:boolean", "$:object")
    assert default_info.availability == "transport_error"
    assert default_info.http_status == 403
    assert "bootstrap_probe" in default_info.evidence
    assert not default_info.verified_callable


def test_p9_profile_records_transport_override_without_using_it_as_proof() -> None:
    firmware = P9_COMPATIBILITY_PROFILE.get("admin.cloud.firmware.download")

    assert firmware.transport_override == "encrypted"
    assert firmware.availability == "untested"
    assert firmware.confidence == "asset_declared"
    assert not firmware.verified_callable


def test_model_profile_serialization_and_unknown_lookups() -> None:
    compact = P9_COMPATIBILITY_PROFILE.to_dict(include_operations=False)
    complete = P9_COMPATIBILITY_PROFILE.to_dict()

    assert "operations" not in compact
    assert len(complete["operations"]) == 570
    with pytest.raises(KeyError, match="Unknown model compatibility operation"):
        P9_COMPATIBILITY_PROFILE.get("admin.missing.form.read")
    with pytest.raises(KeyError, match="Unknown Deco model compatibility profile"):
        get_compatibility_profile("X99")


def test_compatibility_models_expose_confidence_branches() -> None:
    operation = OperationCompatibility(
        name="admin.test.form.read",
        availability="supported",
        evidence=("catalog", "live_asset_probe"),
        returned_data=True,
    )
    profile = ModelCompatibilityProfile(
        model="Test",
        hardware_versions=("1.0",),
        firmware_version="1.0",
        system_mode="Router",
        observed_at="2026-07-10T00:00:00Z",
        catalog_version=1,
        operations=(operation,),
    )

    assert operation.confidence == "observed"
    assert operation.to_dict()["verified_callable"] is True
    assert profile.summary()["operation_count"] == 1
