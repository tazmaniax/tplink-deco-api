"""Tests for endpoint metadata used by discovery and future MCP tools."""

from __future__ import annotations

import pytest

from tplink_deco_api import (
    CAPABILITY_ENDPOINTS,
    CATALOG_VERSION,
    DISCOVERABLE_READ_ENDPOINTS,
    ENDPOINT_CATALOG,
    MUTATION_ENDPOINTS,
    P9_MUTATION_CANDIDATES,
    P9_PROFILE_FIRMWARE,
    P9_PROFILE_HARDWARE_VERSIONS,
    P9_READ_ENDPOINTS,
    READ_ONLY_ENDPOINTS,
    EndpointSpec,
    get_endpoint,
)


def test_catalog_has_unique_stable_names_and_broad_coverage() -> None:
    names = tuple(endpoint.name for endpoint in ENDPOINT_CATALOG)
    controllers = {endpoint.path for endpoint in ENDPOINT_CATALOG}

    assert CATALOG_VERSION == 4
    assert len(names) == 570
    assert len(names) == len(set(names))
    assert len(controllers) >= 62
    assert "admin/client" in controllers
    assert "admin/quick_setup" in controllers
    assert "admin/sync" in controllers


def test_catalog_partitions_read_and_non_read_operations() -> None:
    read_names = {endpoint.name for endpoint in READ_ONLY_ENDPOINTS}
    mutation_names = {endpoint.name for endpoint in MUTATION_ENDPOINTS}
    catalog_names = {endpoint.name for endpoint in ENDPOINT_CATALOG}

    assert read_names.isdisjoint(mutation_names)
    assert read_names | mutation_names == catalog_names
    assert any(endpoint.safety == "mutation" for endpoint in MUTATION_ENDPOINTS)
    assert any(endpoint.safety == "destructive" for endpoint in MUTATION_ENDPOINTS)
    assert any(endpoint.safety == "internal" for endpoint in MUTATION_ENDPOINTS)


def test_discovery_sets_exclude_secrets_and_writes() -> None:
    for endpoint in (
        *CAPABILITY_ENDPOINTS,
        *P9_READ_ENDPOINTS,
        *DISCOVERABLE_READ_ENDPOINTS,
    ):
        assert endpoint.safety == "read_only"
        assert endpoint.sensitivity != "secret"
        assert endpoint.generic_call_supported or endpoint.bootstrap_call_supported


def test_p9_profile_separates_observed_reads_from_untested_mutations() -> None:
    supported_forms = {(endpoint.path, endpoint.form) for endpoint in P9_READ_ENDPOINTS}

    assert len(P9_READ_ENDPOINTS) == 37
    assert len(P9_MUTATION_CANDIDATES) == 23
    assert P9_PROFILE_FIRMWARE == "1.3.0 Build 20250804 Rel. 58832"
    assert P9_PROFILE_HARDWARE_VERSIONS == ("1.0", "2.0")
    assert all(endpoint.safety != "read_only" for endpoint in P9_MUTATION_CANDIDATES)
    assert all(
        (endpoint.path, endpoint.form) in supported_forms for endpoint in P9_MUTATION_CANDIDATES
    )
    assert get_endpoint("admin.device.device_list.remove") in P9_MUTATION_CANDIDATES
    assert get_endpoint("admin.cloud.firmware_status.check") in P9_READ_ENDPOINTS
    assert get_endpoint("admin.cloud.firmware_status.check_upgrade") in P9_READ_ENDPOINTS
    assert get_endpoint("login.auth.read") in P9_READ_ENDPOINTS
    assert get_endpoint("login.keys.read") in P9_READ_ENDPOINTS
    assert get_endpoint("login.check_factory_default.read") in P9_READ_ENDPOINTS


def test_catalog_covers_detailed_documentation_and_special_transports() -> None:
    names = {endpoint.name for endpoint in ENDPOINT_CATALOG}
    documented_samples = {
        "admin.device.mini_device_list.read",
        "admin.client.traffic_stat.list",
        "admin.wireless.bridge.read",
        "admin.smart_network.patrol_filter.get",
        "admin.smart_network.tmp_avira.getOwnerInList",
        "admin.cloud.firmware.sync_check_firmware",
        "admin.cloud.system.transfer",
        "admin.cloud_account.check_cloud_connection.read",
        "admin.iot_device.iotdevice.inner_client_netdev_req",
        "admin.iot_device.iotspace.set_network_device",
        "admin.iot_device.iotrole.commission_complete",
        "admin.iot_automation.iotautomation.remove_triggerlist",
        "admin.iot_automation.iotoneclick.remove_actionlist",
        "admin.vpnconn.cert.sync",
        "admin.administration.account.mcu_write",
        "admin.quick_setup.eponymous_detect.read",
        "discover.sync_master_check.read",
        "admin.sync.sync_download_status_lte.read",
        "admin.telemetry_collect.telemetry_control.read",
    }

    assert documented_samples <= names
    assert get_endpoint("login.auth.read").authentication == "bootstrap"
    assert get_endpoint("login.auth.read").bootstrap_call_supported
    assert get_endpoint("login.keys.read").bootstrap_call_supported
    assert get_endpoint("login.check_factory_default.read").bootstrap_call_supported
    assert get_endpoint("login.default_info.read").bootstrap_call_supported
    domain_login = get_endpoint("domain_login.dlogin.read")
    assert domain_login.authentication == "encrypted"
    assert domain_login.generic_call_supported
    assert not domain_login.bootstrap_call_supported
    assert not get_endpoint("login.login.login").bootstrap_call_supported
    assert get_endpoint("discover.sync_master_check.read").authentication == "group_key"
    assert get_endpoint("admin.sync.sync_get_cfg.read").authentication == "token"
    assert not get_endpoint("admin.sync.sync_get_cfg.read").generic_call_supported
    assert get_endpoint("admin.iot_device.iotrole.get_pairing_code").safety == "mutation"
    assert get_endpoint("admin.wireless.operation_mode.write").required_params == ("mode",)
    assert get_endpoint("admin.wireless.operation_mode.write").contract_source == "documented"
    assert get_endpoint("admin.network.vlan.write").required_params == ("vlan_id",)
    assert get_endpoint("admin.network.vlan.write").optional_params == ("enable",)
    assert get_endpoint("admin.time_setting.request.read").safety == "read_only"
    assert get_endpoint("admin.time_setting.notify.write").safety == "mutation"
    assert not get_endpoint("admin.route.route.read").form_selector


def test_catalog_includes_p9_web_asset_contracts() -> None:
    reboot = get_endpoint("admin.device.system.reboot")
    flow_control = get_endpoint("admin.network.flow_control.write")
    cwmp = get_endpoint("admin.cwmp.cwmp_info.write")

    assert reboot.safety == "destructive"
    assert reboot.required_params == ("mac_list",)
    assert reboot.contract_source == "firmware_asset"
    assert flow_control.required_params == ("enable_flow_control",)
    assert flow_control.contract_source == "firmware_asset"
    assert "ACS_Password" in cwmp.optional_params
    assert cwmp.sensitivity == "secret"
    assert get_endpoint("locale.list.read").response_kind == "list"
    assert get_endpoint("admin.cloud_account.get_deviceInfo.read").sensitivity == "private"
    assert get_endpoint("admin.folder_sharing.tree.read").safety == "read_only"


def test_get_endpoint_and_metadata_roundtrip() -> None:
    endpoint = get_endpoint("admin.client.addr_reservation.getlist")

    assert endpoint.path == "admin/client"
    assert endpoint.form == "addr_reservation"
    assert endpoint.operation == "getlist"
    assert endpoint.safety == "read_only"
    assert endpoint.sensitivity == "private"
    assert endpoint.to_dict()["name"] == endpoint.name
    assert endpoint.documentation == "docs/endpoints/clients.md"
    assert endpoint.to_dict()["documentation"] == endpoint.documentation
    assert endpoint.to_dict()["form_selector"] is True
    assert endpoint.to_dict()["bootstrap_call_supported"] is False

    binary = get_endpoint("admin.log_export.save_log.download")
    assert binary.response_kind == "binary"
    assert binary.media_type == "text/plain"
    assert binary.binary_call_supported

    backup = get_endpoint("admin.firmware.config.backup")
    assert backup.authentication == "encrypted"
    assert backup.response_kind == "binary"
    assert backup.binary_call_supported
    assert not backup.generic_call_supported

    multipart_backup = get_endpoint("admin.firmware.config_multipart.backup")
    assert multipart_backup.authentication == "multipart"
    assert multipart_backup.response_kind == "binary"
    assert multipart_backup.binary_call_supported
    assert multipart_backup.contract_source == "firmware_asset"
    assert not multipart_backup.generic_call_supported

    mutation = get_endpoint("admin.client.addr_reservation.add")
    assert mutation.required_params == ("mac", "ip")
    assert mutation.optional_params == ()
    assert mutation.contract_source == "documented"
    assert not mutation.idempotent
    assert mutation.impact == "changes configuration or runtime state"
    assert mutation.to_dict()["required_params"] == ["mac", "ip"]
    assert mutation.generic_call_supported
    assert not mutation.binary_call_supported

    read = get_endpoint("admin.network.performance.read")
    assert read.idempotent
    assert read.impact == "retrieves state without intended mutation"

    special = get_endpoint("admin.sync.sync_get_info.read")
    assert not special.generic_call_supported
    assert not special.binary_call_supported

    with pytest.raises(KeyError, match="Unknown Deco endpoint operation"):
        get_endpoint("admin.missing.form.read")


def test_endpoint_request_data_uses_defaults_and_explicit_params() -> None:
    endpoint = EndpointSpec(
        "admin/client",
        "client_list",
        "read",
        default_params={"device_mac": "default"},
    )

    assert endpoint.request_data() == {
        "operation": "read",
        "params": {"device_mac": "default"},
    }
    assert endpoint.request_data({"device_mac": "node"}) == {
        "operation": "read",
        "params": {"device_mac": "node"},
    }


def test_endpoint_request_data_validates_documented_required_params() -> None:
    endpoint = get_endpoint("admin.network.wan_mode.write")

    assert endpoint.missing_params() == ("mode",)
    assert endpoint.missing_params({"mode": "router"}) == ()
    with pytest.raises(ValueError, match="missing required params: mode"):
        endpoint.request_data({})
