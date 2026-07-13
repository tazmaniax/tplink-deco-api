"""Tests for protocol-neutral capability routing and safe read fallback."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING
from unittest import mock

import pytest

from tests.response_contract_assertions import assert_response_contract
from tplink_deco_api import (
    CAPABILITY_ROUTES,
    HTTP_NOOP_CONFIRMATIONS,
    MUTATION_CAPABILITY_ROUTES,
    ApiResponse,
    AuthenticationError,
    Device,
    TransportError,
    get_capability_route,
    get_mutation_capability_route,
)
from tplink_deco_api.exceptions import ConfirmationError, UnknownPlanError
from tplink_deco_api.mcp.server import create_server
from tplink_deco_api.responses import (
    CapabilitiesResponse,
    CapabilityResponse,
    ClientsResponse,
    ConfigurationResponse,
    DhcpConfigurationResponse,
    IptvConfigurationResponse,
    Ipv6ConfigurationResponse,
    Ipv6DevicesResponse,
    Ipv6FirewallResponse,
    LanConfigurationResponse,
    MacCloneResponse,
    MeshResponse,
    MutationExecutionResponse,
    MutationPlanCreatedResponse,
    MutationPlanStatusResponse,
    MutationPreflightResponse,
    MutationResponse,
    MutationsResponse,
    NetworkStatusResponse,
    PortForwardingResponse,
    SipAlgResponse,
    VlanConfigurationResponse,
)
from tplink_deco_api.server import ServerConfig
from tplink_deco_api.service import DecoService

if TYPE_CHECKING:
    from tplink_deco_api._json import JsonObject


def _config() -> ServerConfig:
    return ServerConfig(
        host="192.0.2.1",
        username="admin",
        password="secret",
        timeout=60.0,
    )


def _p9_device() -> Device:
    return Device.from_api(_device_payload())


def _device_payload(*, model: str = "P9") -> dict[str, str]:
    return {
        "mac": "AA:BB:CC:DD:EE:FF",
        "device_ip": "192.0.2.1",
        "device_model": model,
        "role": "master",
        "hardware_ver": "2.0",
        "software_ver": "1.3.0 Build 20250804 Rel. 58832",
    }


def _internet_payload() -> JsonObject:
    ip_status = {
        "inet_status": "connected",
        "dial_status": "connected",
        "connect_type": "dynamic",
        "auto_detect_type": "dynamic",
        "error_code": 0,
    }
    return {"ipv4": ip_status, "ipv6": ip_status, "link_status": "up"}


def test_capability_registry_contains_only_read_fallbacks() -> None:
    assert [route.name for route in CAPABILITY_ROUTES] == [
        "mesh_nodes",
        "clients",
        "internet_status",
        "address_reservations",
        "fast_roaming",
        "beamforming",
        "ipv6_configuration",
        "ipv6_firewall",
        "ipv6_clients",
        "lan_configuration",
        "dhcp_configuration",
        "vlan_configuration",
        "port_forwarding",
        "iptv_configuration",
        "sip_alg",
        "mac_clone",
    ]
    assert all(route.fallback_policy == "equivalent_read_only" for route in CAPABILITY_ROUTES[:6])
    assert all(route.fallback_policy == "none" for route in CAPABILITY_ROUTES[6:])
    assert all(route.primary_interface == "tmp_appv2" for route in CAPABILITY_ROUTES[6:])
    assert all(
        route.to_dict()["automatic_mutation_fallback"] is False for route in CAPABILITY_ROUTES
    )
    assert get_capability_route("beamforming").fallback_operation == "0x421B"

    with pytest.raises(KeyError, match="Unknown Deco capability"):
        get_capability_route("unknown")


def test_mutation_capability_registry_has_fixed_routes_without_fallback() -> None:
    assert [route.name for route in MUTATION_CAPABILITY_ROUTES] == [
        "beamforming",
        "fast_roaming",
        "time_settings",
    ]
    assert all(route.to_dict()["fallback_policy"] == "none" for route in MUTATION_CAPABILITY_ROUTES)
    assert all(
        route.to_dict()["automatic_fallback"] is False for route in MUTATION_CAPABILITY_ROUTES
    )
    assert get_mutation_capability_route("beamforming").interface == "http_luci"
    with pytest.raises(KeyError, match="Unknown Deco mutation capability"):
        get_mutation_capability_route("monthly_report")

    with pytest.raises(KeyError, match="Unknown Deco mutation capability"):
        get_mutation_capability_route("unknown")


def test_capability_routes_are_offline_and_report_fallback_readiness() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        result = service.capability_routes()

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()
    assert result["caller_selects_protocol"] is False
    assert result["automatic_mutation_fallback"] is False
    assert result["diagnostics_exposed"] is False
    assert len(result["routes"]) == 16
    assert len(result["mutation_routes"]) == 3
    assert not any(route["fallback_gate_enabled"] for route in result["routes"])
    assert not any(route["all_environment_gates_enabled"] for route in result["mutation_routes"])
    assert result["routes"][0]["primary_configured"] is True
    assert result["routes"][0]["primary_connected"] is False
    assert result["routes"][-1]["primary_configured"] is False
    assert result["routes"][-1]["primary_gate_enabled"] is False


def test_capability_mutation_plan_is_offline_and_protocol_fixed() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        http_plan = service.plan_capability_mutation("beamforming")
        with pytest.raises(ValueError, match="unknown capability"):
            service.plan_capability_mutation("monthly_report")

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()
    assert http_plan["interface"] == "http_luci"
    assert http_plan["operation"] == "admin.wireless.beamforming.write"
    assert http_plan["confirmation"] == HTTP_NOOP_CONFIRMATIONS[http_plan["operation"]]
    assert http_plan["fallback_policy"] == "none"
    assert http_plan["router_contacted"] is False
    assert http_plan["mutation_invoked"] is False


def test_unified_noop_rejects_wrong_confirmation_before_transport() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(PermissionError, match="exact per-call confirmation"),
    ):
        service.verify_setting_noop("beamforming", "wrong")

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()


def test_unified_http_noop_uses_fixed_route_without_fallback() -> None:
    service = DecoService(_config())
    result = {"status": "verified_noop", "verified_noop": True}

    with mock.patch.object(service, "verify_p9_http_noop", return_value=result) as verifier:
        evidence = service.verify_setting_noop(
            "beamforming",
            HTTP_NOOP_CONFIRMATIONS["admin.wireless.beamforming.write"],
        )

    verifier.assert_called_once_with(
        "admin.wireless.beamforming.write",
        HTTP_NOOP_CONFIRMATIONS["admin.wireless.beamforming.write"],
    )
    assert evidence["selected_interface"] == "http_luci"
    assert evidence["fallback_policy"] == "none"
    assert evidence["fallback_used"] is False


def test_unified_monthly_report_write_has_no_server_executor() -> None:
    config = replace(
        _config(),
        allow_mutations=True,
        allow_tmp_reads=True,
        allow_tmp_noop_verification=True,
    )
    service = DecoService(config)
    with (
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(ValueError, match="unknown capability"),
    ):
        service.verify_setting_noop("monthly_report", "ignored")

    get_tmp_client.assert_not_called()


def test_capability_read_prefers_http_and_returns_provenance() -> None:
    service = DecoService(_config())
    client = mock.Mock()
    client.get_device_list.return_value = [_p9_device()]
    client.get_beamforming.return_value = {"enable": True}

    with (
        mock.patch.object(service, "_get_client", return_value=client),
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        result = service.read_capability("beamforming")

    assert_response_contract(CapabilityResponse, result)
    get_tmp_client.assert_not_called()
    assert result["data"] == {"enabled": True}
    assert result["provenance"] == {
        "source_interface": "http_luci",
        "source_operation": "admin.wireless.beamforming.read",
        "fallback_used": False,
        "fallback_policy": "equivalent_read_only",
        "equivalence_evidence": "p9_live_boolean_contract",
        "attempts": [
            {
                "interface": "http_luci",
                "operation": "admin.wireless.beamforming.read",
                "status": "ok",
            }
        ],
    }
    assert result["mutation_invoked"] is False


def test_capability_read_falls_back_to_tmp_after_http_transport_failure() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.return_value = [_p9_device()]
    http_client.get_beamforming.side_effect = TransportError("temporary failure")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"enable": False},
    }

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        result = service.read_capability("beamforming")

    tmp_client.request_read_json.assert_called_once_with(0x421B, None)
    assert result["data"] == {"enabled": False}
    assert result["provenance"]["source_interface"] == "tmp_appv2"
    assert result["provenance"]["fallback_used"] is True
    assert result["provenance"]["attempts"] == [
        {
            "interface": "http_luci",
            "operation": "admin.wireless.beamforming.read",
            "status": "error",
            "error_type": "TransportError",
        },
        {
            "interface": "tmp_appv2",
            "operation": "0x421B",
            "status": "ok",
        },
    ]


def test_capability_read_does_not_fallback_when_tmp_gate_is_disabled() -> None:
    service = DecoService(_config())
    http_client = mock.Mock()
    http_client.get_device_list.return_value = [_p9_device()]
    http_client.get_beamforming.side_effect = TransportError("temporary failure")

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(TransportError, match="temporary failure"),
    ):
        service.read_capability("beamforming")

    get_tmp_client.assert_not_called()


def test_secret_capability_requires_one_logical_gate_before_transport_selection() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"),
    ):
        service.read_capability("clients")

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()


def test_connected_resources_distinguish_mesh_devices_and_reservations() -> None:
    service = DecoService(_config())
    client = mock.Mock()
    client.get_device_list.return_value = [_p9_device()]

    with mock.patch.object(service, "_get_client", return_value=client):
        mesh = service.device_inventory()
        cached = service.device_inventory()

    assert_response_contract(MeshResponse, mesh)
    assert_response_contract(MeshResponse, cached)
    assert mesh["controller"]["model"] == "P9"
    assert mesh["profile_match"] == "exact"
    assert mesh["identity_interface"] == "http_luci"
    assert mesh["fallback_used"] is False
    assert mesh["identity_attempts"] == [
        {
            "interface": "http_luci",
            "operation": "admin.device.device_list.read",
            "status": "ok",
        }
    ]
    assert mesh["router_contacted"] is True
    assert cached["cached"] is True
    client.get_device_list.assert_called_once_with()

    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        service.client_devices_resource()
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        service.address_reservations_resource()


def test_device_inventory_bootstraps_through_tmp_when_http_is_unavailable() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"device_list": [_device_payload()]},
    }

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        mesh = service.device_inventory()
        cached = service.device_inventory()
        capability = service.read_capability("mesh_nodes")

    assert_response_contract(MeshResponse, mesh)
    assert mesh["controller"]["model"] == "P9"
    assert mesh["identity_source"] == "0x400F"
    assert mesh["identity_interface"] == "tmp_appv2"
    assert mesh["fallback_used"] is True
    assert mesh["identity_attempts"] == [
        {
            "interface": "http_luci",
            "operation": "admin.device.device_list.read",
            "status": "error",
            "error_type": "TransportError",
        },
        {
            "interface": "tmp_appv2",
            "operation": "0x400F",
            "status": "ok",
        },
    ]
    assert cached["cached"] is True
    assert capability["data"] == mesh["nodes"]
    assert capability["provenance"]["source_interface"] == "tmp_appv2"
    assert capability["provenance"]["fallback_used"] is True
    http_client.get_device_list.assert_called_once_with()
    tmp_client.request_read_json.assert_called_once_with(0x400F, None)


def test_capability_fallback_works_after_tmp_cold_start_bootstrap() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    http_client.get_beamforming.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.side_effect = [
        {"error_code": 0, "result": {"device_list": [_device_payload()]}},
        {"error_code": 0, "result": {"enable": True}},
    ]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        result = service.read_capability("beamforming")

    assert result["data"] == {"enabled": True}
    assert result["provenance"]["source_interface"] == "tmp_appv2"
    assert result["provenance"]["attempts"][0] == {
        "interface": "http_luci",
        "operation": "admin.wireless.beamforming.read",
        "status": "skipped",
        "reason": "identity_bootstrap_selected_tmp",
    }
    http_client.get_beamforming.assert_not_called()
    assert tmp_client.request_read_json.call_args_list == [
        mock.call(0x400F, None),
        mock.call(0x421B, None),
    ]


def test_network_status_uses_only_tmp_after_tmp_identity_bootstrap() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.side_effect = [
        {"error_code": 0, "result": {"device_list": [_device_payload()]}},
        {"error_code": 0, "result": _internet_payload()},
    ]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        status = service.network_status_resource()

    assert_response_contract(NetworkStatusResponse, status)
    assert status["internet"]["link_status"] == "up"
    assert status["provenance"]["source_interface"] == "tmp_appv2"
    assert status["provenance"]["identity_attempts"][0] == {
        "interface": "http_luci",
        "operation": "admin.device.device_list.read",
        "status": "error",
        "error_type": "TransportError",
    }
    assert status["client_count_status"] == "gated"
    assert status["unavailable_sections"] == [
        {
            "section": section,
            "status": "unavailable",
            "error_type": "SourceUnavailable",
        }
        for section in ("performance", "firmware", "speed_test")
    ]
    http_client.get_internet_status.assert_not_called()
    http_client.get_performance.assert_not_called()
    http_client.get_speed_test.assert_not_called()


def test_network_status_switches_wholly_to_tmp_after_http_data_failure() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.return_value = [_p9_device()]
    http_client.get_internet_status.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": _internet_payload(),
    }

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        status = service.network_status_resource()

    assert_response_contract(NetworkStatusResponse, status)
    assert status["internet"]["link_status"] == "up"
    assert status["provenance"]["source_interface"] == "tmp_appv2"
    assert status["provenance"]["fallback_used"] is True
    assert status["provenance"]["attempts"][0]["status"] == "error"
    assert {item["section"] for item in status["unavailable_sections"]} == {
        "performance",
        "firmware",
        "speed_test",
    }
    http_client.get_performance.assert_not_called()
    http_client.get_speed_test.assert_not_called()
    tmp_client.request_read_json.assert_called_once_with(0x400C, None)


def test_configuration_uses_only_tmp_after_tmp_identity_bootstrap() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.side_effect = [
        {"error_code": 0, "result": {"device_list": [_device_payload()]}},
        {"error_code": 0, "result": _internet_payload()},
        {"error_code": 0, "result": {"enable": True}},
        {"error_code": 0, "result": {"enable": False}},
    ]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        configuration = service.configuration_resource()

    assert_response_contract(ConfigurationResponse, configuration)
    assert configuration["internet"]["link_status"] == "up"
    assert configuration["wireless_features"] == {
        "fast_roaming": {"enabled": True},
        "beamforming": {"enabled": False},
    }
    assert configuration["provenance"]["source_interface"] == "tmp_appv2"
    assert {item["section"] for item in configuration["unavailable_sections"]} == {
        "operating_mode",
        "wan_lan",
        "dhcp",
        "network_features",
        "time_settings",
        "wireless_operation_mode",
        "bridge",
    }
    http_client.get_device_mode.assert_not_called()
    http_client.get_internet_status.assert_not_called()
    http_client.get_wireless_operation_mode.assert_not_called()


def test_client_devices_use_only_tmp_sources_after_tmp_identity_bootstrap() -> None:
    config = replace(
        _config(),
        allow_sensitive_reads=True,
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.side_effect = [
        {"error_code": 0, "result": {"device_list": [_device_payload()]}},
        {
            "error_code": 0,
            "result": {
                "client_list": [
                    {
                        "mac": "AA:BB:CC:DD:EE:01",
                        "ip": "192.0.2.10",
                        "name": "VGVzdA==",
                        "online": True,
                    }
                ]
            },
        },
        {
            "error_code": 0,
            "result": {
                "reservation_list": [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.0.2.10"}],
                "reservation_list_max_count": 64,
            },
        },
    ]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        devices = service.client_devices_resource()

    assert_response_contract(ClientsResponse, devices)
    assert devices["provenance"]["source_interface"] == "tmp_appv2"
    assert devices["devices"][0]["reserved"] is True
    assert devices["devices"][0]["reservation_ip"] == "192.0.2.10"
    assert devices["source_counts"] == {
        "client_list": 1,
        "node_client_assignments": 0,
        "blocked_devices": 0,
        "address_reservations": 1,
    }
    assert {item["section"] for item in devices["unavailable_sections"]} == {
        "clients_by_node",
        "blocked_devices",
    }
    http_client.get_client_list.assert_not_called()
    http_client.get_clients_by_node.assert_not_called()
    http_client.get_address_reservations.assert_not_called()


def test_ipv6_semantic_resources_normalize_positive_p9_tmp_contracts() -> None:
    config = replace(
        _config(),
        allow_sensitive_reads=True,
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.return_value = [_p9_device()]
    tmp_client = mock.Mock()
    tmp_client.request_read_json.side_effect = [
        {
            "error_code": 0,
            "result": {
                "enable_ipv6": True,
                "wan": {
                    "dial_type": "dynamic_ipv6",
                    "enable_auto_dns": True,
                    "enable_prefix_delegation": True,
                    "get_addr_type": "slaac",
                    "ip_info": {
                        "ip": "2001:db8::10",
                        "dns1": "2001:4860:4860::8888",
                        "dns2": "2001:4860:4860::8844",
                    },
                },
                "lan": {
                    "assigned_type": "nd_proxy",
                    "ip": "2001:db8:1::1",
                    "prefix": "64",
                },
            },
        },
        {
            "error_code": 0,
            "result": {
                "firewall_list": [{"name": "HTTPS", "port": "443", "protocol": "TCP"}],
                "firewall_list_limit": 32,
            },
        },
        {
            "error_code": 0,
            "result": {
                "client_list": [
                    {
                        "mac": "aa-bb-cc-dd-ee-01",
                        "ip": "2001:db8:1::10",
                        "name": "VGVzdCBkZXZpY2U=",
                        "client_type": "computer",
                    }
                ]
            },
        },
    ]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        configuration = service.ipv6_configuration_resource()
        firewall = service.ipv6_firewall_resource()
        devices = service.ipv6_devices_resource()

    assert_response_contract(Ipv6ConfigurationResponse, configuration)
    assert_response_contract(Ipv6FirewallResponse, firewall)
    assert_response_contract(Ipv6DevicesResponse, devices)
    assert configuration["enabled"] is True
    assert configuration["wan"] == {
        "dial_type": "dynamic_ipv6",
        "automatic_dns": True,
        "prefix_delegation": True,
        "address_type": "slaac",
        "ip": "2001:db8::10",
        "dns_servers": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
    }
    assert firewall["rules"] == [{"name": "HTTPS", "port": "443", "protocol": "TCP"}]
    assert firewall["rule_count"] == 1
    assert firewall["rule_limit"] == 32
    assert devices["devices"] == [
        {
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "2001:db8:1::10",
            "name": "Test device",
            "client_type": "computer",
        }
    ]
    assert all(
        result["provenance"]["source_interface"] == "tmp_appv2"
        for result in (configuration, firewall, devices)
    )
    assert tmp_client.request_read_json.call_args_list == [
        mock.call(0x4006, None),
        mock.call(0x4230, None),
        mock.call(0x4234, None),
    ]
    http_client.get_device_list.assert_called_once_with()


def test_ipv6_semantic_resources_enforce_gates_before_transport() -> None:
    sensitive_disabled = DecoService(
        replace(
            _config(),
            allow_tmp_reads=True,
            tp_link_id="owner@example.com",
            tmp_host_key_sha256="SHA256:test",
        )
    )
    tmp_disabled = DecoService(replace(_config(), allow_sensitive_reads=True))

    for service, message in (
        (sensitive_disabled, "ALLOW_SENSITIVE_READS"),
        (tmp_disabled, "ALLOW_TMP_READS"),
    ):
        with (
            mock.patch.object(service, "_get_client") as get_client,
            mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
            pytest.raises(PermissionError, match=message),
        ):
            service.ipv6_configuration_resource()
        get_client.assert_not_called()
        get_tmp_client.assert_not_called()


def test_ipv6_semantic_resource_requires_exact_model_evidence() -> None:
    config = replace(
        _config(),
        allow_sensitive_reads=True,
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.return_value = [Device.from_api(_device_payload(model="X50"))]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(PermissionError, match="exact compatibility evidence"),
    ):
        service.ipv6_configuration_resource()

    get_tmp_client.assert_not_called()


def test_ipv6_semantic_resource_supports_tmp_identity_cold_start() -> None:
    config = replace(
        _config(),
        allow_sensitive_reads=True,
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.side_effect = [
        {"error_code": 0, "result": {"device_list": [_device_payload()]}},
        {"error_code": 0, "result": {"firewall_list": [], "firewall_list_limit": 32}},
    ]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        firewall = service.ipv6_firewall_resource()

    assert_response_contract(Ipv6FirewallResponse, firewall)
    assert firewall["rules"] == []
    assert tmp_client.request_read_json.call_args_list == [
        mock.call(0x400F, None),
        mock.call(0x4230, None),
    ]


def test_ipv6_semantic_resource_rejects_contract_drift() -> None:
    config = replace(
        _config(),
        allow_sensitive_reads=True,
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    service._device_cache = (_p9_device(),)
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"firewall_list": "invalid", "firewall_list_limit": 32},
    }

    with (
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
        pytest.raises(ValueError, match="firewall_list is not an array"),
    ):
        service.ipv6_firewall_resource()


def test_network_semantic_resources_normalize_positive_p9_tmp_contracts() -> None:
    config = replace(
        _config(),
        allow_sensitive_reads=True,
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.return_value = [_p9_device()]
    tmp_client = mock.Mock()
    tmp_client.request_read_json.side_effect = [
        {
            "error_code": 0,
            "result": {
                "lan_ip": {"ip": "192.168.68.1", "mask": "255.255.255.0"},
                "dns_server_ip": ["192.168.68.1"],
                "wan_ip": ["198.51.100.10"],
            },
        },
        {
            "error_code": 0,
            "result": {
                "start_ip": "192.168.68.100",
                "end_ip": "192.168.68.250",
                "gateway": "192.168.68.1",
                "dns1": "192.168.68.1",
                "dns2": "1.1.1.1",
                "ip_amount_in_use": 38,
            },
        },
        {"error_code": 0, "result": {"vlan": {"enable": False}}},
        {
            "error_code": 0,
            "result": {
                "port_forwarding_list": [
                    {
                        "port_forwarding_id": "rule-1",
                        "service_name": "HTTPS",
                        "service_type": "custom",
                        "internal_ip": "192.168.68.10",
                        "internal_port": "443",
                        "external_port": "8443",
                        "protocol": "TCP",
                    }
                ],
                "port_forwarding_list_max_count": 64,
            },
        },
        {"error_code": 0, "result": {"enable": True, "type": "bridge"}},
        {"error_code": 0, "result": {"enable": True}},
        {"error_code": 0, "result": {"enable": False}},
    ]

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        lan = service.lan_configuration_resource()
        dhcp = service.dhcp_configuration_resource()
        vlan = service.vlan_configuration_resource()
        forwarding = service.port_forwarding_resource()
        iptv = service.iptv_configuration_resource()
        sip_alg = service.sip_alg_resource()
        mac_clone = service.mac_clone_resource()

    assert_response_contract(LanConfigurationResponse, lan)
    assert_response_contract(DhcpConfigurationResponse, dhcp)
    assert_response_contract(VlanConfigurationResponse, vlan)
    assert_response_contract(PortForwardingResponse, forwarding)
    assert_response_contract(IptvConfigurationResponse, iptv)
    assert_response_contract(SipAlgResponse, sip_alg)
    assert_response_contract(MacCloneResponse, mac_clone)
    assert lan == {
        "schema_version": 1,
        "status": "available",
        "ip": "192.168.68.1",
        "subnet_mask": "255.255.255.0",
        "dns_servers": ["192.168.68.1"],
        "wan_addresses": ["198.51.100.10"],
        "provenance": lan["provenance"],
        "observed_at_epoch_seconds": lan["observed_at_epoch_seconds"],
        "router_contacted": True,
        "mutation_invoked": False,
    }
    assert dhcp["addresses_in_use"] == 38
    assert dhcp["dns_servers"] == ["192.168.68.1", "1.1.1.1"]
    assert vlan["enabled"] is False
    assert forwarding["rules"] == [
        {
            "id": "rule-1",
            "service_name": "HTTPS",
            "service_type": "custom",
            "internal_ip": "192.168.68.10",
            "internal_port": "443",
            "external_port": "8443",
            "protocol": "TCP",
        }
    ]
    assert forwarding["rule_count"] == 1
    assert forwarding["rule_limit"] == 64
    assert iptv["enabled"] is True
    assert iptv["mode"] == "bridge"
    assert sip_alg["enabled"] is True
    assert mac_clone["enabled"] is False
    assert all(
        result["provenance"]["source_interface"] == "tmp_appv2"
        for result in (lan, dhcp, vlan, forwarding, iptv, sip_alg, mac_clone)
    )
    assert tmp_client.request_read_json.call_args_list == [
        mock.call(0x4211, None),
        mock.call(0x4213, None),
        mock.call(0x420D, None),
        mock.call(0x40B0, None),
        mock.call(0x4224, None),
        mock.call(0x421D, None),
        mock.call(0x4226, None),
    ]
    http_client.get_device_list.assert_called_once_with()


def test_private_network_semantic_resource_does_not_require_sensitive_gate() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    service._device_cache = (_p9_device(),)
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"vlan": {"enable": True}},
    }

    with mock.patch.object(service, "_get_tmp_client", return_value=tmp_client):
        vlan = service.vlan_configuration_resource()

    assert_response_contract(VlanConfigurationResponse, vlan)
    assert vlan["enabled"] is True
    tmp_client.request_read_json.assert_called_once_with(0x420D, None)


def test_secret_network_semantic_resource_requires_sensitive_gate() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"),
    ):
        service.port_forwarding_resource()

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()


def test_network_semantic_resource_rejects_contract_drift() -> None:
    config = replace(
        _config(),
        allow_sensitive_reads=True,
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    service._device_cache = (_p9_device(),)
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"port_forwarding_list": "invalid", "port_forwarding_list_max_count": 64},
    }

    with (
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
        pytest.raises(ValueError, match="port_forwarding_list is not an array"),
    ):
        service.port_forwarding_resource()


def test_tmp_identity_bootstrap_requires_its_ordinary_read_gate() -> None:
    service = DecoService(_config())
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(TransportError, match="HTTP unavailable"),
    ):
        service.device_inventory()

    get_tmp_client.assert_not_called()


def test_tmp_identity_bootstrap_fails_closed_on_host_key_error() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(
            service,
            "_get_tmp_client",
            side_effect=TransportError(
                "Failed to open TMP SSH: host-key fingerprint does not match"
            ),
        ),
        pytest.raises(TransportError, match="host-key fingerprint does not match"),
    ):
        service.device_inventory()

    assert service.public_status()["identity_resolved"] is False


def test_tmp_identity_bootstrap_rejects_an_invalid_controller_shape() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"device_list": [{"role": "master"}]},
    }

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
        pytest.raises(ValueError, match="controller model and MAC are required"),
    ):
        service.device_inventory()

    assert service.public_status()["identity_resolved"] is False


def test_tmp_identity_bootstrap_reports_unknown_model_without_authorizing_reads() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)
    http_client = mock.Mock()
    http_client.get_device_list.side_effect = TransportError("HTTP unavailable")
    http_client.get_beamforming.side_effect = TransportError("HTTP unavailable")
    tmp_client = mock.Mock()
    tmp_client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"device_list": [_device_payload(model="X50")]},
    }

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client", return_value=tmp_client),
    ):
        mesh = service.device_inventory()
        with pytest.raises(TransportError, match="HTTP unavailable"):
            service.read_capability("beamforming")

    assert mesh["controller"]["model"] == "X50"
    assert mesh["profile_match"] == "unknown"
    tmp_client.request_read_json.assert_called_once_with(0x400F, None)


def test_http_authentication_failure_does_not_fall_back_to_tmp_identity() -> None:
    config = replace(
        _config(),
        allow_tmp_reads=True,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    service = DecoService(config)

    with (
        mock.patch.object(
            service,
            "_get_client",
            side_effect=AuthenticationError("Failed to login: invalid password"),
        ),
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(AuthenticationError, match="invalid password"),
    ):
        service.device_inventory()

    get_tmp_client.assert_not_called()


def test_semantic_resources_report_supported_and_blocked_mutations() -> None:
    service = DecoService(_config())
    service._device_cache = (_p9_device(),)

    capabilities = service.capabilities()
    mutations = service.semantic_mutations()

    assert_response_contract(CapabilitiesResponse, capabilities)
    assert_response_contract(MutationsResponse, mutations)
    assert capabilities["supported_count"] == 16
    assert capabilities["router_contacted"] is False
    assert all(item["read_operation"] == "get_capability" for item in capabilities["capabilities"])
    ipv6_clients = next(
        item for item in capabilities["capabilities"] if item["name"] == "ipv6_clients"
    )
    assert ipv6_clients["source_configured"] is False
    assert ipv6_clients["source_connected"] is False
    assert ipv6_clients["runtime_gate_enabled"] is False
    assert mutations["candidate_count"] == 22
    beamforming = next(item for item in mutations["mutations"] if item["name"] == "beamforming")
    assert beamforming["validation_status"] == "noop_verified"
    assert beamforming["execution_scope"] == "noop_only"
    assert beamforming["execution_status"] == "gated"
    assert beamforming["plan_operation"] == "plan_mutation"
    assert beamforming["execute_operation"] == "execute_mutation"
    semantic_mutation = service.semantic_mutation("beamforming")
    assert_response_contract(MutationResponse, semantic_mutation)
    assert semantic_mutation == beamforming
    monthly_report = next(
        item for item in mutations["mutations"] if item["name"] == "monthly_report"
    )
    assert monthly_report["validation_status"] == "safety_not_established"
    assert monthly_report["execution_status"] == "blocked"
    assert monthly_report["execute_operation"] is None
    reservation = next(
        item for item in mutations["mutations"] if item["name"] == "address_reservation_modify"
    )
    assert reservation["validation_status"] == "noop_verified"
    assert reservation["execution_scope"] == "none"
    assert reservation["execution_status"] == "blocked"
    system_log_prepare = next(
        item for item in mutations["mutations"] if item["name"] == "system_log_prepare"
    )
    assert system_log_prepare["changes_schema"] == {
        "required": ["level"],
        "optional": [],
    }
    assert system_log_prepare["validation_status"] == "general_verified"
    assert system_log_prepare["execution_scope"] == "none"
    assert system_log_prepare["execution_status"] == "blocked"
    assert system_log_prepare["execute_operation"] is None
    assert "state-changing behavior has not been validated" not in system_log_prepare["blockers"]
    assessment = service.preflight_semantic_mutation(
        "system_log_prepare",
        {"level": 5},
    )
    assert assessment["execution_allowed"] is False
    assert assessment["changes"] == {"level": 5}
    assert "state-changing semantic execution is not yet implemented" in assessment["blockers"]
    assert "state-changing semantic execution is not yet validated" not in assessment["blockers"]
    with pytest.raises(ValueError, match="unknown mutation"):
        service.semantic_mutation("missing")


def test_unknown_deco_model_is_described_without_inheriting_p9_mutation_evidence() -> None:
    unknown = Device.from_api(
        {
            "mac": "11:22:33:44:55:66",
            "device_ip": "192.0.2.1",
            "device_model": "X60",
            "role": "master",
            "hardware_ver": "1.0",
            "software_ver": "9.9.9",
        }
    )
    service = DecoService(_config())
    service._device_cache = (unknown,)

    mesh = service.device_inventory()
    capabilities = service.capabilities()
    mutations = service.semantic_mutations()

    assert mesh["profile_match"] == "unknown"
    assert mesh["profile_name"] is None
    assert capabilities["supported_count"] == 0
    assert capabilities["unknown_count"] == 16
    assert mutations["execution_counts"] == {"blocked": 22}
    assert all(item["support_status"] == "unverified" for item in mutations["mutations"])


def test_semantic_mutation_plan_blocks_changes_and_executes_one_shot_noop() -> None:
    config = replace(
        _config(),
        allow_mutations=True,
        allow_http_noop_verification=True,
    )
    service = DecoService(config)
    service._device_cache = (_p9_device(),)

    preflight = service.preflight_semantic_mutation(
        "beamforming",
        {},
        mode="verify_current_value_noop",
    )
    change_plan = service.plan_semantic_mutation(
        "beamforming",
        {"enable": False},
    )
    noop_plan = service.plan_semantic_mutation(
        "beamforming",
        {},
        mode="verify_current_value_noop",
    )

    assert_response_contract(MutationPreflightResponse, preflight)
    assert_response_contract(MutationPlanCreatedResponse, noop_plan)
    assert change_plan["execution_allowed"] is False
    assert change_plan["plan_id"] is None
    assert "state-changing semantic execution is not yet validated" in change_plan["blockers"]
    assert noop_plan["execution_allowed"] is True
    assert isinstance(noop_plan["plan_id"], str)
    assert (
        noop_plan["required_confirmation"]
        == HTTP_NOOP_CONFIRMATIONS["admin.wireless.beamforming.write"]
    )

    plan_id = noop_plan["plan_id"]
    confirmation = noop_plan["required_confirmation"]
    assert isinstance(plan_id, str)
    assert isinstance(confirmation, str)
    plan_status = service.semantic_mutation_plan(plan_id)
    assert_response_contract(MutationPlanStatusResponse, plan_status)
    assert plan_status["status"] == "pending"
    assert "required_confirmation" not in plan_status
    with (
        mock.patch.object(
            service,
            "verify_setting_noop",
            return_value={"status": "verified_noop", "verified_noop": True},
        ) as verifier,
        pytest.raises(ConfirmationError, match="exact plan confirmation"),
    ):
        service.execute_semantic_mutation(plan_id, "wrong")
    verifier.assert_not_called()

    client = mock.Mock()
    client.get_device_list.return_value = [_p9_device()]
    client.call.side_effect = [
        ApiResponse.from_api({"error_code": 0, "result": {"enable": True}}),
        ApiResponse.from_api({"error_code": 0}),
        ApiResponse.from_api({"error_code": 0, "result": {"enable": True}}),
    ]
    with mock.patch.object(service, "_get_client", return_value=client):
        result = service.execute_semantic_mutation(plan_id, confirmation)

    assert_response_contract(
        MutationExecutionResponse,
        {**result, "idempotency_replayed": False},
    )
    assert result["plan_consumed"] is True
    assert result["fallback_used"] is False
    with pytest.raises(UnknownPlanError, match="unknown plan ID"):
        service.execute_semantic_mutation(plan_id, confirmation)


@pytest.mark.asyncio
async def test_default_server_exposes_only_protocol_neutral_tools() -> None:
    server = create_server(_config())

    tool_names = {tool.name for tool in await server.list_tools()}
    registered_resources = await server.list_resources()
    resource_uri_list = [str(resource.uri) for resource in registered_resources]
    resource_uris = set(resource_uri_list)
    resource_templates = {
        str(template.uriTemplate) for template in await server.list_resource_templates()
    }

    assert tool_names == {
        "deco_get_capability",
        "deco_plan_mutation",
        "deco_execute_mutation",
        "deco_get_wlan_state",
        "deco_get_cloud_state",
    }
    assert len(resource_uri_list) == len(resource_uris)
    assert resource_uris == {
        "deco://mcp",
        "deco://status",
        "deco://configuration",
        "deco://mesh",
        "deco://devices",
        "deco://devices/active",
        "deco://devices/inactive",
        "deco://devices/blocked",
        "deco://devices/ipv6",
        "deco://traffic",
        "deco://address-reservations",
        "deco://network/lan",
        "deco://network/dhcp",
        "deco://network/vlan",
        "deco://network/port-forwarding",
        "deco://network/iptv",
        "deco://network/sip-alg",
        "deco://network/mac-clone",
        "deco://network/ipv6",
        "deco://network/ipv6/firewall",
        "deco://logs",
        "deco://capabilities",
        "deco://mutations",
    }
    assert resource_templates == {"deco://logs/{index}"}

    tools = {tool.name: tool for tool in await server.list_tools()}
    assert tools["deco_get_capability"].annotations.readOnlyHint is True
    assert tools["deco_get_wlan_state"].annotations.readOnlyHint is True
    assert tools["deco_get_cloud_state"].annotations.readOnlyHint is True
    assert tools["deco_plan_mutation"].annotations.readOnlyHint is False
    assert tools["deco_plan_mutation"].annotations.destructiveHint is False
    assert tools["deco_execute_mutation"].annotations.readOnlyHint is False
    assert tools["deco_execute_mutation"].annotations.destructiveHint is True


@pytest.mark.asyncio
async def test_diagnostic_server_retains_protocol_specific_tools() -> None:
    server = create_server(replace(_config(), expose_diagnostic_tools=True))
    tools = {tool.name: tool for tool in await server.list_tools()}
    tool_names = set(tools)

    assert len(tool_names) == 47
    assert "deco_get_capability" in tool_names
    assert "deco_verify_setting_noop" in tool_names
    assert "deco_read_endpoint" in tool_names
    assert "deco_tmp_read" in tool_names
    assert "deco_verify_tmp_ieee80211r_noop" not in tool_names
    assert "deco_invoke_mutation" not in tool_names
    assert all(tool.annotations is not None for tool in tools.values())
    assert tools["deco_get_mesh_overview"].annotations.readOnlyHint is True
    assert tools["deco_verify_setting_noop"].annotations.readOnlyHint is False


@pytest.mark.asyncio
async def test_raw_mutation_visibility_is_independent_from_diagnostics() -> None:
    server = create_server(replace(_config(), expose_raw_mutation_tools=True))
    tool_names = {tool.name for tool in await server.list_tools()}
    resource_uris = {str(resource.uri) for resource in await server.list_resources()}

    assert "deco_invoke_mutation" in tool_names
    assert "deco_read_endpoint" not in tool_names
    assert "deco://diagnostics/operations" not in resource_uris
