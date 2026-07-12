"""Tests for protocol-neutral capability routing and safe read fallback."""

from __future__ import annotations

from dataclasses import replace
from unittest import mock

import pytest

from tplink_deco_api import (
    CAPABILITY_ROUTES,
    HTTP_NOOP_CONFIRMATIONS,
    MUTATION_CAPABILITY_ROUTES,
    TMP_MONTHLY_REPORT_NOOP_CONFIRMATION,
    Device,
    TransportError,
    get_capability_route,
    get_mutation_capability_route,
)
from tplink_deco_api.exceptions import ConfirmationError, UnknownPlanError
from tplink_deco_api.mcp.server import create_server
from tplink_deco_api.server import ServerConfig
from tplink_deco_api.service import DecoService


def _config() -> ServerConfig:
    return ServerConfig(
        host="192.0.2.1",
        username="admin",
        password="secret",
        timeout=60.0,
    )


def _p9_device() -> Device:
    return Device.from_api(
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "device_ip": "192.0.2.1",
            "device_model": "P9",
            "role": "master",
            "hardware_ver": "2.0",
            "software_ver": "1.3.0 Build 20250804 Rel. 58832",
        }
    )


def test_capability_registry_contains_only_read_fallbacks() -> None:
    assert [route.name for route in CAPABILITY_ROUTES] == [
        "mesh_nodes",
        "clients",
        "internet_status",
        "address_reservations",
        "fast_roaming",
        "beamforming",
    ]
    assert all(route.fallback_policy == "equivalent_read_only" for route in CAPABILITY_ROUTES)
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
        "monthly_report",
    ]
    assert all(route.to_dict()["fallback_policy"] == "none" for route in MUTATION_CAPABILITY_ROUTES)
    assert all(
        route.to_dict()["automatic_fallback"] is False for route in MUTATION_CAPABILITY_ROUTES
    )
    assert get_mutation_capability_route("beamforming").interface == "http_luci"
    assert get_mutation_capability_route("monthly_report").operation == "0x4223"

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
    assert len(result["routes"]) == 6
    assert len(result["mutation_routes"]) == 4
    assert not any(route["fallback_gate_enabled"] for route in result["routes"])
    assert not any(route["all_environment_gates_enabled"] for route in result["mutation_routes"])


def test_capability_mutation_plan_is_offline_and_protocol_fixed() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        http_plan = service.plan_capability_mutation("beamforming")
        tmp_plan = service.plan_capability_mutation("monthly_report")

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()
    assert http_plan["interface"] == "http_luci"
    assert http_plan["operation"] == "admin.wireless.beamforming.write"
    assert http_plan["confirmation"] == HTTP_NOOP_CONFIRMATIONS[http_plan["operation"]]
    assert tmp_plan["interface"] == "tmp_appv2"
    assert tmp_plan["operation"] == "0x4223"
    assert tmp_plan["confirmation"] == TMP_MONTHLY_REPORT_NOOP_CONFIRMATION
    assert http_plan["fallback_policy"] == tmp_plan["fallback_policy"] == "none"
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


def test_unified_monthly_report_noop_uses_tmp_current_value() -> None:
    config = replace(
        _config(),
        allow_mutations=True,
        allow_tmp_reads=True,
        allow_tmp_noop_verification=True,
    )
    service = DecoService(config)
    service._device_cache = (_p9_device(),)
    client = mock.Mock()
    client.request_read_json.side_effect = [
        {"error_code": 0, "result": {"enable": True}},
        {"error_code": 0, "result": {"enable": True}},
    ]
    client._request_mutation_json.return_value = {"error_code": 0}

    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        evidence = service.verify_setting_noop(
            "monthly_report",
            TMP_MONTHLY_REPORT_NOOP_CONFIRMATION,
        )

    assert evidence["status"] == "verified_noop"
    assert evidence["selected_interface"] == "tmp_appv2"
    assert evidence["selected_operation"] == "0x4223"
    assert evidence["fallback_used"] is False
    assert client.request_read_json.call_args_list == [mock.call(0x4222), mock.call(0x4222)]
    client._request_mutation_json.assert_called_once_with(0x4223, {"enable": True})


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

    assert mesh["controller"]["model"] == "P9"
    assert mesh["profile_match"] == "exact"
    assert mesh["router_contacted"] is True
    assert cached["cached"] is True
    client.get_device_list.assert_called_once_with()

    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        service.client_devices_resource()
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        service.address_reservations_resource()


def test_semantic_resources_report_supported_and_blocked_mutations() -> None:
    service = DecoService(_config())
    service._device_cache = (_p9_device(),)

    capabilities = service.capabilities()
    mutations = service.semantic_mutations()

    assert capabilities["supported_count"] == 6
    assert capabilities["router_contacted"] is False
    assert all(item["read_operation"] == "get_capability" for item in capabilities["capabilities"])
    assert mutations["candidate_count"] == 21
    beamforming = next(item for item in mutations["mutations"] if item["name"] == "beamforming")
    assert beamforming["validation_status"] == "noop_verified"
    assert beamforming["execution_scope"] == "noop_only"
    assert beamforming["execution_status"] == "gated"
    assert beamforming["plan_operation"] == "plan_mutation"
    assert beamforming["execute_operation"] == "execute_mutation"
    assert service.semantic_mutation("beamforming") == beamforming
    reservation = next(
        item for item in mutations["mutations"] if item["name"] == "address_reservation_modify"
    )
    assert reservation["validation_status"] == "noop_verified"
    assert reservation["execution_scope"] == "none"
    assert reservation["execution_status"] == "blocked"
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
    assert capabilities["unknown_count"] == 6
    assert mutations["execution_counts"] == {"blocked": 21}
    assert all(item["support_status"] == "unverified" for item in mutations["mutations"])


def test_semantic_mutation_plan_blocks_changes_and_executes_one_shot_noop() -> None:
    config = replace(
        _config(),
        allow_mutations=True,
        allow_http_noop_verification=True,
    )
    service = DecoService(config)
    service._device_cache = (_p9_device(),)

    change_plan = service.plan_semantic_mutation(
        "beamforming",
        {"enable": False},
    )
    noop_plan = service.plan_semantic_mutation(
        "beamforming",
        {},
        mode="verify_current_value_noop",
    )

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

    with (
        mock.patch.object(
            service,
            "verify_setting_noop",
            return_value={"status": "verified_noop", "verified_noop": True},
        ) as verifier,
        mock.patch.object(service, "_get_client") as get_client,
    ):
        get_client.return_value.get_device_list.return_value = [_p9_device()]
        result = service.execute_semantic_mutation(plan_id, confirmation)

    verifier.assert_called_once_with("beamforming", confirmation)
    assert result["plan_consumed"] is True
    assert result["fallback_used"] is False
    with pytest.raises(UnknownPlanError, match="unknown plan ID"):
        service.execute_semantic_mutation(plan_id, confirmation)


@pytest.mark.asyncio
async def test_default_server_exposes_only_protocol_neutral_tools() -> None:
    server = create_server(_config())

    tool_names = {tool.name for tool in await server.list_tools()}
    resource_uris = {str(resource.uri) for resource in await server.list_resources()}

    assert tool_names == {
        "deco_get_capability",
        "deco_plan_mutation",
        "deco_execute_mutation",
        "deco_get_wlan_state",
        "deco_get_cloud_state",
    }
    assert resource_uris == {
        "deco://mcp",
        "deco://status",
        "deco://configuration",
        "deco://mesh",
        "deco://devices",
        "deco://devices/active",
        "deco://devices/inactive",
        "deco://devices/blocked",
        "deco://traffic",
        "deco://address-reservations",
        "deco://logs",
        "deco://capabilities",
        "deco://mutations",
    }

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

    assert len(tool_names) == 48
    assert "deco_get_capability" in tool_names
    assert "deco_verify_setting_noop" in tool_names
    assert "deco_read_endpoint" in tool_names
    assert "deco_tmp_read" in tool_names
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
