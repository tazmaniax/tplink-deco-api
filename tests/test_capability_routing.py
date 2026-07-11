"""Tests for protocol-neutral capability routing and safe read fallback."""

from __future__ import annotations

from dataclasses import replace
from unittest import mock

import pytest

from tplink_deco_api import CAPABILITY_ROUTES, TransportError, get_capability_route
from tplink_deco_api.mcp import DecoMcpService, McpConfig
from tplink_deco_api.mcp.server import create_server


def _config() -> McpConfig:
    return McpConfig(
        host="192.0.2.1",
        username="admin",
        password="secret",
        timeout=60.0,
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


def test_capability_routes_are_offline_and_report_fallback_readiness() -> None:
    service = DecoMcpService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        result = service.capability_routes()

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()
    assert result["agent_selects_protocol"] is False
    assert result["automatic_mutation_fallback"] is False
    assert result["diagnostic_tools_exposed"] is False
    assert len(result["routes"]) == 6
    assert not any(route["fallback_gate_enabled"] for route in result["routes"])


def test_capability_read_prefers_http_and_returns_provenance() -> None:
    service = DecoMcpService(_config())
    client = mock.Mock()
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
    service = DecoMcpService(config)
    http_client = mock.Mock()
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
    service = DecoMcpService(_config())
    http_client = mock.Mock()
    http_client.get_beamforming.side_effect = TransportError("temporary failure")

    with (
        mock.patch.object(service, "_get_client", return_value=http_client),
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(TransportError, match="temporary failure"),
    ):
        service.read_capability("beamforming")

    get_tmp_client.assert_not_called()


def test_secret_capability_requires_one_logical_gate_before_transport_selection() -> None:
    service = DecoMcpService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"),
    ):
        service.read_capability("clients")

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()


@pytest.mark.asyncio
async def test_default_server_exposes_only_protocol_neutral_tools() -> None:
    server = create_server(_config())

    tool_names = {tool.name for tool in await server.list_tools()}
    resource_uris = {str(resource.uri) for resource in await server.list_resources()}

    assert tool_names == {
        "deco_get_capability",
        "deco_get_network_overview",
        "deco_get_mesh_overview",
        "deco_get_wlan_state",
        "deco_get_cloud_state",
        "deco_get_client_overview",
        "deco_get_system_overview",
    }
    assert "deco://capability-routes" in resource_uris


@pytest.mark.asyncio
async def test_diagnostic_server_retains_protocol_specific_tools() -> None:
    server = create_server(replace(_config(), expose_diagnostic_tools=True))
    tool_names = {tool.name for tool in await server.list_tools()}

    assert len(tool_names) == 44
    assert "deco_get_capability" in tool_names
    assert "deco_read_endpoint" in tool_names
    assert "deco_tmp_read" in tool_names
