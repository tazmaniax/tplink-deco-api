"""Contract, security and lifecycle tests for the composite REST and MCP server."""

from __future__ import annotations

import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, is_dataclass, replace
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from tplink_deco_api.exceptions import (
    ApiError,
    ConfirmationError,
    ControllerChangedError,
    ExpiredPlanError,
    IdempotencyInProgressError,
)
from tplink_deco_api.mcp.server import create_server
from tplink_deco_api.models import Device
from tplink_deco_api.responses import (
    CapabilitiesResponse,
    CapabilityResponse,
    ClientsResponse,
    CloudResponse,
    ConfigurationResponse,
    DhcpConfigurationResponse,
    IptvConfigurationResponse,
    Ipv6ConfigurationResponse,
    Ipv6DevicesResponse,
    Ipv6FirewallResponse,
    LanConfigurationResponse,
    LogTypesResponse,
    MacCloneResponse,
    MeshResponse,
    MutationExecutionResponse,
    MutationPlanCreatedResponse,
    MutationPreflightResponse,
    MutationResponse,
    MutationsResponse,
    NetworkStatusResponse,
    PortForwardingResponse,
    ResponseDto,
    ServiceStatusResponse,
    SipAlgResponse,
    SystemLogPageResponse,
    TrafficResponse,
    VlanConfigurationResponse,
    WlanResponse,
)
from tplink_deco_api.rest import create_http_application
from tplink_deco_api.rest._in_memory_idempotency_store import _InMemoryIdempotencyStore
from tplink_deco_api.rest.request_capacity_middleware import RequestCapacityMiddleware
from tplink_deco_api.server import ServerConfig, StaticBearerAuthenticator
from tplink_deco_api.service import DecoService

_TOKEN = "x" * 32
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}


def _config(**overrides: bool) -> ServerConfig:
    values = {
        "rest_enabled": True,
        "rest_expose_docs": True,
    }
    values.update(overrides)
    return ServerConfig(
        host="192.0.2.1",
        username="admin",
        password="secret",
        timeout=60.0,
        transport="streamable-http",
        server_host="127.0.0.1",
        server_port=8000,
        mcp_path="/mcp",
        mcp_public_url="http://testserver/mcp",
        bearer_token=_TOKEN,
        allowed_hosts=("testserver",),
        allowed_origins=("https://dashboard.example",),
        **values,
    )


def _mutation_response() -> MutationResponse:
    return MutationResponse(
        name="beamforming",
        description="Change wireless beamforming",
        category="wireless",
        risk="mutation",
        sensitivity="normal",
        scope="mesh",
        changes_schema={"required": ["enable"], "optional": []},
        support_status="supported",
        validation_status="noop_verified",
        execution_scope="noop_only",
        execution_status="ready",
        required_gates=["DECO_ALLOW_MUTATIONS"],
        confirmation_required=True,
        preflight_available=True,
        verification_available=True,
        rollback_available=True,
        plan_operation="plan_mutation",
        execute_operation="execute_mutation",
        blockers=[],
    )


def _preflight_response(*, allowed: bool = True) -> MutationPreflightResponse:
    return MutationPreflightResponse(
        schema_version=1,
        mutation="beamforming",
        mode="verify_current_value_noop",
        changes={},
        model="P9",
        profile_match="exact",
        validation_status="noop_verified",
        execution_scope="noop_only",
        execution_allowed=allowed,
        plan_id=None,
        expires_in_seconds=None,
        required_confirmation=None,
        required_gates=["DECO_ALLOW_MUTATIONS"],
        preflight_available=True,
        verification_available=True,
        rollback_available=True,
        blockers=[] if allowed else ["state-changing semantic execution is not yet validated"],
        router_contacted=False,
        mutation_invoked=False,
        fallback_policy="none",
    )


def _created_plan_response() -> MutationPlanCreatedResponse:
    return MutationPlanCreatedResponse(
        schema_version=1,
        mutation="beamforming",
        mode="verify_current_value_noop",
        changes={},
        model="P9",
        profile_match="exact",
        validation_status="noop_verified",
        execution_scope="noop_only",
        execution_allowed=True,
        plan_id="plan-1",
        expires_in_seconds=300.0,
        required_confirmation="CONFIRM",
        required_gates=["DECO_ALLOW_MUTATIONS"],
        preflight_available=True,
        verification_available=True,
        rollback_available=True,
        blockers=[],
        router_contacted=False,
        mutation_invoked=False,
        fallback_policy="none",
    )


def _execution_response() -> MutationExecutionResponse:
    return MutationExecutionResponse(
        schema_version=1,
        transport="encrypted_owner_http",
        operation_name="admin.wireless.beamforming.write",
        preflight_name="admin.wireless.beamforming.read",
        status="verified_noop",
        verified_noop=True,
        write_firmware_error_code=0,
        write_error_type="",
        post_read_succeeded=True,
        state_unchanged=True,
        rollback_attempted=False,
        rollback_firmware_error_code=None,
        rollback_error_type="",
        rollback_verified=None,
        mutation_request_count=1,
        same_value_payload=True,
        current_value_source="live_preflight:admin.wireless.beamforming.read",
        parameter_keys=["enable"],
        parameter_values_retained=False,
        response_values_retained=False,
        raw_values_emitted=False,
        different_value_write_invoked=False,
        model="P9",
        execution_scope="verified_current_value_noop_only",
        runtime_gates=["DECO_ALLOW_MUTATIONS"],
        requires_attention=False,
        capability="beamforming",
        selected_interface="http_luci",
        selected_operation="admin.wireless.beamforming.write",
        fallback_policy="none",
        fallback_used=False,
        caller_selected_protocol=False,
        plan_id="plan-1",
        plan_consumed=True,
        idempotency_replayed=False,
        verification_name="admin.wireless.beamforming.read",
        rollback_name="admin.wireless.beamforming.write",
        generic_http_noop_execution_supported=False,
    )


def _read_response_dtos(config: ServerConfig) -> dict[str, ResponseDto]:
    tmp_provenance = {
        "source_interface": "tmp_appv2",
        "source_operation": "0x4006",
        "fallback_used": False,
        "fallback_policy": "none",
        "equivalence_evidence": "p9_live_schema_contract",
        "attempts": [],
    }
    capability = CapabilityResponse(
        capability="beamforming",
        schema_version=1,
        data={"enabled": True},
        provenance={
            "source_interface": "http_luci",
            "source_operation": "admin.wireless.beamforming.read",
            "fallback_used": False,
            "fallback_policy": "equivalent_read_only",
            "equivalence_evidence": "verified",
            "attempts": [],
        },
        mutation_invoked=False,
    )
    mutation = _mutation_response()
    return {
        "public_status": ServiceStatusResponse(**DecoService(config).public_status()),
        "network_status_resource": NetworkStatusResponse(
            schema_version=1,
            status="healthy",
            controller={},
            internet=None,
            mesh={},
            performance=None,
            firmware=None,
            speed_test=None,
            client_count=None,
            client_count_status="gated",
            provenance={
                "source_interface": "http_luci",
                "source_operation": "admin.device.device_list.read",
                "fallback_used": False,
                "attempts": [],
                "identity_attempts": [],
                "single_source_interface": True,
            },
            warnings=[],
            unavailable_sections=[],
            observed_at_epoch_seconds=1.0,
            passwords_included=False,
            client_identities_included=False,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "configuration_resource": ConfigurationResponse(
            schema_version=1,
            controller={},
            provenance={
                "source_interface": "http_luci",
                "source_operation": "admin.device.device_list.read",
                "fallback_used": False,
                "attempts": [],
                "identity_attempts": [],
                "single_source_interface": True,
            },
            related_sections=[],
            nickname=None,
            nickname_status="gated",
            unavailable_sections=[],
            passwords_included=False,
            client_identities_included=False,
            address_reservations_included=False,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "device_inventory": MeshResponse(
            schema_version=1,
            resolution_status="resolved",
            controller={},
            nodes=[],
            node_count=0,
            mixed_model_mesh=False,
            identity_source="admin.device.device_list.read",
            identity_interface="http_luci",
            identity_attempts=[],
            fallback_used=False,
            profile_match="exact",
            profile_name="P9",
            cached=True,
            router_contacted=False,
            mutation_invoked=False,
        ),
        "client_devices_resource": ClientsResponse(
            schema_version=1,
            view="all",
            devices=[],
            device_count=0,
            all_device_count=0,
            source_counts={},
            provenance=None,
            unavailable_sections=[],
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "traffic_resource": TrafficResponse(
            schema_version=1,
            device_speeds=[],
            device_count=0,
            aggregate_speed={"up_speed": 0, "down_speed": 0},
            status="available",
            provenance={
                "source_interface": "http_luci",
                "source_operation": "admin.client.traffic_stat.list",
                "fallback_used": False,
                "fallback_policy": "equivalent_read_only",
                "equivalence_evidence": "p9_live_schema_equivalence",
                "attempts": [],
            },
            unavailable_sections=[],
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "address_reservations_resource": capability,
        "lan_configuration_resource": LanConfigurationResponse(
            schema_version=1,
            status="available",
            ip="192.0.2.1",
            subnet_mask="255.255.255.0",
            dns_servers=["192.0.2.1"],
            wan_addresses=["198.51.100.10"],
            provenance={**tmp_provenance, "source_operation": "0x4211"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "dhcp_configuration_resource": DhcpConfigurationResponse(
            schema_version=1,
            status="available",
            start_ip="192.0.2.100",
            end_ip="192.0.2.250",
            gateway="192.0.2.1",
            dns_servers=["192.0.2.1", "1.1.1.1"],
            addresses_in_use=12,
            provenance={**tmp_provenance, "source_operation": "0x4213"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "vlan_configuration_resource": VlanConfigurationResponse(
            schema_version=1,
            status="available",
            enabled=False,
            provenance={**tmp_provenance, "source_operation": "0x420D"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "port_forwarding_resource": PortForwardingResponse(
            schema_version=1,
            status="available",
            rules=[],
            rule_count=0,
            rule_limit=64,
            provenance={**tmp_provenance, "source_operation": "0x40B0"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "iptv_configuration_resource": IptvConfigurationResponse(
            schema_version=1,
            status="available",
            enabled=False,
            mode="bridge",
            provenance={**tmp_provenance, "source_operation": "0x4224"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "sip_alg_resource": SipAlgResponse(
            schema_version=1,
            status="available",
            enabled=True,
            provenance={**tmp_provenance, "source_operation": "0x421D"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "mac_clone_resource": MacCloneResponse(
            schema_version=1,
            status="available",
            enabled=False,
            provenance={**tmp_provenance, "source_operation": "0x4226"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "ipv6_configuration_resource": Ipv6ConfigurationResponse(
            schema_version=1,
            status="available",
            enabled=True,
            wan={},
            lan={},
            provenance=tmp_provenance,
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "ipv6_firewall_resource": Ipv6FirewallResponse(
            schema_version=1,
            status="available",
            rules=[],
            rule_count=0,
            rule_limit=32,
            provenance={**tmp_provenance, "source_operation": "0x4230"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "ipv6_devices_resource": Ipv6DevicesResponse(
            schema_version=1,
            status="available",
            devices=[],
            device_count=0,
            provenance={**tmp_provenance, "source_operation": "0x4234"},
            observed_at_epoch_seconds=1.0,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "logs_resource": LogTypesResponse(
            schema_version=1,
            categories=[],
            category_count=0,
            selector_field="level",
            web_ui_default_level=5,
            all_level=8,
            preparation_mutation="system_log_prepare",
            status="available",
            unavailable_sections=[],
            log_contents_included=False,
            router_contacted=True,
            mutation_invoked=False,
        ),
        "system_log_page_resource": SystemLogPageResponse(
            schema_version=1,
            current_index=2,
            total_pages=4,
            page_size=100,
            entries=[],
            entry_count=0,
            log_contents_included=True,
            prepared_level=None,
            level_reported_by_firmware=False,
            preparation_mutation="system_log_prepare",
            source_interface="http_luci",
            router_contacted=True,
            mutation_invoked=False,
        ),
        "capabilities": CapabilitiesResponse(
            schema_version=1,
            resolution_status="resolved",
            controller={},
            profile_match="exact",
            capabilities=[],
            supported_count=0,
            unknown_count=0,
            unsupported_count=0,
            router_contacted=False,
            mutation_invoked=False,
        ),
        "read_capability": capability,
        "wlan_state": WlanResponse(
            passwords_included=False,
            is_eg=False,
            bands={},
            iot={},
            mlo={},
            features={},
        ),
        "cloud_state": CloudResponse(ddns=None, manager=None),
        "semantic_mutations": MutationsResponse(
            schema_version=1,
            resolution_status="resolved",
            controller={},
            profile_match="exact",
            mutations=[mutation],
            candidate_count=1,
            execution_counts={"ready": 1},
            mutation_gate_status={"ordinary": True},
            router_contacted=False,
            mutation_invoked=False,
        ),
        "semantic_mutation": mutation,
    }


def test_composite_application_exposes_health_rest_openapi_and_mcp() -> None:
    application = create_http_application(_config())

    with TestClient(application) as client:
        health = client.get("/healthz")
        ready = client.get("/readyz")
        unauthorized = client.get("/api/v1/service")
        schema_without_auth = client.get("/openapi.json")
        schema = client.get("/openapi.json", headers=_AUTH)
        docs = client.get("/docs", headers=_AUTH)
        mcp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        doubled_path = client.post("/mcp/mcp", json={})
        missing_capability = client.get("/api/v1/capabilities/missing", headers=_AUTH)

    assert health.status_code == 200
    assert health.text == "ok"
    assert ready.text == "ready"
    assert unauthorized.status_code == 401
    assert unauthorized.headers["www-authenticate"] == "Bearer"
    assert unauthorized.headers["cache-control"] == "no-store"
    assert unauthorized.headers["content-type"].startswith("application/problem+json")
    assert unauthorized.json()["code"] == "authentication_failed"
    assert schema_without_auth.status_code == 401
    assert schema.status_code == 200
    assert docs.status_code == 200
    assert schema.headers["cache-control"] == "no-store"
    assert docs.headers["cache-control"] == "no-store"
    assert schema.json()["openapi"].startswith("3.1")
    assert schema.json()["paths"]["/api/v1/status"]["get"]["operationId"] == ("getNetworkStatus")
    assert "BearerAuth" in schema.json()["components"]["securitySchemes"]
    assert mcp.status_code == 401
    assert doubled_path.status_code == 404
    assert missing_capability.status_code == 404
    assert missing_capability.json()["code"] == "resource_not_found"
    assert "x-request-id" in health.headers


def test_openapi_contract_lists_the_complete_versioned_surface() -> None:
    schema = create_http_application(_config()).openapi()
    expected_operations = {
        ("/api/v1/service", "get"): "getServiceStatus",
        ("/api/v1/status", "get"): "getNetworkStatus",
        ("/api/v1/configuration", "get"): "getConfiguration",
        ("/api/v1/mesh", "get"): "getMesh",
        ("/api/v1/clients", "get"): "getClients",
        ("/api/v1/traffic", "get"): "getTraffic",
        ("/api/v1/address-reservations", "get"): "getAddressReservations",
        ("/api/v1/network/lan", "get"): "getLanConfiguration",
        ("/api/v1/network/dhcp", "get"): "getDhcpConfiguration",
        ("/api/v1/network/vlan", "get"): "getVlanConfiguration",
        ("/api/v1/network/port-forwarding", "get"): "getPortForwarding",
        ("/api/v1/network/iptv", "get"): "getIptvConfiguration",
        ("/api/v1/network/sip-alg", "get"): "getSipAlg",
        ("/api/v1/network/mac-clone", "get"): "getMacClone",
        ("/api/v1/network/ipv6", "get"): "getIpv6Configuration",
        ("/api/v1/network/ipv6/firewall", "get"): "getIpv6Firewall",
        ("/api/v1/clients/ipv6", "get"): "getIpv6Clients",
        ("/api/v1/log-types", "get"): "getLogTypes",
        ("/api/v1/logs/{index}", "get"): "getSystemLogPage",
        ("/api/v1/capabilities", "get"): "getCapabilities",
        ("/api/v1/capabilities/{name}", "get"): "getCapability",
        ("/api/v1/wlan", "get"): "getWlan",
        ("/api/v1/cloud", "get"): "getCloud",
        ("/api/v1/mutations", "get"): "getMutations",
        ("/api/v1/mutations/{name}", "get"): "getMutation",
        ("/api/v1/mutation-preflights", "post"): "preflightMutation",
        ("/api/v1/mutation-plans", "post"): "createMutationPlan",
        ("/api/v1/mutation-plans/{plan_id}", "get"): "getMutationPlan",
        ("/api/v1/mutation-plans/{plan_id}/executions", "post"): ("executeMutationPlan"),
    }
    expected_response_models = {
        ("/api/v1/service", "get"): "ServiceStatusResponse",
        ("/api/v1/status", "get"): "NetworkStatusResponse",
        ("/api/v1/configuration", "get"): "ConfigurationResponse",
        ("/api/v1/mesh", "get"): "MeshResponse",
        ("/api/v1/clients", "get"): "ClientsResponse",
        ("/api/v1/traffic", "get"): "TrafficResponse",
        ("/api/v1/address-reservations", "get"): "CapabilityResponse",
        ("/api/v1/network/lan", "get"): "LanConfigurationResponse",
        ("/api/v1/network/dhcp", "get"): "DhcpConfigurationResponse",
        ("/api/v1/network/vlan", "get"): "VlanConfigurationResponse",
        ("/api/v1/network/port-forwarding", "get"): "PortForwardingResponse",
        ("/api/v1/network/iptv", "get"): "IptvConfigurationResponse",
        ("/api/v1/network/sip-alg", "get"): "SipAlgResponse",
        ("/api/v1/network/mac-clone", "get"): "MacCloneResponse",
        ("/api/v1/network/ipv6", "get"): "Ipv6ConfigurationResponse",
        ("/api/v1/network/ipv6/firewall", "get"): "Ipv6FirewallResponse",
        ("/api/v1/clients/ipv6", "get"): "Ipv6DevicesResponse",
        ("/api/v1/log-types", "get"): "LogTypesResponse",
        ("/api/v1/logs/{index}", "get"): "SystemLogPageResponse",
        ("/api/v1/capabilities", "get"): "CapabilitiesResponse",
        ("/api/v1/capabilities/{name}", "get"): "CapabilityResponse",
        ("/api/v1/wlan", "get"): "WlanResponse",
        ("/api/v1/cloud", "get"): "CloudResponse",
        ("/api/v1/mutations", "get"): "MutationsResponse",
        ("/api/v1/mutations/{name}", "get"): "MutationResponse",
        ("/api/v1/mutation-preflights", "post"): "MutationPreflightResponse",
        ("/api/v1/mutation-plans", "post"): "MutationPlanCreatedResponse",
        ("/api/v1/mutation-plans/{plan_id}", "get"): "MutationPlanStatusResponse",
        ("/api/v1/mutation-plans/{plan_id}/executions", "post"): ("MutationExecutionResponse"),
    }
    operations = {
        (path, method): operation["operationId"]
        for path, path_item in schema["paths"].items()
        for method, operation in path_item.items()
        if method in {"get", "post"}
    }

    assert schema["openapi"].startswith("3.1")
    assert operations == expected_operations
    assert all(
        schema["paths"][path][method]["security"] == [{"BearerAuth": []}]
        for path, method in expected_operations
    )
    for (path, method), model_name in expected_response_models.items():
        status_code = "201" if model_name == "MutationPlanCreatedResponse" else "200"
        response_schema = schema["paths"][path][method]["responses"][status_code]["content"][
            "application/json"
        ]["schema"]
        assert response_schema == {"$ref": f"#/components/schemas/{model_name}"}
    assert "JsonDocument" not in schema["components"]["schemas"]
    for mode in ("Input", "Output"):
        name = f"JsonValue-{mode}"
        assert schema["components"]["schemas"][name] == {
            "anyOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "number"},
                {"type": "boolean"},
                {
                    "items": {"$ref": f"#/components/schemas/{name}"},
                    "type": "array",
                },
                {
                    "additionalProperties": {"$ref": f"#/components/schemas/{name}"},
                    "type": "object",
                },
                {"type": "null"},
            ]
        }
    assert (
        "required_confirmation"
        not in schema["components"]["schemas"]["MutationPlanStatusResponse"]["properties"]
    )
    assert {
        "schema_version",
        "status",
        "controller",
        "internet",
        "mesh",
        "provenance",
        "router_contacted",
        "mutation_invoked",
    }.issubset(schema["components"]["schemas"]["NetworkStatusResponse"]["required"])
    created_response = schema["paths"]["/api/v1/mutation-plans"]["post"]["responses"]["201"]
    assert created_response["headers"]["Location"]["schema"] == {"type": "string"}
    log_parameters = schema["paths"]["/api/v1/logs/{index}"]["get"]["parameters"]
    assert next(item for item in log_parameters if item["name"] == "index")["schema"] == {
        "minimum": 0,
        "title": "Index",
        "type": "integer",
    }


def test_response_dtos_are_frozen_protocol_neutral_mappings() -> None:
    response = _mutation_response()

    assert is_dataclass(response)
    assert response["name"] == "beamforming"
    assert dict(response) == response.to_dict()
    with pytest.raises(FrozenInstanceError):
        response.name = "changed"


def test_rest_response_accepts_deep_mixed_firmware_json() -> None:
    application = create_http_application(_config())
    service = application.state.deco_service
    capability = CapabilityResponse(
        capability="beamforming",
        schema_version=1,
        data={
            "outer": {
                "records": [
                    {
                        "nested": [
                            {
                                "value": {
                                    "still_nested": [
                                        {"enabled": True},
                                    ]
                                }
                            }
                        ]
                    }
                ]
            }
        },
        provenance={},
        mutation_invoked=False,
    )
    with (
        mock.patch.object(service, "read_capability", return_value=capability),
        TestClient(application) as client,
    ):
        response = client.get("/api/v1/capabilities/beamforming", headers=_AUTH)

    assert response.status_code == 200
    assert response.json() == capability.to_dict()


@pytest.mark.asyncio
async def test_mcp_resources_and_rest_routes_serialize_shared_results_identically() -> None:
    config = _config()
    service = mock.create_autospec(DecoService, instance=True)
    responses = _read_response_dtos(config)
    pairs = (
        ("public_status", "deco://mcp", "/api/v1/service"),
        ("network_status_resource", "deco://status", "/api/v1/status"),
        ("configuration_resource", "deco://configuration", "/api/v1/configuration"),
        ("device_inventory", "deco://mesh", "/api/v1/mesh"),
        ("client_devices_resource", "deco://devices", "/api/v1/clients"),
        ("traffic_resource", "deco://traffic", "/api/v1/traffic"),
        (
            "address_reservations_resource",
            "deco://address-reservations",
            "/api/v1/address-reservations",
        ),
        ("lan_configuration_resource", "deco://network/lan", "/api/v1/network/lan"),
        ("dhcp_configuration_resource", "deco://network/dhcp", "/api/v1/network/dhcp"),
        ("vlan_configuration_resource", "deco://network/vlan", "/api/v1/network/vlan"),
        (
            "port_forwarding_resource",
            "deco://network/port-forwarding",
            "/api/v1/network/port-forwarding",
        ),
        ("iptv_configuration_resource", "deco://network/iptv", "/api/v1/network/iptv"),
        ("sip_alg_resource", "deco://network/sip-alg", "/api/v1/network/sip-alg"),
        ("mac_clone_resource", "deco://network/mac-clone", "/api/v1/network/mac-clone"),
        (
            "ipv6_configuration_resource",
            "deco://network/ipv6",
            "/api/v1/network/ipv6",
        ),
        (
            "ipv6_firewall_resource",
            "deco://network/ipv6/firewall",
            "/api/v1/network/ipv6/firewall",
        ),
        ("ipv6_devices_resource", "deco://devices/ipv6", "/api/v1/clients/ipv6"),
        ("logs_resource", "deco://logs", "/api/v1/log-types"),
        ("system_log_page_resource", "deco://logs/2", "/api/v1/logs/2"),
        ("capabilities", "deco://capabilities", "/api/v1/capabilities"),
        ("semantic_mutations", "deco://mutations", "/api/v1/mutations"),
    )
    for method_name, _, _ in pairs:
        getattr(service, method_name).return_value = responses[method_name]
    with mock.patch("tplink_deco_api.rest.app.DecoService", return_value=service):
        application = create_http_application(config)
    mcp_server = create_server(config, service)

    with TestClient(application) as client:
        for _, resource_uri, rest_path in pairs:
            rest_response = client.get(rest_path, headers=_AUTH)
            resource_result = await mcp_server.read_resource(resource_uri)
            assert isinstance(resource_result[0].content, str)
            assert rest_response.json() == json.loads(resource_result[0].content)


def test_non_ascii_bearer_token_is_rejected_without_type_error() -> None:
    authenticator = StaticBearerAuthenticator(_TOKEN)

    assert authenticator.accepts("café") is False


def test_docs_are_absent_when_rest_is_disabled() -> None:
    application = create_http_application(_config(rest_enabled=False, rest_expose_docs=True))

    with TestClient(application) as client:
        schema = client.get("/openapi.json", headers=_AUTH)
        docs = client.get("/docs", headers=_AUTH)

    assert schema.status_code == 404
    assert docs.status_code == 404


def test_rest_read_routes_delegate_to_one_shared_service() -> None:
    config = _config()
    application = create_http_application(config)
    service = application.state.deco_service
    documents = _read_response_dtos(config)
    methods = (
        "public_status",
        "network_status_resource",
        "configuration_resource",
        "device_inventory",
        "client_devices_resource",
        "traffic_resource",
        "address_reservations_resource",
        "logs_resource",
        "system_log_page_resource",
        "capabilities",
        "read_capability",
        "wlan_state",
        "cloud_state",
    )
    with ExitStack() as stack:
        patched = {
            method: stack.enter_context(
                mock.patch.object(service, method, return_value=documents[method])
            )
            for method in methods
        }
        with TestClient(application) as client:
            responses = (
                client.get("/api/v1/service", headers=_AUTH),
                client.get("/api/v1/status", headers=_AUTH),
                client.get("/api/v1/configuration", headers=_AUTH),
                client.get("/api/v1/mesh?refresh=true", headers=_AUTH),
                client.get("/api/v1/clients?view=blocked", headers=_AUTH),
                client.get("/api/v1/traffic", headers=_AUTH),
                client.get("/api/v1/address-reservations", headers=_AUTH),
                client.get("/api/v1/log-types", headers=_AUTH),
                client.get("/api/v1/logs/2", headers=_AUTH),
                client.get("/api/v1/capabilities", headers=_AUTH),
                client.get("/api/v1/capabilities/beamforming", headers=_AUTH),
                client.get("/api/v1/wlan?include_passwords=true", headers=_AUTH),
                client.get("/api/v1/cloud", headers=_AUTH),
            )

    assert all(response.status_code == 200 for response in responses)
    assert [response.json() for response in responses] == [
        documents[method].to_dict() for method in methods
    ]
    patched["device_inventory"].assert_called_once_with(refresh=True)
    patched["client_devices_resource"].assert_called_once_with("blocked")
    patched["read_capability"].assert_called_once_with("beamforming")
    patched["wlan_state"].assert_called_once_with(include_passwords=True)
    patched["system_log_page_resource"].assert_called_once_with(2, 100)


def test_rest_mutation_catalog_and_noncreating_preflight() -> None:
    application = create_http_application(_config())
    service = application.state.deco_service
    mutation_document = _mutation_response()
    catalog = _read_response_dtos(_config())["semantic_mutations"]
    preflight = _preflight_response()
    with (
        mock.patch.object(service, "semantic_mutations", return_value=catalog) as inventory,
        mock.patch.object(
            service,
            "semantic_mutation",
            side_effect=[
                mutation_document,
                ValueError("unknown"),
            ],
        ) as one_mutation,
        mock.patch.object(
            service,
            "preflight_semantic_mutation",
            return_value=preflight,
        ) as assess,
        TestClient(application) as client,
    ):
        all_mutations = client.get("/api/v1/mutations", headers=_AUTH)
        mutation = client.get("/api/v1/mutations/beamforming", headers=_AUTH)
        missing = client.get("/api/v1/mutations/missing", headers=_AUTH)
        response = client.post(
            "/api/v1/mutation-preflights",
            headers=_AUTH,
            json={"name": "beamforming", "mode": "verify_current_value_noop"},
        )

    assert all_mutations.json() == catalog.to_dict()
    assert mutation.json()["name"] == "beamforming"
    assert missing.status_code == 404
    assert response.status_code == 200
    assert response.json()["plan_id"] is None
    inventory.assert_called_once_with()
    assert one_mutation.call_count == 2
    assess.assert_called_once_with("beamforming", {}, mode="verify_current_value_noop")


def test_rest_plan_creation_rejects_blockers_and_returns_created_plan() -> None:
    application = create_http_application(replace(_config(), rest_prefix="/router/v1"))
    service = application.state.deco_service
    blocked = _preflight_response(allowed=False)
    created = _created_plan_response()
    with (
        mock.patch.object(
            service,
            "plan_semantic_mutation",
            side_effect=[blocked, created],
        ),
        TestClient(application) as client,
    ):
        rejected = client.post(
            "/router/v1/mutation-plans",
            headers=_AUTH,
            json={"name": "beamforming", "changes": {"enable": False}},
        )
        accepted = client.post(
            "/router/v1/mutation-plans",
            headers=_AUTH,
            json={"name": "beamforming", "mode": "verify_current_value_noop"},
        )

    assert rejected.status_code == 409
    assert rejected.headers["content-type"].startswith("application/problem+json")
    assert rejected.json()["code"] == "mutation_ineligible"
    assert rejected.json()["blockers"] == blocked["blockers"]
    assert accepted.status_code == 201
    assert accepted.json()["plan_id"] == "plan-1"
    assert accepted.headers["location"] == "/router/v1/mutation-plans/plan-1"


def test_rest_cannot_create_a_tmp_mutation_plan() -> None:
    application = create_http_application(_config(allow_mutations=True, allow_tmp_reads=True))
    service = application.state.deco_service
    service._device_cache = (
        Device.from_api(
            {
                "mac": "AA:BB:CC:DD:EE:FF",
                "device_ip": "192.0.2.1",
                "device_model": "P9",
                "role": "master",
                "hardware_ver": "2.0",
                "software_ver": "1.3.0 Build 20250804 Rel. 58832",
            }
        ),
    )

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
        TestClient(application) as client,
    ):
        response = client.post(
            "/api/v1/mutation-plans",
            headers=_AUTH,
            json={"name": "monthly_report", "mode": "verify_current_value_noop"},
        )

    assert response.status_code == 409
    assert response.json()["code"] == "mutation_ineligible"
    get_client.assert_not_called()
    get_tmp_client.assert_not_called()


def test_rest_execution_is_synchronous_and_process_idempotent() -> None:
    application = create_http_application(_config())
    service = application.state.deco_service
    with (
        mock.patch.object(
            service,
            "execute_semantic_mutation",
            return_value=_execution_response(),
        ) as execute,
        TestClient(application) as client,
    ):
        first = client.post(
            "/api/v1/mutation-plans/plan-1/executions",
            headers={**_AUTH, "Idempotency-Key": "request-0001"},
            json={"confirmation": "CONFIRM"},
        )
        replay = client.post(
            "/api/v1/mutation-plans/plan-1/executions",
            headers={**_AUTH, "Idempotency-Key": "request-0001"},
            json={"confirmation": "CONFIRM"},
        )
        conflict = client.post(
            "/api/v1/mutation-plans/plan-1/executions",
            headers={**_AUTH, "Idempotency-Key": "request-0001"},
            json={"confirmation": "DIFFERENT"},
        )
        missing_key = client.post(
            "/api/v1/mutation-plans/plan-1/executions",
            headers=_AUTH,
            json={"confirmation": "CONFIRM"},
        )

    assert first.status_code == 200
    assert first.json()["idempotency_replayed"] is False
    assert replay.status_code == 200
    assert replay.json()["idempotency_replayed"] is True
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "idempotency_conflict"
    assert missing_key.status_code == 422
    assert missing_key.json()["code"] == "invalid_request"
    execute.assert_called_once_with("plan-1", "CONFIRM")


@pytest.mark.parametrize(
    ("error", "status_code", "code"),
    [
        (ExpiredPlanError("expired"), 410, "plan_expired"),
        (ConfirmationError("wrong"), 403, "request_forbidden"),
        (ControllerChangedError("changed"), 409, "controller_changed"),
        (IdempotencyInProgressError("running"), 409, "idempotency_in_progress"),
        (ValueError("bad"), 422, "invalid_request"),
        (TimeoutError("slow"), 504, "router_timeout"),
        (OSError("offline"), 503, "router_unavailable"),
        (ApiError(-1), 502, "router_error"),
    ],
)
def test_rest_maps_domain_and_router_errors(
    error: Exception,
    status_code: int,
    code: str,
) -> None:
    application = create_http_application(_config())
    service = application.state.deco_service
    with (
        mock.patch.object(service, "network_status_resource", side_effect=error),
        TestClient(application) as client,
    ):
        response = client.get(
            "/api/v1/status",
            headers={**_AUTH, "X-Request-ID": "test-request"},
        )

    assert response.status_code == status_code
    assert response.json()["code"] == code
    assert response.json()["request_id"] == "test-request"
    assert response.headers["x-request-id"] == "test-request"
    if isinstance(error, IdempotencyInProgressError):
        assert response.headers["retry-after"] == "1"


def test_rest_plan_status_maps_unknown_plan() -> None:
    application = create_http_application(_config())
    with TestClient(application) as client:
        response = client.get("/api/v1/mutation-plans/missing", headers=_AUTH)

    assert response.status_code == 404
    assert response.json()["code"] == "unknown_plan"


def test_parent_transport_security_and_cors_cover_both_surfaces() -> None:
    application = create_http_application(_config())
    with TestClient(application) as client:
        health_with_unlisted_host = client.get(
            "/healthz",
            headers={"Host": "attacker.example"},
        )
        invalid_host = client.get(
            "/api/v1/service",
            headers={
                **_AUTH,
                "Host": "attacker.example",
                "Origin": "https://dashboard.example",
            },
        )
        invalid_origin = client.get(
            "/api/v1/service",
            headers={**_AUTH, "Origin": "https://attacker.example"},
        )
        preflight = client.options(
            "/api/v1/status",
            headers={
                "Origin": "https://dashboard.example",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization,X-Request-ID",
            },
        )

    assert health_with_unlisted_host.status_code == 200
    assert invalid_host.status_code == 400
    assert invalid_host.headers["access-control-allow-origin"] == "https://dashboard.example"
    assert invalid_origin.status_code == 403
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "https://dashboard.example"
    assert "Authorization" in preflight.headers["access-control-allow-headers"]


def test_idempotency_store_expires_and_evicts_records(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _InMemoryIdempotencyStore(ttl_seconds=5.0, max_records=1)
    clock = mock.Mock(side_effect=[10.0, 10.0, 11.0, 11.0, 20.0, 20.0])
    monkeypatch.setattr("tplink_deco_api.rest._in_memory_idempotency_store.time.monotonic", clock)

    first, replayed = store.execute("one", "a", lambda: {"value": 1})
    second, second_replayed = store.execute("two", "b", lambda: {"value": 2})
    after_expiry, expired_replayed = store.execute("two", "b", lambda: {"value": 3})

    assert first == {"value": 1}
    assert replayed is False
    assert second == {"value": 2}
    assert second_replayed is False
    assert after_expiry == {"value": 3}
    assert expired_replayed is False


def test_idempotency_store_does_not_hold_global_lock_across_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _InMemoryIdempotencyStore(ttl_seconds=5.0)
    clock = mock.Mock(side_effect=[10.0, 20.0, 21.0, 22.0, 23.0])
    monkeypatch.setattr("tplink_deco_api.rest._in_memory_idempotency_store.time.monotonic", clock)
    entered = threading.Event()
    release = threading.Event()

    def slow_operation() -> dict[str, int]:
        entered.set()
        release.wait(timeout=2)
        return {"value": 1}

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(store.execute, "one", "a", slow_operation)
        assert entered.wait(timeout=1)
        with pytest.raises(IdempotencyInProgressError):
            store.execute("one", "a", lambda: {"value": 2})
        other, replayed = store.execute("two", "b", lambda: {"value": 3})
        release.set()
        first_result, first_replayed = first.result(timeout=2)

    assert other == {"value": 3}
    assert replayed is False
    assert first_result == {"value": 1}
    assert first_replayed is False


def test_composite_server_main_runs_one_worker() -> None:
    config = _config()
    application = mock.Mock()
    with (
        mock.patch(
            "tplink_deco_api.rest.server.ServerConfig.from_env",
            return_value=config,
        ),
        mock.patch(
            "tplink_deco_api.rest.server.create_http_application",
            return_value=application,
        ),
        mock.patch("tplink_deco_api.rest.server.uvicorn.run") as run,
    ):
        from tplink_deco_api.rest.server import main

        main()

    run.assert_called_once_with(
        application,
        host="127.0.0.1",
        port=8000,
        workers=1,
    )


@pytest.mark.asyncio
async def test_request_capacity_rejects_excess_router_facing_work() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def downstream(scope, receive, send) -> None:
        entered.set()
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RequestCapacityMiddleware(
        downstream,
        max_in_flight=1,
        protected_prefixes=("/api/v1", "/mcp"),
    )
    scope = {
        "type": "http",
        "path": "/api/v1/status",
        "state": {"request_id": "capacity-test"},
    }
    messages = []

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message) -> None:
        messages.append(message)

    first = asyncio.create_task(middleware(scope, receive, send))
    await entered.wait()
    await middleware(scope, receive, send)
    release.set()
    await first

    starts = [message for message in messages if message["type"] == "http.response.start"]
    assert starts[0]["status"] == 429
    assert starts[1]["status"] == 200
