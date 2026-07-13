"""Tests for MCP configuration, authorization, and tool registration."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from unittest import mock

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

from tests.response_contract_assertions import assert_response_contract
from tplink_deco_api import (
    HTTP_NOOP_CONFIRMATIONS,
    TMP_IEEE80211R_NOOP_CONFIRMATION,
    AddressReservation,
    AddressReservationTable,
    ApiError,
    ApiResponse,
    BinaryResponse,
    CapabilityReport,
    ClientDevice,
    CompatibilityManifest,
    Device,
    DeviceMode,
    EndpointProbeResult,
    InternetStatus,
    IotHost,
    IpInfo,
    IpStatus,
    LanDetails,
    LogType,
    MloHost,
    NodeClientList,
    OperationCompatibility,
    Performance,
    SpeedTest,
    SystemLogEntry,
    SystemLogPage,
    TimeSettings,
    TransportError,
    WanDetails,
    WanInfo,
    WlanBackhaul,
    WlanBand,
    WlanConfig,
    WlanGuest,
    WlanHost,
    get_endpoint,
)
from tplink_deco_api.mcp._static_token_verifier import _StaticTokenVerifier
from tplink_deco_api.mcp.server import create_server, main
from tplink_deco_api.responses import (
    ClientsResponse,
    CloudResponse,
    ConfigurationResponse,
    LogTypesResponse,
    NetworkStatusResponse,
    ServiceStatusResponse,
    SystemLogPageResponse,
    TrafficResponse,
    WlanResponse,
)
from tplink_deco_api.server import ServerConfig
from tplink_deco_api.service import DecoService


def _config(**overrides: bool) -> ServerConfig:
    values: dict[str, bool] = {
        "allow_sensitive_reads": False,
        "allow_bulk_secret_reads": False,
        "allow_binary_content": False,
        "allow_mutations": False,
        "allow_destructive": False,
        "allow_internal": False,
        "allow_tmp_noop_verification": False,
        "allow_http_noop_verification": False,
        "expose_diagnostic_tools": True,
    }
    values.update(overrides)
    return ServerConfig(
        host="192.0.2.1",
        username="admin",
        password="secret",
        timeout=60.0,
        **values,
    )


def _p9_controller() -> Device:
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


def _prime_p9_profile(service: DecoService) -> None:
    service._device_cache = (_p9_controller(),)


def test_mcp_config_from_env_and_public_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECO_HOST", "192.0.2.2")
    monkeypatch.setenv("DECO_USERNAME", "owner")
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TIMEOUT", "30")
    monkeypatch.setenv("DECO_ALLOW_SENSITIVE_READS", "yes")
    monkeypatch.setenv("DECO_ALLOW_BULK_SECRET_READS", "true")
    monkeypatch.setenv("DECO_ALLOW_BINARY_CONTENT", "1")
    monkeypatch.setenv("DECO_ALLOW_MUTATIONS", "true")
    monkeypatch.setenv("DECO_ALLOW_DESTRUCTIVE", "1")
    monkeypatch.setenv("DECO_ALLOW_INTERNAL", "on")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    monkeypatch.setenv("DECO_ALLOW_TMP_READS", "yes")
    monkeypatch.setenv("DECO_ALLOW_UNVERIFIED_TMP_READS", "true")
    monkeypatch.setenv("DECO_ALLOW_HTTP_NOOP_VERIFICATION", "on")
    monkeypatch.setenv("DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS", "on")
    monkeypatch.setenv("DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS", "on")

    config = ServerConfig.from_env()
    public = config.public_settings()

    assert config.host == "192.0.2.2"
    assert config.timeout == 30.0
    assert config.allow_sensitive_reads
    assert config.allow_bulk_secret_reads
    assert config.allow_binary_content
    assert config.allow_mutations
    assert config.allow_destructive
    assert config.allow_internal
    assert config.tp_link_id == "owner@example.com"
    assert config.tmp_host_key_sha256 == "SHA256:test"
    assert config.allow_tmp_reads
    assert config.allow_unverified_tmp_reads
    assert not config.allow_tmp_noop_verification
    assert config.allow_http_noop_verification
    assert config.expose_diagnostic_tools
    assert config.expose_raw_mutation_tools
    assert public["password_configured"] is True
    assert public["tp_link_id_configured"] is True
    assert public["tmp_host_key_sha256"] == "SHA256:test"
    assert public["allow_tmp_noop_verification"] is False
    assert public["tmp_writes_hard_disabled"] is True
    assert public["tmp_transport_status"] == "experimental"
    assert public["allow_http_noop_verification"] is True
    assert public["allow_bulk_secret_reads"] is True
    assert public["allow_binary_content"] is True
    assert public["expose_diagnostic_tools"] is True
    assert public["expose_raw_mutation_tools"] is True
    assert "password" not in public
    assert "owner@example.com" not in str(public)


def test_mcp_config_loads_streamable_http_security(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECO_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("DECO_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("DECO_SERVER_PORT", "9000")
    monkeypatch.setenv("DECO_MCP_PATH", "/router-mcp")
    monkeypatch.setenv("DECO_MCP_PUBLIC_URL", "http://192.0.2.10:9000/router-mcp")
    monkeypatch.setenv("DECO_SERVER_BEARER_TOKEN", "x" * 32)
    monkeypatch.setenv("DECO_SERVER_ALLOWED_HOSTS", "192.0.2.10:9000, localhost:9000")
    monkeypatch.setenv("DECO_SERVER_ALLOWED_ORIGINS", "https://agent.example")
    monkeypatch.setenv("DECO_REST_ENABLED", "1")
    monkeypatch.setenv("DECO_REST_PREFIX", "/router-api/v1")
    monkeypatch.setenv("DECO_REST_EXPOSE_DOCS", "true")

    config = ServerConfig.from_env()
    public = config.public_settings()

    assert config.transport == "streamable-http"
    assert config.server_host == "0.0.0.0"
    assert config.server_port == 9000
    assert config.mcp_path == "/router-mcp"
    assert config.allowed_hosts == ("192.0.2.10:9000", "localhost:9000")
    assert config.allowed_origins == ("https://agent.example",)
    assert public["server_bearer_token_configured"] is True
    assert config.rest_enabled is True
    assert config.rest_prefix == "/router-api/v1"
    assert config.rest_expose_docs is True
    assert "x" * 32 not in str(public)


@pytest.mark.parametrize("value", ["invalid", "0", "65536"])
def test_mcp_config_rejects_invalid_http_port(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DECO_SERVER_PORT", value)

    with pytest.raises(ValueError, match="DECO_SERVER_PORT"):
        ServerConfig.from_env()


def test_mcp_config_rejects_incomplete_streamable_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DECO_MCP_TRANSPORT", "streamable-http")

    with pytest.raises(ValueError, match="DECO_MCP_PUBLIC_URL"):
        ServerConfig.from_env()

    short_token = replace(
        _config(),
        transport="streamable-http",
        mcp_public_url="http://192.0.2.10:8000/mcp",
        bearer_token="short",
        allowed_hosts=("192.0.2.10:8000",),
    )
    with pytest.raises(ValueError, match="DECO_SERVER_BEARER_TOKEN"):
        create_server(short_token)

    missing_hosts = replace(short_token, bearer_token="x" * 32, allowed_hosts=())
    with pytest.raises(ValueError, match="DECO_SERVER_ALLOWED_HOSTS"):
        create_server(missing_hosts)


@pytest.mark.parametrize("value", ["invalid", "0", "-1"])
def test_mcp_config_rejects_invalid_timeout(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DECO_TIMEOUT", value)

    with pytest.raises(ValueError, match="DECO_TIMEOUT"):
        ServerConfig.from_env()


@pytest.mark.parametrize("value", ["api/v1", "/api/v1/"])
def test_server_config_rejects_invalid_rest_prefix(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DECO_REST_PREFIX", value)

    with pytest.raises(ValueError, match="DECO_REST_PREFIX"):
        ServerConfig.from_env()


@pytest.mark.parametrize("value", ["mcp", "/mcp/", "/"])
def test_server_config_rejects_invalid_mcp_path(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DECO_MCP_PATH", value)

    with pytest.raises(ValueError, match="DECO_MCP_PATH"):
        ServerConfig.from_env()


@pytest.mark.parametrize(
    ("rest_prefix", "mcp_path"),
    [
        ("/api/v1", "/api/v1"),
        ("/mcp/api", "/mcp"),
        ("/api", "/api/mcp"),
        ("/docs", "/mcp"),
        ("/api/v1", "/readyz"),
        ("/healthz/api", "/mcp"),
    ],
)
def test_server_config_rejects_overlapping_http_paths(
    rest_prefix: str,
    mcp_path: str,
) -> None:
    config = replace(_config(), rest_prefix=rest_prefix, mcp_path=mcp_path)

    with pytest.raises(ValueError, match="must not overlap"):
        config.validate_server()


@pytest.mark.parametrize("value", ["invalid", "0", "-1"])
def test_server_config_rejects_invalid_request_capacity(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DECO_SERVER_MAX_IN_FLIGHT_REQUESTS", value)

    with pytest.raises(ValueError, match="DECO_SERVER_MAX_IN_FLIGHT_REQUESTS"):
        ServerConfig.from_env()


def test_mcp_service_catalog_and_public_status() -> None:
    service = DecoService(_config())

    read_catalog = service.endpoint_catalog("read_only")
    public_catalog = service.endpoint_catalog()
    p9_catalog = service.endpoint_catalog(model="P9")
    status = service.public_status()
    profile = service.p9_profile()

    assert_response_contract(ServiceStatusResponse, status)

    assert read_catalog
    assert all(item["safety"] == "read_only" for item in read_catalog)
    assert all(item["sensitivity"] != "secret" for item in public_catalog)
    assert all("model_compatibility" in item for item in p9_catalog)
    assert status["password_configured"] is True
    assert status["authenticated"] is False
    assert isinstance(status["catalogued_operations"], int)
    assert profile["firmware_version"] == "1.3.0 Build 20250804 Rel. 58832"
    assert len(profile["supported_reads"]) == 60
    assert profile["read_observation_counts"] == {
        "invalid_response": 1,
        "not_found": 100,
        "rejected": 52,
        "supported": 60,
        "transport_error": 6,
    }
    assert len(profile["mutation_candidates"]) == 23
    assert profile["web_asset_observation"] == {
        "observed_at": "2026-07-10T22:16:00+00:00",
        "asset_files": 39,
        "controllers": 18,
        "forms": 48,
        "previously_uncatalogued_forms": 10,
        "live_reads": {
            "accepted_null": 2,
            "supported_data": 1,
            "rejected": 2,
            "not_found": 2,
            "invalid_response": 0,
        },
        "evidence": "docs/api-responses/p9-web-assets.json",
    }
    assert profile["client_topology"] == {
        "per_node_query": "supported",
        "default_set_matches_per_node_union": True,
        "duplicate_assignments_observed": False,
        "node_association_source": "queried device_mac",
        "access_host_semantics": "opaque; does not match the queried node MAC or device ID",
    }
    assert profile["fuzzy_read_observation"] == {
        "observed_at": "2026-07-10T20:55:48.128101+00:00",
        "candidate_count": 237,
        "consistent": 237,
        "rejected": 191,
        "accepted_null": 40,
        "transport_error": 6,
        "returned_data": 0,
        "session_recovered": 1,
        "conclusion": (
            "bounded read/get/getlist/list aliases and safe parameter variants did not identify "
            "any additional data-returning P9 endpoint"
        ),
    }
    assert "complete table equality" in str(profile["mutation_evidence"])
    assert "beamforming" in str(profile["mutation_evidence"])
    assert "802.11r" in str(profile["mutation_evidence"])
    assert "time-settings" in str(profile["mutation_evidence"])
    assert profile["model_compatibility"]["summary"]["returned_data"] == 32
    assert profile["sensitive_schema_observation"] == {
        "observed_at": "2026-07-10T22:46:56.546969+00:00",
        "endpoint_count": 55,
        "supported": 19,
        "rejected": 5,
        "not_found": 30,
        "transport_error": 1,
        "returned_data": 4,
        "accepted_empty": 15,
        "asset_backed_seeded": 9,
        "newly_probed": 46,
        "values_retained": False,
        "binary_reads_excluded": True,
        "evidence": "docs/api-responses/p9-all-sensitive-compatibility.json",
    }
    assert profile["bootstrap_observation"] == {
        "observed_at": "2026-07-11",
        "attempted": 4,
        "supported": 3,
        "transport_error": 1,
        "authenticated": False,
        "values_retained": False,
        "credential_values_emitted": False,
        "evidence": "docs/api-responses/p9-bootstrap-compatibility.json",
    }
    assert profile["domain_login_observation"] == {
        "observed_at": "2026-07-11T08:40:28Z",
        "authentication": "encrypted_owner_session",
        "availability": "supported",
        "returned_data": False,
        "values_retained": False,
        "evidence": "docs/api-responses/p9-domain-login-compatibility.json",
    }

    performance = service.operation_compatibility("admin.network.performance.read")
    assert performance["compatibility"]["availability"] == "supported"
    assert performance["compatibility"]["returned_data"] is True
    assert "$.cpu_usage:number" in performance["compatibility"]["schema_paths"]

    with pytest.raises(ValueError, match="invalid safety level"):
        service.endpoint_catalog("unsafe")
    with pytest.raises(KeyError, match="Unknown Deco model"):
        service.endpoint_catalog(model="X99")


def test_mcp_service_reports_transport_coverage_offline() -> None:
    service = DecoService(_config())

    with mock.patch.object(service, "_get_client") as get_client:
        capabilities = service.transport_capabilities()

    get_client.assert_not_called()
    assert capabilities["catalogued_http_operations"] == 570
    transports = {item["authentication"]: item for item in capabilities["transports"]}
    assert set(transports) == {
        "bootstrap",
        "download",
        "encrypted",
        "group_key",
        "multipart",
        "plain",
        "token",
    }
    assert transports["encrypted"]["implemented"] is True
    assert transports["plain"]["implemented"] is True
    assert transports["bootstrap"]["implemented"] is True
    assert transports["bootstrap"]["bootstrap_call_supported"] == 4
    assert transports["multipart"]["implemented"] is True
    assert transports["multipart"]["binary_call_supported"] == 1
    assert "backup is supported" in transports["multipart"]["notes"]
    assert transports["group_key"]["implemented"] is False
    assert transports["token"]["implemented"] is False
    assert capabilities["binary_policy"] == {
        "bulk_secret_gate_required": True,
        "bulk_secret_gate_enabled": False,
        "content_export_gate_required": True,
        "content_export_gate_enabled": False,
        "digest_discovery_operation": "discover_p9_binary_reads",
        "binary_content_returned_by_discovery": False,
    }
    assert capabilities["tmp_appv2"]["external_port"] == 20001
    assert capabilities["tmp_appv2"]["protocol_implemented"] is True
    assert capabilities["tmp_appv2"]["read_only_session_implemented"] is True
    assert capabilities["tmp_appv2"]["scoped_noop_verification_implemented"] is False
    assert capabilities["tmp_appv2"]["scoped_noop_runtime_gate_enabled"] is False
    assert capabilities["tmp_appv2"]["server_writes_hard_disabled"] is True
    assert capabilities["tmp_appv2"]["source_checkout_lab_harness_available"] is True
    assert capabilities["tmp_appv2"]["generic_mutation_implemented"] is False
    assert capabilities["tmp_appv2"]["ssh_adapter_implemented"] is True
    assert capabilities["tmp_appv2"]["p9_transport_authenticated"] is True
    assert capabilities["tmp_appv2"]["p9_opcode_tested_count"] == 251
    assert capabilities["tmp_appv2"]["p9_service_detected"] is True


def test_mcp_service_reports_unified_p9_access_coverage_offline() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        coverage = service.p9_access_coverage()

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()
    assert coverage["offline"] is True
    assert coverage["router_contacted"] is False
    assert coverage["unified_semantic_surface"]["capability_count"] == 6
    assert coverage["unified_semantic_surface"]["mutation_capability_count"] == 3
    assert coverage["unified_semantic_surface"]["caller_selects_protocol"] is False
    assert coverage["unified_semantic_surface"]["automatic_mutation_fallback"] is False
    assert coverage["http"]["catalogued_read_count"] == 219
    assert coverage["http"]["p9_observation_counts"] == {
        "invalid_response": 1,
        "not_found": 100,
        "rejected": 52,
        "supported": 60,
        "transport_error": 6,
    }
    assert coverage["http"]["returned_data_count"] == 32
    assert coverage["http"]["accepted_empty_count"] == 28
    assert coverage["http"]["supported_individual_callable_count"] == 60
    assert coverage["http"]["supported_batch_json_count"] == 60
    assert coverage["http"]["supported_without_call_path"] == []
    assert coverage["http"]["untested_binary_count"] == 0
    assert coverage["http"]["untested_binary_operations"] == []
    assert coverage["http"]["bulk_secret_runtime_gate_enabled"] is False
    assert coverage["http"]["binary_content_export_gate_enabled"] is False
    assert coverage["http"]["safe_untested_json_count"] == 0
    assert coverage["http"]["catalogued_read_without_transport_count"] == 0
    assert coverage["http"]["catalogued_read_without_transport"] == []
    assert coverage["http"]["untested_operation_details"] == []
    assert coverage["tmp"]["read_count"] == 246
    assert coverage["tmp"]["catalogued_read_count"] == 246
    assert coverage["tmp"]["p9_tested_read_count"] == 246
    assert coverage["tmp"]["returned_data_count"] == 55
    assert coverage["tmp"]["returned_binary_count"] == 1
    assert coverage["tmp"]["parameterized_returned_data_count"] == 7
    assert coverage["tmp"]["batch_without_params_count"] == 48
    assert coverage["tmp"]["batch_with_confirmed_params_count"] == 55
    assert coverage["tmp"]["parameterized_batch_opt_in_supported"] is True
    assert coverage["tmp"]["parameterized_batch_request_values_returned"] is False
    assert coverage["tmp"]["payload_rejected_count"] == 4
    assert coverage["tmp"]["payload_rejected_exact_app_contract_count"] == 3
    assert coverage["tmp"]["payload_rejected_unresolved_app_contract_count"] == 1
    assert coverage["tmp"]["appv2_rejected_count"] == 186
    assert coverage["tmp"]["untested_read_count"] == 0
    assert coverage["tmp"]["all_reads_tested"] is True
    assert coverage["mutations"]["http"] == {
        "p9_candidate_count": 23,
        "tested_count": 4,
        "execution_eligible_count": 0,
        "execution_available": True,
        "execution_policy": "general_scope_model_evidence_required",
        "verification_candidate_count": 0,
        "verification_queue_operation": "p9_http_mutation_verification_queue",
        "scoped_noop_operation_count": 3,
        "scoped_noop_runtime_gate_enabled": False,
        "scoped_noop_execution_eligible_count": 0,
        "scoped_noop_executors": [
            "verify_setting_noop",
            "verify_p9_http_noop",
        ],
    }
    assert coverage["mutations"]["tmp"] == {
        "candidate_count": 348,
        "tested_count": 3,
        "static_app_contract_count": 315,
        "direct_static_app_contract_count": 291,
        "indirect_static_app_contract_count": 24,
        "static_app_contract_missing_count": 33,
        "complete_safety_contract_count": 0,
        "p9_static_key_preflight_count": 67,
        "preflight_candidate_key_coverage_complete_count": 19,
        "preflight_candidate_key_coverage_blocked_count": 48,
        "execution_eligible_count": 0,
        "execution_available": False,
        "generic_execution_available": False,
        "scoped_noop_executor_count": 0,
        "scoped_noop_runtime_gate_enabled": False,
        "scoped_noop_executors": [],
        "server_write_policy": "hard_disabled",
        "source_checkout_lab_harness_available": True,
        "verification_candidate_count": 0,
        "default_verification_queue_count": 0,
        "verification_queue_operation": "p9_tmp_mutation_verification_queue",
    }
    assert coverage["invariants"] == {
        "all_positive_http_reads_have_caller_path": True,
        "all_positive_tmp_reads_have_caller_path": True,
        "all_positive_tmp_json_reads_have_batch_path": True,
        "all_positive_reads_have_caller_path": True,
        "all_tmp_reads_tested_on_p9": True,
        "mutations_default_disabled": True,
        "http_generic_noop_only_execution_absent": True,
        "http_scoped_noop_execution_exposed": True,
        "tmp_generic_mutation_execution_absent": True,
        "tmp_scoped_noop_execution_exposed": False,
        "tmp_server_writes_hard_disabled": True,
    }
    assert coverage["unresolved_summary"] == {
        "http_binary_reads_untested": 0,
        "http_binary_reads_transport_error": 2,
        "http_binary_reads_invalid_response": 1,
        "tmp_reads_payload_rejected": 4,
        "tmp_read_contract_unresolved": 1,
        "http_mutations_untested": 19,
        "http_mutations_general_scope_verified": 0,
        "tmp_mutations_untested": 345,
        "tmp_mutations_general_scope_verified": 0,
    }
    assert coverage["authorization_ready_action_count"] == 0
    actions = {action["id"]: action for action in coverage["authorization_ready_actions"]}
    assert actions == {}
    audits = {audit["id"]: audit for audit in coverage["completed_live_audits"]}
    assert set(audits) == {
        "p9_tmp_iot_module_contract_discovery",
        "p9_http_binary_digest_discovery",
        "p9_mcp_complete_tmp_batch_audit",
        "p9_tmp_beamforming_noop_verification",
        "p9_tmp_monthly_report_noop_verification",
    }
    assert audits["p9_mcp_complete_tmp_batch_audit"]["mutation_invoked"] is False
    assert audits["p9_tmp_beamforming_noop_verification"]["state_unchanged"] is True
    assert audits["p9_tmp_monthly_report_noop_verification"]["state_unchanged"] is True
    assert all(action["explicit_authorization_required"] for action in actions.values())
    assert all(action["live_invoked"] is False for action in actions.values())
    assert {item["surface"] for item in coverage["remaining_gaps"]} == {
        "tmp_reads",
        "http_reads",
        "http_mutations",
        "tmp_mutations",
    }
    gaps = {item["surface"]: item for item in coverage["remaining_gaps"]}
    assert gaps["http_mutations"]["count"] == 23
    assert "no new bounded candidates" in gaps["http_mutations"]["next_action"]
    assert gaps["tmp_mutations"]["count"] == 345
    assert "isolated source-checkout" in gaps["tmp_mutations"]["next_action"]


def test_mcp_service_filters_unverified_tmp_opcode_catalog_offline() -> None:
    service = DecoService(_config())

    with mock.patch.object(service, "_get_client") as get_client:
        catalog = service.p9_tmp_opcode_catalog(category="plc")

    get_client.assert_not_called()
    assert catalog["catalogued_opcode_count"] == 600
    assert catalog["returned_opcode_count"] == 2
    assert catalog["p9_transport_detected"] is True
    assert catalog["p9_opcode_tested_count"] == 251
    assert catalog["p9_observation_counts"] == {
        "accepted": 2,
        "payload_rejected": 4,
        "rejected": 186,
        "returned_binary": 1,
        "returned_data": 55,
        "untested": 352,
    }
    assert catalog["protocol_implemented"] is True
    assert catalog["read_only_session_implemented"] is True
    assert catalog["ssh_adapter_implemented"] is True
    assert [item["hex_code"] for item in catalog["opcodes"]] == ["0x424C", "0x424D"]

    alias = service.p9_tmp_opcode_catalog(query="TIME_SYNC")
    assert alias["returned_opcode_count"] == 1
    assert alias["opcodes"][0]["hex_code"] == "0x400E"
    assert alias["filter"]["query"] == "TIME_SYNC"

    with pytest.raises(ValueError, match="invalid safety level"):
        service.p9_tmp_opcode_catalog(safety="unsafe")


def test_mcp_service_reports_tmp_mutation_inventory_offline() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        inventory = service.p9_tmp_mutation_inventory()
        plan = service.plan_tmp_mutation(0x40C1)

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()
    assert inventory["candidate_count"] == 348
    assert inventory["safety_counts"] == {"destructive": 71, "mutation": 277}
    assert inventory["preflight_relationship_count"] == 222
    assert inventory["p9_supported_preflight_count"] == 70
    assert inventory["p9_static_key_preflight_count"] == 67
    assert inventory["preflight_candidate_key_coverage_complete_count"] == 19
    assert inventory["preflight_candidate_key_coverage_blocked_count"] == 48
    assert inventory["rollback_relationship_count"] == 188
    assert inventory["preflight_relationship_evidence_counts"] == {
        "curated_opcode_relationship": 81,
        "signed_app_opcode_name_pair_inference": 141,
    }
    assert inventory["rollback_relationship_evidence_counts"] == {
        "curated_opcode_relationship": 24,
        "preflight_state_restore": 130,
        "signed_app_inverse_name_pair_inference": 34,
    }
    assert inventory["known_parameter_contract_count"] == 315
    assert inventory["static_app_contract_count"] == 315
    assert inventory["direct_static_app_contract_count"] == 291
    assert inventory["indirect_static_app_contract_count"] == 24
    assert inventory["static_app_candidate_keys_count"] == 274
    assert inventory["static_app_null_payload_count"] == 27
    assert inventory["static_app_model_only_count"] == 14
    assert inventory["static_app_contract_missing_count"] == 33
    assert inventory["mutation_tested_count"] == 3
    assert inventory["complete_safety_contract_count"] == 0
    assert inventory["execution_eligible_count"] == 0
    assert inventory["execution_available"] is False
    assert inventory["generic_execution_available"] is False
    assert inventory["scoped_noop_executor_count"] == 0
    assert inventory["scoped_noop_runtime_gate_enabled"] is False
    assert inventory["scoped_noop_operations"] == []
    assert inventory["server_write_policy"] == "hard_disabled"
    assert inventory["tmp_transport_status"] == "experimental"
    assert inventory["prepared_verification_harness_count"] == 3
    assert all(
        harness["scope"] == "isolated_source_checkout_lab_only"
        and harness["execution_available"] is False
        for harness in inventory["prepared_verification_harnesses"]
    )
    ieee80211r = next(plan for plan in inventory["plans"] if plan["code"] == 0x4209)
    assert ieee80211r["scoped_execution_supported"] is False
    assert ieee80211r["runtime_gate_enabled"] is False
    assert ieee80211r["execution_eligible"] is False
    beamforming = next(plan for plan in inventory["plans"] if plan["code"] == 0x421C)
    assert beamforming["verification_harness"] == "examples/verify_tmp_beamforming_noop.py"
    assert beamforming["live_verification_invoked"] is True
    assert beamforming["scoped_execution_supported"] is False
    assert beamforming["execution_eligible"] is False
    monthly_report = next(plan for plan in inventory["plans"] if plan["code"] == 0x4223)
    assert monthly_report["verification_harness"] == ("examples/verify_tmp_monthly_report_noop.py")
    assert monthly_report["live_verification_invoked"] is True
    assert monthly_report["scoped_execution_supported"] is False
    assert monthly_report["runtime_gate_enabled"] is False
    assert monthly_report["execution_eligible"] is False
    qos = next(plan for plan in inventory["plans"] if plan["code"] == 0x4037)
    assert qos["preflight_result_keys"] == ("custom_detail",)
    assert qos["preflight_missing_candidate_keys"] == ("qos_mode",)
    assert plan["name"] == "TMP_APPV2_OP_IP_RESERVATION_LIST_ADD"
    assert plan["preflight_hex_code"] == "0x40C0"
    assert plan["rollback_hex_code"] == "0x40C3"
    assert plan["parameter_contract"] == (
        "static_app_candidate_keys:reservation_list,reservation_list_max_count"
    )
    assert plan["app_request_models"] == ("ReservationListBean",)
    assert plan["p9_parameter_contract_verified"] is False
    assert plan["execution_eligible"] is False

    with pytest.raises(ValueError, match="is read_only"):
        service.plan_tmp_mutation(0x4004)

    enabled = DecoService(
        _config(
            allow_mutations=True,
            allow_tmp_reads=True,
            allow_tmp_noop_verification=True,
        )
    ).p9_tmp_mutation_inventory()
    assert enabled["execution_eligible_count"] == 0
    assert enabled["scoped_noop_runtime_gate_enabled"] is False


def test_mcp_service_ranks_tmp_mutation_verification_offline() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch.object(service, "_get_tmp_client") as get_tmp_client,
    ):
        queue = service.p9_tmp_mutation_verification_queue(limit=4)

    get_client.assert_not_called()
    get_tmp_client.assert_not_called()
    assert queue["candidate_count"] == 348
    assert queue["tier_counts"] == {
        "destructive_excluded": 71,
        "evidence_blocked": 193,
        "high_risk_deferred": 81,
        "safety_not_established": 3,
    }
    assert queue["verification_candidate_count"] == 0
    assert queue["returned_count"] == 0
    assert queue["returned_tier_counts"] == {}
    assert queue["candidates"] == []
    assert queue["explicit_per_operation_authorization_required"] is True
    assert queue["parameter_values_included"] is False
    assert queue["payloads_generated"] is False
    assert queue["mutation_invoked"] is False
    assert queue["execution_available"] is False


def test_mcp_service_hard_blocks_tmp_writes_with_all_gates_enabled() -> None:
    get_tmp_client = mock.Mock()
    service = DecoService(
        _config(
            allow_mutations=True,
            allow_tmp_reads=True,
            allow_tmp_noop_verification=True,
        )
    )
    with (
        mock.patch.object(service, "_get_tmp_client", get_tmp_client),
        pytest.raises(PermissionError, match="server-side TMP writes are hard-disabled"),
    ):
        service.verify_tmp_ieee80211r_noop(TMP_IEEE80211R_NOOP_CONFIRMATION)

    get_tmp_client.assert_not_called()


def test_mcp_http_noop_verification_rejects_before_router_contact() -> None:
    operation = "admin.wireless.beamforming.write"
    confirmation = HTTP_NOOP_CONFIRMATIONS[operation]
    get_client = mock.Mock()

    service = DecoService(_config())
    with (
        mock.patch.object(service, "_get_client", get_client),
        pytest.raises(PermissionError, match="exact per-call confirmation"),
    ):
        service.verify_p9_http_noop(operation, "wrong")

    service = DecoService(_config(allow_mutations=True))
    with (
        mock.patch.object(service, "_get_client", get_client),
        pytest.raises(PermissionError, match="ALLOW_HTTP_NOOP_VERIFICATION"),
    ):
        service.verify_p9_http_noop(operation, confirmation)

    service = DecoService(_config(allow_http_noop_verification=True))
    with (
        mock.patch.object(service, "_get_client", get_client),
        pytest.raises(PermissionError, match="ALLOW_MUTATIONS"),
    ):
        service.verify_p9_http_noop(operation, confirmation)

    with pytest.raises(ValueError, match="unsupported operation"):
        service.verify_p9_http_noop("admin.client.addr_reservation.modify", "wrong")

    get_client.assert_not_called()


def test_mcp_http_noop_verification_executes_only_verified_current_value() -> None:
    operation = "admin.device.timesetting.write"
    read_operation = "admin.device.timesetting.read"
    confirmation = HTTP_NOOP_CONFIRMATIONS[operation]
    state = {"timezone": "GMT0BST", "continent": "Europe", "tz_region": "London"}
    service = DecoService(
        _config(
            allow_mutations=True,
            allow_http_noop_verification=True,
        )
    )
    _prime_p9_profile(service)
    client = mock.Mock()
    client.call.side_effect = [
        ApiResponse.from_api({"error_code": 0, "result": state}),
        ApiResponse.from_api({"error_code": 0}),
        ApiResponse.from_api({"error_code": 0, "result": state}),
    ]

    with mock.patch.object(service, "_get_client", return_value=client):
        result = service.verify_p9_http_noop(operation, confirmation)

    assert result["status"] == "verified_noop"
    assert result["execution_scope"] == "verified_current_value_noop_only"
    assert result["generic_http_noop_execution_supported"] is False
    assert result["requires_attention"] is False
    assert result["parameter_values_retained"] is False
    assert result["response_values_retained"] is False
    assert client.call.call_args_list == [
        mock.call(get_endpoint(read_operation)),
        mock.call(get_endpoint(operation), state),
        mock.call(get_endpoint(read_operation)),
    ]


def test_mcp_http_noop_verification_latches_after_nonverified_outcome() -> None:
    operation = "admin.wireless.ieee80211r.write"
    confirmation = HTTP_NOOP_CONFIRMATIONS[operation]
    state = {"enable": True}
    service = DecoService(
        _config(
            allow_mutations=True,
            allow_http_noop_verification=True,
        )
    )
    _prime_p9_profile(service)
    client = mock.Mock()
    client.call.side_effect = [
        ApiResponse.from_api({"error_code": 0, "result": state}),
        ApiResponse.from_api({"error_code": 1}),
        ApiResponse.from_api({"error_code": 0, "result": state}),
    ]

    with mock.patch.object(service, "_get_client", return_value=client):
        result = service.verify_p9_http_noop(operation, confirmation)
        with pytest.raises(PermissionError, match="safety latch"):
            service.verify_p9_http_noop(operation, confirmation)

    assert result["status"] == "write_rejected_or_uncertain_state_unchanged"
    assert result["requires_attention"] is True
    assert service.public_status()["http_mutation_latched"] is True
    assert client.call.call_count == 3


def test_mcp_tmp_host_key_probe_does_not_authenticate() -> None:
    config = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
    )
    client = mock.Mock()
    client.probe_host_key.return_value = "SHA256:observed"
    with mock.patch("tplink_deco_api.service.deco_service.DecoTmpClient", return_value=client):
        result = DecoService(config).tmp_host_key()

    assert result == {
        "host": "192.0.2.1",
        "port": 20001,
        "host_key_sha256": "SHA256:observed",
        "authentication_attempted": False,
        "tmp_payload_sent": False,
        "matches_configured": False,
    }


def test_mcp_tmp_read_enforces_independent_model_and_sensitivity_gates() -> None:
    base = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    with pytest.raises(PermissionError, match="ALLOW_TMP_READS"):
        DecoService(base).tmp_read(0x400F)

    enabled = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
        allow_tmp_reads=True,
    )
    service = DecoService(enabled)
    get_client = mock.Mock()
    with mock.patch.object(service, "_get_tmp_client", get_client):
        with pytest.raises(ValueError, match="unknown opcode"):
            service.tmp_read(0xFFFF)
        with pytest.raises(PermissionError, match="is mutation"):
            service.tmp_read(0x424D)
        with pytest.raises(PermissionError, match="rejected by the P9"):
            service.tmp_read(0x424C)
        with pytest.raises(PermissionError, match="binary TMP read operation"):
            service.tmp_read(0x401E)
        with pytest.raises(PermissionError, match="SENSITIVE_READS"):
            service.tmp_read(0x4009)
    get_client.assert_not_called()


def test_mcp_tmp_read_calls_positively_observed_reads() -> None:
    verified_config = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
        allow_tmp_reads=True,
    )
    client = mock.Mock()
    client.request_read_json.return_value = {"error_code": 0}
    service = DecoService(verified_config)
    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        assert service.tmp_read(0x400F, None) == {"error_code": 0}
    client.request_read_json.assert_called_once_with(0x400F, None)

    location = DecoService(verified_config)
    with mock.patch.object(location, "_get_tmp_client", return_value=client):
        location.tmp_read(0x400A, {})
    client.request_read_json.assert_called_with(0x400A, {})

    parameterized = DecoService(replace(verified_config, allow_sensitive_reads=True))
    with mock.patch.object(parameterized, "_get_tmp_client", return_value=client) as get_client:
        with pytest.raises(ValueError, match="parameters are required"):
            parameterized.tmp_read(0x402D)
        with pytest.raises(ValueError, match="parameter keys must exactly match"):
            parameterized.tmp_read(0x402D, {"id": "owner"})
        with pytest.raises(ValueError, match="owner_id must be a non-empty string"):
            parameterized.tmp_read(0x402D, {"owner_id": ""})
        with pytest.raises(ValueError, match="page must be an integer"):
            parameterized.tmp_read(
                0x402F,
                {"owner_id": "owner", "page": True, "page_size": 20},
            )
        with pytest.raises(ValueError, match="version must be a non-negative integer"):
            parameterized.tmp_read(0x403A, {"version": -1})
        with pytest.raises(ValueError, match="iot_client_list must be an array of objects"):
            parameterized.tmp_read(0x4049, {"iot_client_list": ["not-an-object"]})
        assert parameterized.tmp_read(0x402D, {"owner_id": "owner"}) == {"error_code": 0}
        parameterized.tmp_read(
            0x4031,
            {"owner_id": "owner", "start_time": 1, "end_time": 2},
        )
        parameterized.tmp_read(0x403A, {"version": 1029})
        parameterized.tmp_read(0x4049, {"iot_client_list": []})
    assert get_client.call_count == 4
    client.request_read_json.assert_called_with(
        0x4049,
        {"iot_client_list": []},
    )


def test_mcp_tmp_binary_read_returns_digest_and_gates_content() -> None:
    config = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
        allow_tmp_reads=True,
    )
    client = mock.Mock()
    client.request_read.return_value = b"binary"
    service = DecoService(config)
    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        result = service.tmp_read_binary(0x401E, None)
        with pytest.raises(PermissionError, match="SENSITIVE_READS"):
            service.tmp_read_binary(0x401E, None, include_content=True)
        with pytest.raises(PermissionError, match="lacks a P9 binary observation"):
            service.tmp_read_binary(0x400F)
        with pytest.raises(PermissionError, match="is mutation"):
            service.tmp_read_binary(0x424D)
        with pytest.raises(ValueError, match="unknown opcode"):
            service.tmp_read_binary(0xFFFF)

    assert result["size"] == 6
    assert result["sha256"] == hashlib.sha256(b"binary").hexdigest()
    assert result["content_base64"] is None

    allowed = DecoService(
        replace(
            config,
            allow_sensitive_reads=True,
            allow_binary_content=True,
        )
    )
    with mock.patch.object(allowed, "_get_tmp_client", return_value=client):
        content = allowed.tmp_read_binary(0x401E, include_content=True)
    assert content["content_base64"] == "YmluYXJ5"


def test_mcp_tmp_contract_discovery_requires_read_and_inference_gates() -> None:
    base = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    with pytest.raises(PermissionError, match="ALLOW_TMP_READS"):
        DecoService(base).discover_tmp_read_contracts()

    tmp_enabled = replace(base, allow_tmp_reads=True)
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(tmp_enabled).discover_tmp_read_contracts()

    sensitive_enabled = replace(tmp_enabled, allow_sensitive_reads=True)
    with pytest.raises(PermissionError, match="ALLOW_UNVERIFIED_TMP_READS"):
        DecoService(sensitive_enabled).discover_tmp_read_contracts(
            include_inferred_iot_module_contract=True
        )

    service = DecoService(replace(sensitive_enabled, allow_unverified_tmp_reads=True))
    client = mock.Mock()
    expected = {"confirmed_contract_count": 1}
    with (
        mock.patch.object(service, "_get_tmp_client", return_value=client),
        mock.patch(
            "tplink_deco_api.service.deco_service.probe_tmp_read_contracts",
            return_value=expected,
        ) as probe,
    ):
        assert (
            service.discover_tmp_read_contracts(include_inferred_iot_module_contract=True)
            == expected
        )
    probe.assert_called_once_with(client, include_inferred_iot_module_contract=True)


def test_mcp_unverified_tmp_discovery_requires_independent_gates() -> None:
    base = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    with pytest.raises(PermissionError, match="ALLOW_TMP_READS"):
        DecoService(base).discover_tmp_unverified_reads()

    tmp_enabled = replace(base, allow_tmp_reads=True)
    with pytest.raises(PermissionError, match="ALLOW_UNVERIFIED_TMP_READS"):
        DecoService(tmp_enabled).discover_tmp_unverified_reads()

    unverified_enabled = replace(tmp_enabled, allow_unverified_tmp_reads=True)
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(unverified_enabled).discover_tmp_unverified_reads(include_sensitive=True)

    service = DecoService(unverified_enabled)
    client = mock.Mock()
    expected = {"selected_operation_count": 1}
    with (
        mock.patch.object(service, "_get_tmp_client", return_value=client),
        mock.patch(
            "tplink_deco_api.service.deco_service.probe_tmp_unverified_reads",
            return_value=expected,
        ) as probe,
    ):
        assert service.discover_tmp_unverified_reads(max_operations=1) == expected
    probe.assert_called_once_with(
        client,
        include_sensitive=False,
        max_operations=1,
    )


def test_mcp_p9_tmp_data_requires_secret_gate_and_batches_confirmed_reads() -> None:
    base = ServerConfig(
        "192.0.2.1",
        "admin",
        "secret",
        60.0,
        tp_link_id="owner@example.com",
        tmp_host_key_sha256="SHA256:test",
    )
    with pytest.raises(PermissionError, match="ALLOW_TMP_READS"):
        DecoService(base).p9_tmp_data("qos")
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(replace(base, allow_tmp_reads=True)).p9_tmp_data("qos")

    service = DecoService(replace(base, allow_tmp_reads=True, allow_sensitive_reads=True))
    client = mock.Mock()
    client.request_read_json.return_value = {
        "error_code": 0,
        "result": {"mode": "private-value"},
    }
    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        result = service.p9_tmp_data("qos")

    assert result["available_count"] == 1
    assert result["selected_count"] == 1
    assert result["skipped_parameterized_count"] == 0
    assert result["succeeded_count"] == 1
    assert result["failed_count"] == 0
    assert result["values_included"] is True
    assert result["mutation_invoked"] is False
    assert result["results"] == [
        {
            "code": 0x4036,
            "hex_code": "0x4036",
            "name": "TMP_APPV2_OP_QOS_MODE_GET",
            "category": "qos",
            "status": "ok",
            "response": {"error_code": 0, "result": {"mode": "private-value"}},
        }
    ]
    client.request_read_json.assert_called_once_with(0x4036)

    with pytest.raises(ValueError, match="unknown category"):
        service.p9_tmp_data("unknown")

    client.request_read_json.side_effect = TransportError("temporary failure")
    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        failed = service.p9_tmp_data("qos")
    assert failed["succeeded_count"] == 0
    assert failed["failed_count"] == 1
    assert failed["results"][0]["status"] == "error"
    assert failed["results"][0]["error_type"] == "TransportError"
    assert "temporary failure" not in json.dumps(failed)

    client.reset_mock()
    client.request_read_json.side_effect = None
    client.request_read_json.return_value = {"error_code": 0, "result": {"owner_list": []}}
    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        account = service.p9_tmp_data("account")
    assert account["available_count"] == 2
    assert account["selected_count"] == 1
    assert account["skipped_parameterized_count"] == 1
    assert account["skipped_parameterized_operations"] == [
        {
            "code": 0x402D,
            "hex_code": "0x402D",
            "name": "TMP_APPV2_OP_OWNER_GET",
            "confirmed_parameter_sets": [["owner_id"]],
            "read_operation": "tmp_read",
        }
    ]
    client.request_read_json.assert_called_once_with(0x4029)


def test_mcp_p9_tmp_data_can_resolve_all_confirmed_parameterized_reads() -> None:
    service = DecoService(
        ServerConfig(
            "192.0.2.1",
            "admin",
            "secret",
            60.0,
            allow_sensitive_reads=True,
            tp_link_id="owner@example.com",
            tmp_host_key_sha256="SHA256:test",
            allow_tmp_reads=True,
        )
    )
    client = mock.Mock()

    def request(opcode: int, params: object = None) -> dict[str, object]:
        if opcode == 0x4012 and params is None:
            return {
                "error_code": 0,
                "result": {"client_list": [{"owner_id": "private-owner-id"}]},
            }
        return {"error_code": 0, "result": {}}

    client.request_read_json.side_effect = request
    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        result = service.p9_tmp_data(include_parameterized=True)

    assert result["available_count"] == 55
    assert result["selected_count"] == 55
    assert result["include_parameterized"] is True
    assert result["parameterized_selected_count"] == 7
    assert result["parameterized_resolved_count"] == 7
    assert result["skipped_parameterized_count"] == 0
    assert result["dependency_request_count"] == 0
    assert result["request_count"] == 55
    assert result["succeeded_count"] == 55
    assert result["failed_count"] == 0
    assert result["skipped_count"] == 0
    assert result["all_available_operations_attempted"] is True
    assert result["request_parameter_values_included"] is False
    assert result["mutation_invoked"] is False
    calls = client.request_read_json.call_args_list
    for opcode in (0x402D, 0x402F, 0x4031):
        assert mock.call(opcode, {"owner_id": "private-owner-id"}) in calls
    assert mock.call(0x403A, {"version": 1029}) in calls
    assert mock.call(0x4049, {"iot_client_list": []}) in calls
    assert mock.call(0x4201, {"version": 1}) in calls
    assert mock.call(0x4202, {"version": 1029}) in calls
    parameterized_results = [item for item in result["results"] if "parameter_source" in item]
    assert len(parameterized_results) == 7
    assert all("params" not in item for item in parameterized_results)


def test_mcp_p9_tmp_data_reports_missing_parameter_source_without_guessing() -> None:
    service = DecoService(
        ServerConfig(
            "192.0.2.1",
            "admin",
            "secret",
            60.0,
            allow_sensitive_reads=True,
            tp_link_id="owner@example.com",
            tmp_host_key_sha256="SHA256:test",
            allow_tmp_reads=True,
        )
    )
    client = mock.Mock()
    client.request_read_json.return_value = {"error_code": 0, "result": {}}
    with mock.patch.object(service, "_get_tmp_client", return_value=client):
        result = service.p9_tmp_data("account", include_parameterized=True)

    assert result["available_count"] == 2
    assert result["selected_count"] == 2
    assert result["parameterized_selected_count"] == 1
    assert result["parameterized_resolved_count"] == 0
    assert result["dependency_request_count"] == 2
    assert result["request_count"] == 1
    assert result["skipped_count"] == 1
    assert result["all_available_operations_attempted"] is False
    skipped = next(item for item in result["results"] if item["status"] == "skipped")
    assert skipped["hex_code"] == "0x402D"
    assert skipped["skip_reason"] == "confirmed owner identifier unavailable"
    assert mock.call(0x402D, mock.ANY) not in client.request_read_json.call_args_list


def test_mcp_tmp_configuration_and_shared_close_are_fail_closed() -> None:
    service = DecoService(ServerConfig("192.0.2.1", "admin", "secret", 60.0))
    with pytest.raises(ValueError, match="DECO_TP_LINK_ID"):
        service._tmp_ssh_config()

    service = DecoService(
        ServerConfig(
            "192.0.2.1",
            "admin",
            "secret",
            60.0,
            tp_link_id="owner@example.com",
        )
    )
    with pytest.raises(ValueError, match="DECO_TMP_HOST_KEY_SHA256"):
        service._tmp_ssh_config()

    http_client = mock.Mock()
    tmp_client = mock.Mock()
    service._client = http_client
    service._tmp_client = tmp_client
    http_client.logout.side_effect = RuntimeError("logout failed")
    with pytest.raises(RuntimeError, match="logout failed"):
        service.close()
    tmp_client.close.assert_called_once()


def test_mcp_service_probes_transport_ports_without_authentication() -> None:
    service = DecoService(_config())
    connection = mock.MagicMock()

    with (
        mock.patch.object(service, "_get_client") as get_client,
        mock.patch(
            "tplink_deco_api.service.deco_service.socket.create_connection",
            side_effect=[ConnectionRefusedError, connection, TimeoutError],
        ) as create_connection,
    ):
        result = service.probe_p9_transport_services(timeout=1.0)

    get_client.assert_not_called()
    assert result["authentication_attempted"] is False
    assert result["payload_sent"] is False
    assert [item["status"] for item in result["hosts"][0]["services"]] == [
        "refused",
        "open",
        "timeout",
    ]
    assert create_connection.call_args_list == [
        mock.call(("192.0.2.1", 22), timeout=1.0),
        mock.call(("192.0.2.1", 20001), timeout=1.0),
        mock.call(("192.0.2.1", 20002), timeout=1.0),
    ]
    connection.__enter__.assert_called_once_with()
    connection.__exit__.assert_called_once()

    with pytest.raises(ValueError, match="between 0 and 10"):
        service.probe_p9_transport_services(timeout=0)


def test_mcp_service_read_authorization_and_call() -> None:
    service = DecoService(_config())
    response = ApiResponse.from_api({"error_code": 0, "result": {"cpu_usage": 0.5}})
    client = mock.Mock()
    client.call.return_value = response

    with mock.patch.object(service, "_get_client", return_value=client):
        actual = service.read_endpoint("admin.network.performance.read")

    assert actual is response
    client.call.assert_called_once()

    with pytest.raises(PermissionError, match="classified as mutation"):
        service.read_endpoint("admin.network.wan_mode.write")
    with pytest.raises(PermissionError, match="sensitive reads require"):
        service.read_endpoint("admin.wireless.wlan.read")
    bootstrap = mock.Mock()
    bootstrap.call_bootstrap.return_value = response
    with (
        mock.patch("tplink_deco_api.service.deco_service.DecoClient", return_value=bootstrap),
        mock.patch.object(service, "_get_client") as get_client,
    ):
        bootstrap_response = service.read_endpoint("login.auth.read")
    assert bootstrap_response is response
    bootstrap.call_bootstrap.assert_called_once_with(get_endpoint("login.auth.read"), None)
    get_client.assert_not_called()
    with pytest.raises(PermissionError, match="sensitive reads require"):
        service.read_endpoint("login.default_info.read")
    sensitive_service = DecoService(_config(allow_sensitive_reads=True))
    domain_response = ApiResponse.from_api({"error_code": 0, "result": None})
    domain_client = mock.Mock()
    domain_client.call.return_value = domain_response
    with mock.patch.object(sensitive_service, "_get_client", return_value=domain_client):
        actual_domain = sensitive_service.read_endpoint("domain_login.dlogin.read")
    assert actual_domain is domain_response
    domain_client.call.assert_called_once_with(get_endpoint("domain_login.dlogin.read"), None)


def test_mcp_p9_http_data_batches_supported_reads_by_controller() -> None:
    service = DecoService(_config())
    response = ApiResponse.from_api({"error_code": 0, "result": {"value": 1}})
    with mock.patch.object(service, "read_endpoint", return_value=response) as read_endpoint:
        result = service.p9_http_data("admin/network")

    assert result["controller"] == "admin/network"
    assert result["selected_count"] == 7
    assert result["skipped_sensitive_count"] == 1
    assert result["succeeded_count"] == 7
    assert result["firmware_error_count"] == 0
    assert result["failed_count"] == 0
    assert result["values_included"] is True
    assert result["mutation_invoked"] is False
    assert len(result["results"]) == 7
    assert all(item["controller"] == "admin/network" for item in result["results"])
    assert all(item["response"] == response.payload for item in result["results"])
    assert read_endpoint.call_count == 7

    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        service.p9_http_data("admin/network", include_sensitive=True)
    with pytest.raises(ValueError, match="unknown controller"):
        service.p9_http_data("unknown")

    firmware_error = ApiResponse.from_api({"error_code": 1, "result": None})
    with mock.patch.object(
        service,
        "read_endpoint",
        side_effect=[firmware_error, TransportError("private error"), *([response] * 5)],
    ):
        partial = service.p9_http_data("admin/network")
    assert partial["succeeded_count"] == 5
    assert partial["firmware_error_count"] == 1
    assert partial["failed_count"] == 1
    assert [item["status"] for item in partial["results"][:2]] == [
        "firmware_error",
        "error",
    ]
    assert partial["results"][1]["error_type"] == "TransportError"
    assert "private error" not in json.dumps(partial)

    with mock.patch.object(service, "read_endpoint", return_value=response) as read_endpoint:
        bootstrap = service.p9_http_data("login")
    assert bootstrap["transport"] == "http"
    assert bootstrap["selected_count"] == 3
    assert bootstrap["skipped_sensitive_count"] == 0
    assert bootstrap["succeeded_count"] == 3
    assert read_endpoint.call_count == 3


def test_mcp_p9_http_data_includes_sensitive_values_only_after_opt_in() -> None:
    service = DecoService(_config(allow_sensitive_reads=True))
    response = ApiResponse.from_api({"error_code": 0, "result": {"credential": "private-value"}})
    with mock.patch.object(service, "read_endpoint", return_value=response) as read_endpoint:
        result = service.p9_http_data("admin/administration", include_sensitive=True)

    assert result["selected_count"] == 9
    assert result["skipped_sensitive_count"] == 0
    assert result["succeeded_count"] == 9
    assert result["results"][0]["response"] == response.payload
    assert read_endpoint.call_count == 9

    domain_response = ApiResponse.from_api({"error_code": 0, "result": None})
    with mock.patch.object(
        service,
        "read_endpoint",
        return_value=domain_response,
    ) as read_domain:
        domain = service.p9_http_data("domain_login", include_sensitive=True)
    assert domain["selected_count"] == 1
    assert domain["succeeded_count"] == 1
    assert domain["results"][0]["name"] == "domain_login.dlogin.read"
    read_domain.assert_called_once_with("domain_login.dlogin.read", None)


def test_mcp_reports_no_remaining_safe_untested_p9_http_reads() -> None:
    service = DecoService(_config())
    with mock.patch.object(service, "read_endpoint") as read_endpoint:
        result = service.discover_p9_untested_http_reads()

    assert result["selected_count"] == 0
    assert result["selected_operations"] == []
    assert result["supported_count"] == 0
    assert result["rejected_count"] == 0
    assert result["failed_count"] == 0
    assert result["sensitive_operations_included"] is False
    assert result["binary_operations_included"] is False
    assert result["mutation_invoked"] is False
    assert result["results"] == []
    read_endpoint.assert_not_called()


def test_mcp_service_allows_opted_in_sensitive_read() -> None:
    service = DecoService(_config(allow_sensitive_reads=True))
    response = ApiResponse.from_api({"error_code": 0, "result": {"ssid": "encoded"}})
    client = mock.Mock()
    client.call.return_value = response

    with mock.patch.object(service, "_get_client", return_value=client):
        actual = service.read_endpoint("admin.wireless.wlan.read")

    assert actual is response


def test_mcp_service_network_overview_uses_confirmed_high_level_reads() -> None:
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).network_overview()

    service = DecoService(_config(allow_sensitive_reads=True))
    client = mock.Mock()
    client.get_device_mode.return_value = DeviceMode("router", "Router", "GB")
    ip_status = IpStatus("connected", "connected", "dynamic", "dynamic", 0)
    client.get_internet_status.return_value = InternetStatus(ip_status, ip_status, "up")
    wan_ip = IpInfo(
        "198.51.100.10",
        "255.255.255.0",
        "AA:BB:CC:DD:EE:FF",
        "198.51.100.1",
        "1.1.1.1",
        "8.8.8.8",
    )
    lan_ip = IpInfo(
        "192.168.68.1",
        "255.255.255.0",
        "AA:BB:CC:DD:EE:00",
        "",
        "",
        "",
    )
    client.get_wan_info.return_value = WanInfo(
        WanDetails(wan_ip, "dynamic", True),
        LanDetails(lan_ip),
    )
    client.get_performance.return_value = Performance(0.25, 0.5)
    client.get_time_settings.return_value = TimeSettings(
        "12:00:00",
        "2026-07-10",
        "GMT0BST",
        "Europe/London",
        "Europe",
        "enabled",
    )
    client.get_address_reservations.return_value = AddressReservationTable(
        (AddressReservation("AA:BB:CC:DD:EE:01", "192.168.68.10"),),
        64,
    )
    client.get_lan_ipv4.return_value = {"ip": "192.168.68.1"}
    client.get_lan_ip.return_value = {"mask": "255.255.255.0"}
    client.call.side_effect = [
        ApiResponse.from_api({"error_code": 0, "result": {"mode": "router"}}),
        ApiResponse.from_api({"error_code": 0, "result": {"enabled": False}}),
        ApiResponse.from_api({"error_code": 0, "result": {"mode": "default"}}),
    ]

    with mock.patch.object(service, "_get_client", return_value=client):
        overview = service.network_overview()

    assert overview["device_mode"] == {
        "workmode": "router",
        "sysmode": "Router",
        "region": "GB",
    }
    assert overview["internet"]["link_status"] == "up"
    assert overview["wan"]["ip_info"]["ip"] == "198.51.100.10"
    assert overview["configuration"] == {
        "wan_mode": {"mode": "router"},
        "lan_ipv4": {"ip": "192.168.68.1"},
        "lan_ip": {"mask": "255.255.255.0"},
        "vlan": {"enabled": False},
        "mac_clone": {"mode": "default"},
    }
    assert overview["address_reservations"]["entries"] == [
        {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.68.10"}
    ]


def test_mcp_configuration_resource_is_sanitized_and_separates_related_data() -> None:
    service = DecoService(_config())
    _prime_p9_profile(service)
    client = mock.Mock()
    client.get_device_mode.return_value = DeviceMode("router", "Router", "GB")
    ip_status = IpStatus("connected", "connected", "dynamic", "dynamic", 0)
    client.get_internet_status.return_value = InternetStatus(ip_status, ip_status, "up")
    wan_ip = IpInfo(
        "198.51.100.10",
        "255.255.255.0",
        "AA:BB:CC:DD:EE:FF",
        "198.51.100.1",
        "1.1.1.1",
        "8.8.8.8",
    )
    lan_ip = IpInfo("192.168.68.1", "255.255.255.0", "AA:BB:CC:DD:EE:00", "", "", "")
    client.get_wan_info.return_value = WanInfo(
        WanDetails(wan_ip, "dynamic", True),
        LanDetails(lan_ip),
    )
    client.get_dhcp_info.return_value = {"enable": True, "pool_start": "192.168.68.100"}
    client.get_lan_ipv4.return_value = {"ip": "192.168.68.1"}
    client.get_lan_ip.return_value = {"mask": "255.255.255.0"}
    client.call.side_effect = [
        ApiResponse.from_api({"error_code": 0, "result": {"mode": "router"}}),
        ApiResponse.from_api({"error_code": 0, "result": {"enabled": False}}),
        ApiResponse.from_api({"error_code": 0, "result": {"mode": "default"}}),
    ]
    client.get_time_settings.return_value = TimeSettings(
        "12:00:00",
        "2026-07-10",
        "GMT0BST",
        "Europe/London",
        "Europe",
        "enabled",
    )
    client.get_wireless_operation_mode.return_value = {"mode": "host"}
    client.get_bridge_status.return_value = {"enable": False}
    client.get_fast_roaming.return_value = {"enable": True}
    client.get_beamforming.return_value = {"enable": True}

    with mock.patch.object(service, "_get_client", return_value=client):
        configuration = service.configuration_resource()

    assert_response_contract(ConfigurationResponse, configuration)

    assert configuration["controller"]["model"] == "P9"
    assert configuration["operating_mode"]["workmode"] == "router"
    assert configuration["wireless_features"]["beamforming"] == {"enabled": True}
    assert configuration["network_features"] == {
        "wan_mode": {"mode": "router"},
        "lan_ipv4": {"ip": "192.168.68.1"},
        "lan_ip": {"mask": "255.255.255.0"},
        "vlan": {"enabled": False},
        "mac_clone": {"mode": "default"},
    }
    assert configuration["nickname_status"] == "gated"
    assert "client_devices" in configuration["related_sections"]
    assert "logs" in configuration["related_sections"]
    assert configuration["passwords_included"] is False
    assert configuration["client_identities_included"] is False
    assert configuration["address_reservations_included"] is False
    assert configuration["unavailable_sections"] == []


def test_mcp_device_resources_normalize_and_filter_every_known_device_source() -> None:
    service = DecoService(_config(allow_sensitive_reads=True))
    client = mock.Mock()
    client.call.return_value = ApiResponse.from_api(
        {
            "error_code": 0,
            "result": {
                "client_list": [
                    {"mac": "AA:BB:CC:DD:EE:03", "name": "QmxvY2tlZA==", "client_type": "iot"}
                ]
            },
        }
    )
    client.get_address_reservations.return_value = AddressReservationTable(
        (AddressReservation("AA:BB:CC:DD:EE:04", "192.0.2.40"),),
        64,
    )
    capability = {
        "capability": "clients",
        "schema_version": 1,
        "data": [
            {
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "192.0.2.10",
                "name": "Active",
                "online": True,
                "enable_priority": True,
                "up_speed": 10,
                "down_speed": 20,
            },
            {
                "mac": "AA:BB:CC:DD:EE:02",
                "ip": "192.0.2.20",
                "name": "Inactive",
                "online": False,
            },
        ],
        "provenance": {},
        "mutation_invoked": False,
    }
    assigned_client = ClientDevice.from_api(
        {
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.0.2.10",
            "name": "QWN0aXZl",
            "online": True,
        }
    )
    clients_by_node = (NodeClientList("AA:BB:CC:DD:EE:FF", (assigned_client,)),)

    with (
        mock.patch.object(service, "read_capability", return_value=capability),
        mock.patch.object(service, "get_clients_by_node", return_value=clients_by_node),
        mock.patch.object(service, "_get_client", return_value=client),
    ):
        devices = service.client_devices_resource("all")
        active = service.client_devices_resource("active")
        inactive = service.client_devices_resource("inactive")
        blocked = service.client_devices_resource("blocked")

    records = {record["mac"]: record for record in devices["devices"]}
    assert_response_contract(ClientsResponse, devices)
    assert devices["device_count"] == devices["all_device_count"] == 4
    assert records["AA:BB:CC:DD:EE:01"]["status"] == "active"
    assert records["AA:BB:CC:DD:EE:01"]["connected_node"] == "AA:BB:CC:DD:EE:FF"
    assert records["AA:BB:CC:DD:EE:01"]["prioritized"] is True
    assert records["AA:BB:CC:DD:EE:03"]["blocked"] is True
    assert records["AA:BB:CC:DD:EE:03"]["access_status"] == "blocked"
    assert records["AA:BB:CC:DD:EE:04"]["reserved"] is True
    assert records["AA:BB:CC:DD:EE:04"]["reservation_ip"] == "192.0.2.40"
    assert [record["mac"] for record in active["devices"]] == ["AA:BB:CC:DD:EE:01"]
    assert {record["mac"] for record in inactive["devices"]} == {
        "AA:BB:CC:DD:EE:02",
        "AA:BB:CC:DD:EE:03",
        "AA:BB:CC:DD:EE:04",
    }
    assert [record["mac"] for record in blocked["devices"]] == ["AA:BB:CC:DD:EE:03"]
    assert devices["unavailable_sections"] == []

    with pytest.raises(ValueError, match="unknown view"):
        service.client_devices_resource("unknown")


def test_mcp_traffic_resource_normalizes_device_and_aggregate_speeds() -> None:
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).traffic_resource()

    service = DecoService(_config(allow_sensitive_reads=True))
    client = mock.Mock()
    client.get_traffic_statistics.return_value = {
        "client_list_speed": [
            {"mac": "AA:BB:CC:DD:EE:01", "up_speed": 10, "down_speed": 20},
            {"mac": "AA:BB:CC:DD:EE:02", "up_speed": 30, "down_speed": 40},
        ]
    }

    with mock.patch.object(service, "_get_client", return_value=client):
        traffic = service.traffic_resource()

    assert_response_contract(TrafficResponse, traffic)

    assert traffic["device_count"] == 2
    assert traffic["device_speeds"][0] == {
        "mac": "AA:BB:CC:DD:EE:01",
        "up_speed": 10,
        "down_speed": 20,
    }
    assert traffic["aggregate_speed"] == {"up_speed": 40, "down_speed": 60}
    assert traffic["status"] == "available"
    assert traffic["unavailable_sections"] == []


def test_mcp_logs_resource_excludes_log_contents() -> None:
    service = DecoService(_config())
    client = mock.Mock()
    client.get_log_types.return_value = [LogType("system", 1), LogType("network", 2)]

    with mock.patch.object(service, "_get_client", return_value=client):
        logs = service.logs_resource()

    assert_response_contract(LogTypesResponse, logs)

    assert logs["status"] == "available"
    assert logs["category_count"] == 2
    assert logs["categories"] == [
        {"name": "system", "value": 1},
        {"name": "network", "value": 2},
    ]
    assert logs["log_contents_included"] is False
    assert logs["unavailable_sections"] == []


def test_mcp_system_log_pages_require_both_secret_read_gates() -> None:
    disabled = DecoService(_config())
    sensitive_only = DecoService(_config(allow_sensitive_reads=True))

    with (
        mock.patch.object(disabled, "_get_client") as disabled_client,
        pytest.raises(PermissionError, match="DECO_ALLOW_SENSITIVE_READS"),
    ):
        disabled.system_log_page_resource(0)
    with (
        mock.patch.object(sensitive_only, "_get_client") as sensitive_client,
        pytest.raises(PermissionError, match="DECO_ALLOW_BULK_SECRET_READS"),
    ):
        sensitive_only.system_log_page_resource(0)

    disabled_client.assert_not_called()
    sensitive_client.assert_not_called()


def test_mcp_system_log_page_returns_typed_http_data() -> None:
    service = DecoService(_config(allow_sensitive_reads=True, allow_bulk_secret_reads=True))
    client = mock.Mock()
    client.get_system_log.return_value = SystemLogPage(
        current_index=2,
        total_pages=4,
        entries=(SystemLogEntry(content="message", level="INFO"),),
    )

    with mock.patch.object(service, "_get_client", return_value=client):
        page = service.system_log_page_resource(2, 50)

    assert_response_contract(SystemLogPageResponse, page)
    assert page == {
        "schema_version": 1,
        "current_index": 2,
        "total_pages": 4,
        "page_size": 50,
        "entries": [{"content": "message", "time": "", "level": "INFO", "type": ""}],
        "entry_count": 1,
        "log_contents_included": True,
        "source_interface": "http_luci",
        "router_contacted": True,
        "mutation_invoked": False,
    }
    client.get_system_log.assert_called_once_with(index=2, limit=50)


@pytest.mark.parametrize(("index", "limit"), ((-1, 100), (0, 0), (0, 101)))
def test_mcp_system_log_page_validates_before_router_contact(
    index: int,
    limit: int,
) -> None:
    service = DecoService(_config(allow_sensitive_reads=True, allow_bulk_secret_reads=True))

    with (
        mock.patch.object(service, "_get_client") as get_client,
        pytest.raises(ValueError, match="Failed to read system log"),
    ):
        service.system_log_page_resource(index, limit)

    get_client.assert_not_called()


@pytest.mark.asyncio
async def test_mcp_system_log_resource_template_reads_one_page() -> None:
    service = mock.create_autospec(DecoService, instance=True)
    service.system_log_page_resource.return_value = {
        "schema_version": 1,
        "current_index": 2,
        "total_pages": 4,
        "page_size": 100,
        "entries": [],
        "entry_count": 0,
        "log_contents_included": True,
        "source_interface": "http_luci",
        "router_contacted": True,
        "mutation_invoked": False,
    }
    server = create_server(_config(), service)

    result = await server.read_resource("deco://logs/2")

    assert '"current_index": 2' in str(result)
    service.system_log_page_resource.assert_called_once_with(2)


def test_mcp_configuration_resource_includes_gated_nickname() -> None:
    service = DecoService(_config(allow_sensitive_reads=True))
    _prime_p9_profile(service)
    client = mock.Mock()
    unavailable = TransportError("not available")
    client.get_device_mode.side_effect = unavailable
    client.get_internet_status.side_effect = unavailable
    client.get_wan_info.side_effect = unavailable
    client.get_dhcp_info.side_effect = unavailable
    client.get_time_settings.side_effect = unavailable
    client.get_wireless_operation_mode.side_effect = unavailable
    client.call.side_effect = [
        unavailable,
        ApiResponse.from_api({"error_code": 0, "result": {"nickname": "Mesh"}}),
    ]

    with mock.patch.object(service, "_get_client", return_value=client):
        configuration = service.configuration_resource()

    assert configuration["nickname"] == {"nickname": "Mesh"}
    assert configuration["nickname_status"] == "available"


def test_mcp_network_status_resource_summarizes_health_without_client_identities() -> None:
    service = DecoService(_config())
    controller = Device.from_api(
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "device_ip": "192.0.2.1",
            "device_model": "P9",
            "role": "master",
            "hardware_ver": "2.0",
            "software_ver": "1.3.0 Build 20250804 Rel. 58832",
            "inet_status": "online",
            "group_status": "connected",
            "connection_type": ["wired"],
        }
    )
    satellite = Device.from_api(
        {
            "mac": "AA:BB:CC:DD:EE:01",
            "device_ip": "192.0.2.2",
            "device_model": "P9",
            "role": "slave",
            "hardware_ver": "2.0",
            "software_ver": "1.3.0 Build 20250804 Rel. 58832",
            "inet_status": "offline",
            "group_status": "disconnected",
            "connection_type": ["band5", "plc"],
            "signal_level": {"band5": "1"},
        }
    )
    disconnected = IpStatus("disconnected", "disconnected", "dynamic", "dynamic", 1)
    client = mock.Mock()
    client.get_device_list.return_value = [controller, satellite]
    client.get_internet_status.return_value = InternetStatus(
        disconnected,
        disconnected,
        "down",
    )
    client.get_performance.return_value = Performance(0.95, 0.5)
    client.get_speed_test.return_value = SpeedTest(100, 20, "idle", True, 123)
    client.call.return_value = ApiResponse.from_api(
        {"error_code": 0, "result": {"update_available": False}}
    )

    with mock.patch.object(service, "_get_client", return_value=client):
        status = service.network_status_resource()

    assert_response_contract(NetworkStatusResponse, status)

    assert status["status"] == "degraded"
    assert status["controller"] == {
        "model": "P9",
        "role": "master",
        "hardware_version": "2.0",
        "software_version": "1.3.0 Build 20250804 Rel. 58832",
        "internet_status": "online",
        "group_status": "connected",
    }
    assert status["mesh"] == {
        "total_nodes": 2,
        "online_nodes": 1,
        "offline_nodes": 1,
        "controller_online": True,
        "mixed_model_mesh": False,
        "backhaul_type_counts": {"band5": 1, "plc": 1, "wired": 1},
        "weak_signal_nodes": 1,
    }
    assert status["client_count"] is None
    assert status["client_count_status"] == "gated"
    assert status["client_identities_included"] is False
    assert status["passwords_included"] is False
    assert status["speed_test"]["down_speed"] == 100
    assert status["unavailable_sections"] == []
    assert {warning["code"] for warning in status["warnings"]} == {
        "mesh_nodes_offline",
        "weak_wireless_backhaul",
        "internet_offline",
        "high_cpu_usage",
    }
    client.get_client_list.assert_not_called()


def test_mcp_network_status_resource_returns_partial_results_and_gated_client_count() -> None:
    service = DecoService(_config(allow_sensitive_reads=True))
    controller = Device.from_api(
        {
            "device_model": "P9",
            "role": "master",
            "hardware_ver": "2.0",
            "software_ver": "1.3.0 Build 20250804 Rel. 58832",
            "inet_status": "online",
            "group_status": "connected",
        }
    )
    connected = IpStatus("connected", "connected", "dynamic", "dynamic", 0)
    client = mock.Mock()
    client.get_device_list.return_value = [controller]
    client.get_internet_status.return_value = InternetStatus(connected, connected, "up")
    client.get_performance.side_effect = TransportError("temporary failure")
    client.get_speed_test.return_value = SpeedTest(100, 20, "idle", True, 123)
    client.call.return_value = ApiResponse.from_api(
        {"error_code": 0, "result": {"status": "idle", "download_progress": None}}
    )
    client.get_client_list.return_value = [mock.Mock(), mock.Mock()]

    with mock.patch.object(service, "_get_client", return_value=client):
        status = service.network_status_resource()

    assert status["status"] == "degraded"
    assert status["internet"]["link_status"] == "up"
    assert status["performance"] is None
    assert status["firmware"] == {"status": "idle", "download_progress": None}
    assert status["client_count"] == 2
    assert status["client_count_status"] == "available"
    assert status["unavailable_sections"] == [
        {
            "section": "performance",
            "status": "unavailable",
            "error_type": "TransportError",
        }
    ]
    assert status["warnings"] == [
        {
            "code": "partial_data",
            "message": "1 live status section(s) could not be read",
        }
    ]


def test_mcp_service_mesh_overview_preserves_per_node_associations() -> None:
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).mesh_overview()

    service = DecoService(_config(allow_sensitive_reads=True))
    device = Device.from_api(
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "device_ip": "192.168.68.1",
            "device_model": "P9",
            "role": "master",
            "support_plc": True,
            "connection_type": ["wired"],
        }
    )
    client = mock.Mock()
    client.get_device_list.return_value = [device]
    client.get_clients_by_node.return_value = (NodeClientList(device.mac, ()),)

    with mock.patch.object(service, "_get_client", return_value=client):
        overview = service.mesh_overview()

    assert overview["node_count"] == 1
    assert overview["nodes"][0]["supports_plc"] is True
    assert overview["clients_by_node"][0]["node_mac"] == device.mac
    assert overview["client_assignments"] == 0


def test_mcp_service_wlan_state_omits_passwords_by_default() -> None:
    band = WlanBand(
        WlanHost("Home", "host-secret", 1, True, "11ax", "20MHz", False),
        WlanGuest("Guest", "guest-secret", True, 10, True),
        WlanBackhaul(6),
    )
    config = WlanConfig(
        band,
        band,
        band,
        IotHost("IoT", "iot-secret", "wpa2", True, True, False),
        MloHost("MLO", "mlo-secret", False, ("2g", "5g"), False),
    )
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).wlan_state()

    service = DecoService(_config(allow_sensitive_reads=True))
    client = mock.Mock()
    client.get_wlan_config.return_value = config
    client.get_wireless_operation_mode.return_value = {"mode": "host"}
    client.get_bridge_status.return_value = {"enabled": False}
    client.get_fast_roaming.return_value = {"enabled": True}
    client.get_beamforming.return_value = {"enabled": True}
    with mock.patch.object(service, "_get_client", return_value=client):
        redacted = service.wlan_state()
        complete = service.wlan_state(include_passwords=True)

    assert_response_contract(WlanResponse, redacted)
    assert_response_contract(WlanResponse, complete)

    assert "secret" not in json.dumps(redacted)
    assert redacted["passwords_included"] is False
    assert complete["bands"]["2.4ghz"]["host"]["password"] == "host-secret"
    assert complete["iot"]["password"] == "iot-secret"
    assert redacted["features"] == {
        "operation_mode": {"mode": "host"},
        "bridge": {"enabled": False},
        "fast_roaming": {"enabled": True},
        "beamforming": {"enabled": True},
    }


def test_mcp_service_cloud_state_requires_sensitive_gate() -> None:
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).cloud_state()

    service = DecoService(_config(allow_sensitive_reads=True))
    responses = [
        ApiResponse.from_api({"error_code": 0, "result": {"enabled": True}}),
        ApiResponse.from_api({"error_code": 0, "result": {"permissions": ["owner"]}}),
    ]
    with mock.patch.object(service, "read_endpoint", side_effect=responses) as read_endpoint:
        state = service.cloud_state()

    assert_response_contract(CloudResponse, state)

    assert state == {
        "ddns": {"enabled": True},
        "manager": {"permissions": ["owner"]},
    }
    assert [call.args[0] for call in read_endpoint.call_args_list] == [
        "admin.cloud.ddns.get",
        "admin.cloud.manager.get",
    ]


def test_mcp_service_client_overview_covers_confirmed_client_data() -> None:
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).client_overview()

    service = DecoService(_config(allow_sensitive_reads=True))
    client_device = ClientDevice.from_api(
        {
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.168.68.10",
            "name": "VGVzdA==",
            "online": True,
        }
    )
    reservation = AddressReservation(client_device.mac, client_device.ip)
    client = mock.Mock()
    client.get_client_list.return_value = [client_device]
    client.get_traffic_statistics.return_value = {"traffic_stat_list": []}
    client.call.return_value = ApiResponse.from_api({"error_code": 0, "result": {"black_list": []}})
    client.get_address_reservations.return_value = AddressReservationTable((reservation,), 64)

    with mock.patch.object(service, "_get_client", return_value=client):
        overview = service.client_overview()

    assert overview["client_count"] == 1
    assert overview["clients"][0]["name"] == "Test"
    assert overview["traffic_statistics"] == {"traffic_stat_list": []}
    assert overview["blacklist"] == {"black_list": []}
    assert overview["address_reservations"]["count"] == 1


def test_mcp_service_system_overview_covers_confirmed_system_data() -> None:
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).system_overview()

    service = DecoService(_config(allow_sensitive_reads=True))
    client = mock.Mock()
    client.get_speed_test.return_value = SpeedTest(100, 20, "idle", True, 123)
    client.call.side_effect = [
        ApiResponse.from_api(
            {
                "error_code": 0,
                "result": {"status": "idle", "download_progress": None},
            }
        ),
        ApiResponse.from_api({"error_code": 0, "result": {"nickname": "Mesh"}}),
    ]
    client.get_log_types.return_value = [LogType("system", 1)]

    with mock.patch.object(service, "_get_client", return_value=client):
        overview = service.system_overview()

    assert overview == {
        "speed_test": {
            "down_speed": 100,
            "up_speed": 20,
            "status": "idle",
            "ever_tested": True,
            "last_speed_test_time": 123,
        },
        "firmware_status": {"status": "idle", "download_progress": None},
        "nickname": {"nickname": "Mesh"},
        "log_types": [{"name": "system", "value": 1}],
    }


def test_mcp_service_binary_read_requires_sensitive_opt_in() -> None:
    name = "admin.log_export.save_log.download"
    with pytest.raises(PermissionError, match="sensitive reads require"):
        DecoService(_config()).read_binary_endpoint(name)

    sensitive_only = DecoService(_config(allow_sensitive_reads=True))
    with (
        mock.patch.object(sensitive_only, "_get_client") as get_client,
        pytest.raises(PermissionError, match="DECO_ALLOW_BULK_SECRET_READS"),
    ):
        sensitive_only.read_binary_endpoint(name)
    get_client.assert_not_called()

    service = DecoService(
        _config(
            allow_sensitive_reads=True,
            allow_bulk_secret_reads=True,
        )
    )
    response = BinaryResponse(name, b"log\n", "text/plain")
    client = mock.Mock()
    client.call_binary.return_value = response

    with mock.patch.object(service, "_get_client", return_value=client):
        actual = service.read_binary_endpoint(name)

    assert actual is response
    client.call_binary.assert_called_once_with(get_endpoint(name))

    with (
        mock.patch.object(service, "_get_client") as get_client,
        pytest.raises(PermissionError, match="DECO_ALLOW_BINARY_CONTENT"),
    ):
        service.read_binary_endpoint(name, include_content=True)
    get_client.assert_not_called()

    content_service = DecoService(
        _config(
            allow_sensitive_reads=True,
            allow_bulk_secret_reads=True,
            allow_binary_content=True,
        )
    )
    with mock.patch.object(content_service, "_get_client", return_value=client):
        assert content_service.read_binary_endpoint(name, include_content=True) is response

    multipart_name = "admin.firmware.config_multipart.backup"
    multipart_response = BinaryResponse(
        multipart_name,
        b"encrypted backup",
        "application/octet-stream",
    )
    client.call_binary.reset_mock(return_value=True)
    client.call_binary.return_value = multipart_response
    with mock.patch.object(service, "_get_client", return_value=client):
        actual_multipart = service.read_binary_endpoint(multipart_name)
    assert actual_multipart is multipart_response
    client.call_binary.assert_called_once_with(get_endpoint(multipart_name))

    with pytest.raises(PermissionError, match="not a binary read"):
        service.read_binary_endpoint("admin.network.performance.read")


def test_mcp_service_binary_discovery_is_digest_only_and_independently_gated() -> None:
    disabled = DecoService(_config())
    with (
        mock.patch.object(disabled, "_get_client") as get_client,
        pytest.raises(PermissionError, match="DECO_ALLOW_SENSITIVE_READS"),
    ):
        disabled.discover_p9_binary_reads()
    get_client.assert_not_called()

    sensitive_only = DecoService(_config(allow_sensitive_reads=True))
    with (
        mock.patch.object(sensitive_only, "_get_client") as get_client,
        pytest.raises(PermissionError, match="DECO_ALLOW_BULK_SECRET_READS"),
    ):
        sensitive_only.discover_p9_binary_reads()
    get_client.assert_not_called()

    service = DecoService(
        _config(
            allow_sensitive_reads=True,
            allow_bulk_secret_reads=True,
        )
    )
    responses = [
        BinaryResponse("admin.firmware.config.backup", b"backup"),
        BinaryResponse("admin.firmware.config_multipart.backup", b"multipart"),
        TransportError("Failed to POST endpoint: timeout"),
    ]
    with mock.patch.object(service, "read_binary_endpoint", side_effect=responses) as read:
        result = service.discover_p9_binary_reads()

    assert read.call_args_list == [
        mock.call("admin.firmware.config.backup"),
        mock.call("admin.firmware.config_multipart.backup"),
        mock.call("admin.log_export.save_log.download"),
    ]
    assert result["selected_count"] == 3
    assert result["received_count"] == 2
    assert result["failed_count"] == 1
    assert result["digest_metadata_only"] is True
    assert result["binary_content_returned"] is False
    assert result["binary_content_persisted"] is False
    assert result["mutation_invoked"] is False
    serialized = json.dumps(result)
    assert "content_base64" not in serialized
    assert "YmFja3Vw" not in serialized
    assert "bXVsdGlwYXJ0" not in serialized
    assert result["results"][2] == {
        "name": "admin.log_export.save_log.download",
        "status": "error",
        "error_type": "TransportError",
        "binary_content_returned": False,
    }


@pytest.mark.parametrize(
    "error",
    [
        TransportError("Failed to POST endpoint: HTTP 403", status_code=403),
        ApiError(-1, "missing encrypted response data"),
    ],
)
def test_mcp_service_relogs_once_for_expired_read_session(
    error: ApiError | TransportError,
) -> None:
    service = DecoService(_config())
    response = ApiResponse.from_api({"error_code": 0, "result": {"ok": True}})
    client = mock.Mock()
    client.call.side_effect = [error, response]

    with mock.patch.object(service, "_get_client", return_value=client) as get_client:
        actual = service.read_endpoint("admin.network.performance.read")

    assert actual is response
    client.invalidate_session.assert_called_once()
    assert get_client.call_count == 2


def test_mcp_service_does_not_retry_unrelated_transport_error() -> None:
    service = DecoService(_config())
    client = mock.Mock()
    client.call.side_effect = TransportError(
        "Failed to POST endpoint: HTTP 500",
        status_code=500,
    )

    with (
        mock.patch.object(service, "_get_client", return_value=client),
        pytest.raises(TransportError),
    ):
        service.read_endpoint("admin.network.performance.read")

    client.invalidate_session.assert_not_called()


def test_mcp_service_mutation_gates_and_confirmation() -> None:
    service = DecoService(_config())

    with pytest.raises(PermissionError, match="use the read operation"):
        service.invoke_mutation(
            "admin.network.performance.read",
            None,
            "admin.network.performance.read",
        )
    with pytest.raises(PermissionError, match="confirmation must exactly match"):
        service.invoke_mutation("admin.network.wan_mode.write", None, "wrong")
    with pytest.raises(PermissionError, match="ALLOW_MUTATIONS"):
        service.invoke_mutation(
            "admin.network.wan_mode.write",
            None,
            "admin.network.wan_mode.write",
        )
    with pytest.raises(PermissionError, match="ALLOW_DESTRUCTIVE"):
        service.invoke_mutation(
            "admin.device.factory.write",
            None,
            "admin.device.factory.write",
        )
    with pytest.raises(PermissionError, match="ALLOW_INTERNAL"):
        service.invoke_mutation(
            "admin.sync.sync_firmware.write",
            None,
            "admin.sync.sync_firmware.write",
        )


def test_mcp_service_rejects_unverified_mutation_before_connecting() -> None:
    service = DecoService(_config(allow_mutations=True))
    name = "admin.network.wan_mode.write"
    params = {"mode": "router"}
    plan_confirmation = service.plan_mutation(name, params)["confirmation_sha256"]

    with (
        mock.patch.object(service, "_get_client") as get_client,
        pytest.raises(PermissionError, match="has not been verified on P9"),
    ):
        service.invoke_mutation(name, params, name, str(plan_confirmation))

    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("name", "params"),
    [
        (
            "admin.client.addr_reservation.modify",
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.0.2.10"},
        ),
        ("admin.wireless.beamforming.write", {"enable": True}),
        ("admin.wireless.ieee80211r.write", {"enable": True}),
        (
            "admin.device.timesetting.write",
            {"timezone": "GMT0BST", "continent": "Europe", "tz_region": "London"},
        ),
    ],
)
def test_mcp_service_rejects_noop_only_verified_mutation_for_general_execution(
    name: str,
    params: dict[str, object],
) -> None:
    service = DecoService(_config(allow_mutations=True))
    plan_confirmation = service.plan_mutation(name, params)["confirmation_sha256"]

    with (
        mock.patch.object(service, "_get_client") as get_client,
        pytest.raises(PermissionError, match="limited to noop_only"),
    ):
        service.invoke_mutation(name, params, name, str(plan_confirmation))

    get_client.assert_not_called()


def test_mcp_service_invokes_enabled_verified_mutation_with_matching_plan() -> None:
    service = DecoService(_config(allow_mutations=True))
    response = ApiResponse.from_api({"error_code": 0, "result": {"ok": True}})
    client = mock.Mock()
    client.call.return_value = response
    name = "admin.network.wan_mode.write"
    params = {"mode": "router"}
    plan_confirmation = service.plan_mutation(name, params)["confirmation_sha256"]
    compatibility = OperationCompatibility(
        name=name,
        availability="supported",
        evidence=("full_manifest",),
        mutation_tested=True,
        mutation_test_scope="general",
    )
    profile = mock.Mock()
    profile.get.return_value = compatibility

    with (
        mock.patch.object(service, "_get_client", return_value=client),
        mock.patch(
            "tplink_deco_api.service.deco_service.get_compatibility_profile",
            return_value=profile,
        ),
    ):
        actual = service.invoke_mutation(name, params, name, str(plan_confirmation))

    assert actual is response
    client.call.assert_called_once_with(get_endpoint(name), params)


def test_mcp_service_rejects_mutation_when_plan_parameters_changed() -> None:
    service = DecoService(_config(allow_mutations=True))
    name = "admin.network.wan_mode.write"
    plan_confirmation = service.plan_mutation(name, {"mode": "router"})["confirmation_sha256"]

    with (
        mock.patch.object(service, "_get_client") as get_client,
        pytest.raises(PermissionError, match="reviewed parameters"),
    ):
        service.invoke_mutation(
            name,
            {"mode": "access_point"},
            name,
            str(plan_confirmation),
        )

    get_client.assert_not_called()


def test_mcp_service_validates_before_connecting_and_rejects_special_transport() -> None:
    service = DecoService(_config(allow_mutations=True))

    validation = service.validate_operation("admin.network.wan_mode.write", {})

    assert validation["valid"] is False
    assert validation["missing_params"] == ["mode"]
    assert validation["provided_params"] == []
    assert validation["model_compatibility"]["availability"] == "untested"
    assert validation["model_compatibility"]["confidence"] == "inferred"
    bootstrap = service.validate_operation("login.auth.read", {})
    assert bootstrap["valid"] is True
    assert bootstrap["transport_supported"] is True
    assert bootstrap["effective_authentication"] == "bootstrap"
    assert bootstrap["model_compatibility"]["availability"] == "supported"
    domain_login = service.validate_operation("domain_login.dlogin.read", {})
    assert domain_login["valid"] is True
    assert domain_login["transport_supported"] is True
    assert domain_login["effective_authentication"] == "encrypted"
    assert domain_login["model_compatibility"]["availability"] == "supported"
    assert domain_login["model_compatibility"]["returned_data"] is False
    with (
        mock.patch.object(service, "_get_client") as get_client,
        pytest.raises(ValueError, match="missing required params: mode"),
    ):
        service.invoke_mutation(
            "admin.network.wan_mode.write",
            {},
            "admin.network.wan_mode.write",
        )
    get_client.assert_not_called()

    internal = DecoService(_config(allow_internal=True))
    with pytest.raises(PermissionError, match="transport 'token'"):
        internal.invoke_mutation(
            "admin.sync.sync_firmware.write",
            {},
            "admin.sync.sync_firmware.write",
        )


def test_mcp_service_plans_mutation_without_connecting() -> None:
    service = DecoService(_config())
    name = "admin.client.addr_reservation.add"

    with mock.patch.object(service, "_get_client") as get_client:
        plan = service.plan_mutation(
            name,
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.68.10"},
        )

    get_client.assert_not_called()
    assert plan["name"] == name
    assert plan["gate_enabled"] is False
    assert plan["preflight_read"] == "admin.client.addr_reservation.getlist"
    assert plan["rollback_operation"] == "admin.client.addr_reservation.remove"
    assert plan["ready_for_explicit_test"] is False

    with pytest.raises(PermissionError, match="read-only"):
        service.plan_mutation("admin.network.performance.read", {})


def test_mcp_service_p9_mutation_inventory_is_offline_and_non_executable() -> None:
    service = DecoService(_config())

    with mock.patch.object(service, "_get_client") as get_client:
        inventory = service.p9_mutation_inventory()

    get_client.assert_not_called()
    assert inventory["candidate_count"] == 23
    assert inventory["mutation_tested_count"] == 4
    assert inventory["complete_safety_contract_count"] == 10
    assert inventory["live_preflight_count"] == 10
    assert inventory["execution_eligible_count"] == 0
    assert inventory["verification_candidate_count"] == 0
    assert inventory["verification_tier_counts"] == {
        "destructive_excluded": 3,
        "evidence_blocked": 1,
        "high_risk_deferred": 15,
        "verified_noop": 4,
    }
    assert inventory["verification_queue_operation"] == ("p9_http_mutation_verification_queue")
    assert inventory["scoped_noop_executor_count"] == 2
    assert inventory["scoped_noop_operation_count"] == 3
    assert inventory["scoped_noop_runtime_gate_enabled"] is False
    assert inventory["scoped_noop_execution_eligible_count"] == 0
    assert inventory["scoped_noop_executors"] == [
        "verify_setting_noop",
        "verify_p9_http_noop",
    ]
    assert [item["operation"] for item in inventory["scoped_noop_operations"]] == list(
        HTTP_NOOP_CONFIRMATIONS
    )
    assert inventory["execution_policy"] == {
        "model_verification_required": True,
        "general_scope_verification_required": True,
        "plan_confirmation_required": True,
        "exact_name_confirmation_required": True,
        "runtime_safety_gate_required": True,
        "noop_only_requires_scoped_executor": True,
    }
    reservation = next(
        item
        for item in inventory["candidates"]
        if item["endpoint"]["name"] == "admin.client.addr_reservation.add"
    )
    assert reservation["complete_safety_contract"] is True
    assert reservation["live_preflight_supported"] is True
    assert reservation["preflight_read"] == "admin.client.addr_reservation.getlist"
    assert reservation["preflight_compatibility"]["availability"] == "supported"
    assert reservation["execution_eligible"] is False

    modify = next(
        item
        for item in inventory["candidates"]
        if item["endpoint"]["name"] == "admin.client.addr_reservation.modify"
    )
    assert modify["compatibility"]["mutation_tested"] is True
    assert modify["mutation_test_scope"] == "noop_only"
    assert modify["execution_eligible"] is False
    assert modify["scoped_noop_execution_supported"] is False
    assert any("limited to noop_only" in warning for warning in modify["plan_warnings"])

    beamforming = next(
        item
        for item in inventory["candidates"]
        if item["endpoint"]["name"] == "admin.wireless.beamforming.write"
    )
    assert beamforming["compatibility"]["mutation_tested"] is True
    assert beamforming["mutation_test_scope"] == "noop_only"
    assert beamforming["complete_safety_contract"] is True
    assert beamforming["live_preflight_supported"] is True
    assert beamforming["execution_eligible"] is False
    assert beamforming["scoped_noop_execution_supported"] is True
    assert beamforming["scoped_noop_runtime_gate_enabled"] is False
    assert any("limited to noop_only" in warning for warning in beamforming["plan_warnings"])

    ieee80211r = next(
        item
        for item in inventory["candidates"]
        if item["endpoint"]["name"] == "admin.wireless.ieee80211r.write"
    )
    assert ieee80211r["compatibility"]["mutation_tested"] is True
    assert ieee80211r["mutation_test_scope"] == "noop_only"
    assert ieee80211r["complete_safety_contract"] is True
    assert ieee80211r["live_preflight_supported"] is True
    assert ieee80211r["execution_eligible"] is False
    assert any("limited to noop_only" in warning for warning in ieee80211r["plan_warnings"])

    timesetting = next(
        item
        for item in inventory["candidates"]
        if item["endpoint"]["name"] == "admin.device.timesetting.write"
    )
    assert timesetting["compatibility"]["mutation_tested"] is True
    assert timesetting["mutation_test_scope"] == "noop_only"
    assert timesetting["complete_safety_contract"] is True
    assert timesetting["live_preflight_supported"] is True
    assert timesetting["execution_eligible"] is False
    assert any("limited to noop_only" in warning for warning in timesetting["plan_warnings"])

    enabled = DecoService(
        _config(
            allow_mutations=True,
            allow_http_noop_verification=True,
        )
    ).p9_mutation_inventory()
    assert enabled["execution_eligible_count"] == 0
    assert enabled["scoped_noop_runtime_gate_enabled"] is True
    assert enabled["scoped_noop_execution_eligible_count"] == 3

    lan_ip = next(
        item
        for item in inventory["candidates"]
        if item["endpoint"]["name"] == "admin.network.lan_ip.write"
    )
    assert lan_ip["complete_safety_contract"] is False
    assert lan_ip["live_preflight_supported"] is False
    assert (
        "firmware asset and documented LAN IP parameter names conflict" in lan_ip["plan_warnings"]
    )


def test_mcp_service_ranks_http_mutation_verification_offline() -> None:
    service = DecoService(_config())

    with mock.patch.object(service, "_get_client") as get_client:
        default = service.p9_http_mutation_verification_queue()
        complete = service.p9_http_mutation_verification_queue(
            include_deferred=True,
            include_destructive=True,
            include_verified=True,
            limit=100,
        )

    get_client.assert_not_called()
    assert default["candidate_count"] == 23
    assert default["verification_candidate_count"] == 0
    assert default["returned_count"] == 0
    assert default["verification_execution_available"] is False
    assert default["execution_eligible_count"] == 0
    assert complete["returned_count"] == 23
    assert complete["tier_counts"] == {
        "destructive_excluded": 3,
        "evidence_blocked": 1,
        "high_risk_deferred": 15,
        "verified_noop": 4,
    }
    assert complete["mutation_invoked"] is False
    assert complete["payloads_generated"] is False


def test_mcp_service_preflights_full_reservation_table_without_mutating() -> None:
    service = DecoService(_config())
    client = mock.Mock()
    client.get_address_reservations.return_value = AddressReservationTable(
        (AddressReservation("AA:BB:CC:DD:EE:01", "192.168.68.10"),),
        1,
    )

    with mock.patch.object(service, "_get_client", return_value=client):
        result = service.preflight_mutation(
            "admin.client.addr_reservation.add",
            {"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.68.11"},
        )

    assert result["preflight_supported"] is True
    assert result["preflight_passed"] is False
    assert result["reasons"] == ["reservation table is full"]
    assert result["observation"]["is_full"] is True
    assert result["mutation_invoked"] is False
    client.get_address_reservations.assert_called_once_with()
    client.call.assert_not_called()


def test_mcp_service_preflights_noop_reservation_modify_with_rollback() -> None:
    service = DecoService(_config())
    reservation = AddressReservation("AA:BB:CC:DD:EE:01", "192.168.68.10")
    client = mock.Mock()
    client.get_address_reservations.return_value = AddressReservationTable((reservation,), 64)

    with mock.patch.object(service, "_get_client", return_value=client):
        result = service.preflight_mutation(
            "admin.client.addr_reservation.modify",
            {"mac": reservation.mac, "ip": reservation.ip},
        )

    assert result["preflight_passed"] is True
    assert result["observation"]["no_op"] is True
    assert result["rollback_params"] == {"mac": reservation.mac, "ip": reservation.ip}
    assert result["mutation_invoked"] is False


def test_mcp_service_preflight_rejects_invalid_params_before_connecting() -> None:
    service = DecoService(_config())

    with (
        mock.patch.object(service, "_get_client") as get_client,
        pytest.raises(ValueError, match="mac must be a MAC address"),
    ):
        service.preflight_mutation(
            "admin.client.addr_reservation.remove",
            {"mac": "invalid"},
        )

    get_client.assert_not_called()


def test_mcp_service_reports_unknown_preflight_without_connecting() -> None:
    service = DecoService(_config())

    with mock.patch.object(service, "_get_client") as get_client:
        result = service.preflight_mutation(
            "admin.network.lan_ip.write",
            {"ip": "192.168.68.1", "mask": "255.255.255.0"},
        )

    get_client.assert_not_called()
    assert result["preflight_supported"] is False
    assert result["preflight_passed"] is False
    assert result["reasons"] == ["catalogued preflight does not have an evaluator"]
    assert result["mutation_invoked"] is False


def test_mcp_service_preflights_wan_mode_and_returns_rollback() -> None:
    service = DecoService(_config())
    response = ApiResponse.from_api({"error_code": 0, "result": {"wan": {"mode": "dynamic_ip"}}})

    with mock.patch.object(service, "read_endpoint", return_value=response) as read_endpoint:
        result = service.preflight_mutation(
            "admin.network.wan_mode.write",
            {"mode": "dynamic_ip"},
        )

    read_endpoint.assert_called_once_with("admin.network.wan_mode.read")
    assert result["preflight_passed"] is True
    assert result["observation"]["no_op"] is True
    assert result["rollback_params"] == {"mode": "dynamic_ip"}
    assert result["mutation_invoked"] is False


@pytest.mark.parametrize(
    ("name", "current", "target", "no_op"),
    [
        ("admin.wireless.ieee80211r.write", True, True, True),
        ("admin.wireless.beamforming.write", False, True, False),
    ],
)
def test_mcp_service_preflights_boolean_wireless_toggles(
    name: str,
    current: bool,
    target: bool,
    no_op: bool,
) -> None:
    service = DecoService(_config())
    response = ApiResponse.from_api({"error_code": 0, "result": {"enable": current}})

    with mock.patch.object(service, "read_endpoint", return_value=response):
        result = service.preflight_mutation(name, {"enable": target})

    assert result["preflight_passed"] is True
    assert result["observation"]["no_op"] is no_op
    assert result["rollback_params"] == {"enable": current}


def test_mcp_service_preflights_wireless_operation_mode() -> None:
    service = DecoService(_config())
    response = ApiResponse.from_api({"error_code": 0, "result": {"mode": "host"}})

    with mock.patch.object(service, "read_endpoint", return_value=response) as read_endpoint:
        result = service.preflight_mutation(
            "admin.wireless.operation_mode.write",
            {"mode": "host"},
        )

    read_endpoint.assert_called_once_with("admin.wireless.operation_mode.read")
    assert result["preflight_passed"] is True
    assert result["observation"]["no_op"] is True
    assert result["rollback_params"] == {"mode": "host"}


def test_mcp_service_preflights_time_settings_and_blacklist() -> None:
    service = DecoService(_config())
    time_response = ApiResponse.from_api(
        {
            "error_code": 0,
            "result": {
                "timezone": "GMT0BST",
                "continent": "Europe",
                "tz_region": "Europe/London",
            },
        }
    )
    blacklist_response = ApiResponse.from_api(
        {
            "error_code": 0,
            "result": {
                "client_list": [
                    {
                        "mac": "AA:BB:CC:DD:EE:01",
                        "name": "VGVzdA==",
                        "client_type": "phone",
                    }
                ]
            },
        }
    )

    with mock.patch.object(
        service,
        "read_endpoint",
        side_effect=[time_response, blacklist_response],
    ):
        time_result = service.preflight_mutation(
            "admin.device.timesetting.write",
            {
                "timezone": "GMT0BST",
                "continent": "Europe",
                "tz_region": "Europe/London",
            },
        )
        blacklist_result = service.preflight_mutation(
            "admin.client.black_list.remove",
            {"mac": "AA:BB:CC:DD:EE:01"},
        )

    assert time_result["preflight_passed"] is True
    assert time_result["observation"]["no_op"] is True
    assert time_result["rollback_params"] == {
        "timezone": "GMT0BST",
        "continent": "Europe",
        "tz_region": "Europe/London",
    }
    assert blacklist_result["preflight_passed"] is True
    assert blacklist_result["observation"]["target_exists"] is True
    assert blacklist_result["rollback_params"] == {
        "mac": "AA:BB:CC:DD:EE:01",
        "name": "VGVzdA==",
        "client_type": "phone",
    }


def test_mcp_service_discovers_and_closes() -> None:
    with pytest.raises(PermissionError, match="ALLOW_SENSITIVE_READS"):
        DecoService(_config()).get_clients_by_node()

    service = DecoService(_config(allow_sensitive_reads=True))
    probe = EndpointProbeResult(
        endpoint=get_endpoint("admin.component_control.switch_list.read"),
        status="supported",
        elapsed_seconds=0.1,
        response=ApiResponse.from_api({"error_code": 0, "result": {}}),
    )
    report = CapabilityReport("192.0.2.1", "2026-07-10T00:00:00Z", (probe,))
    client = mock.Mock()
    client.discover_capabilities.return_value = report
    client.discover_p9_read_endpoints.return_value = report
    client.discover_read_endpoints.return_value = report
    client.get_clients_by_node.return_value = (NodeClientList("AA:BB", ()),)
    service._client = client

    assert service.discover_capabilities() is report
    assert service.discover_p9_reads() is report
    assert service.discover_all_reads() is report
    assert service.get_clients_by_node() == (NodeClientList("AA:BB", ()),)

    service.close()

    client.logout.assert_called_once()
    assert service._client is None
    service.close()


def test_mcp_service_sensitive_schema_discovery_requires_gate() -> None:
    service = DecoService(_config())
    with pytest.raises(PermissionError, match="DECO_ALLOW_SENSITIVE_READS"):
        service.discover_p9_sensitive_schemas()
    with pytest.raises(PermissionError, match="DECO_ALLOW_SENSITIVE_READS"):
        service.discover_all_sensitive_schemas()

    service = DecoService(_config(allow_sensitive_reads=True))
    observation = mock.Mock()
    client = mock.Mock()
    client.observe_endpoint_schema.return_value = observation
    with mock.patch.object(service, "_get_client", return_value=client):
        result = service.discover_p9_sensitive_schemas()

    assert len(result) == 11
    assert all(item is observation for item in result)
    assert client.observe_endpoint_schema.call_count == 11
    assert all(
        call.kwargs == {"include_sensitive": True}
        for call in client.observe_endpoint_schema.call_args_list
    )

    client.reset_mock()
    client.observe_endpoint_schema.return_value = observation
    with mock.patch.object(service, "_get_client", return_value=client):
        all_result = service.discover_all_sensitive_schemas()

    assert len(all_result) == 57
    assert client.observe_endpoint_schema.call_count == 57


def test_mcp_service_builds_value_free_compatibility_manifest() -> None:
    service = DecoService(_config())
    probe = EndpointProbeResult(
        endpoint=get_endpoint("admin.network.performance.read"),
        status="supported",
        elapsed_seconds=0.1,
        response=ApiResponse.from_api(
            {"error_code": 0, "result": {"cpu_usage": 0.5, "private_ip": "192.0.2.5"}}
        ),
    )
    report = CapabilityReport("192.0.2.1", "2026-07-10T00:00:00Z", (probe,))
    client = mock.Mock()
    client.get_device_list.return_value = [
        Device.from_api(
            {
                "device_model": "P9",
                "hardware_ver": "2.0",
                "software_ver": "1.3.0",
            }
        )
    ]
    client.get_device_mode.return_value = DeviceMode("FAP", "Router")
    client.discover_p9_read_endpoints.return_value = report
    client.discover_read_endpoints.return_value = report

    with mock.patch.object(service, "_get_client", return_value=client):
        manifest = service.build_compatibility_manifest()
        full_manifest = service.build_compatibility_manifest(full=True)

    assert manifest.model == "P9"
    assert manifest.hardware_versions == ("2.0",)
    assert manifest.firmware_version == "1.3.0"
    assert manifest.system_mode == "Router"
    assert "$.cpu_usage:number" in manifest.observations[0].schema_paths
    assert "192.0.2.5" not in manifest.to_json()

    assert full_manifest.observations == manifest.observations
    client.discover_read_endpoints.assert_called_once()


def test_mcp_service_connects_lazily_and_requires_password() -> None:
    missing = ServerConfig("192.0.2.1", "admin", "", 60.0)
    with pytest.raises(ValueError, match="DECO_PASSWORD"):
        DecoService(missing)._get_client()

    service = DecoService(_config())
    client = mock.Mock()
    client.is_authenticated.side_effect = [False, True]
    with mock.patch(
        "tplink_deco_api.service.deco_service.DecoClient", return_value=client
    ) as client_type:
        assert service._get_client() is client
        assert service._get_client() is client

    client_type.assert_called_once_with("192.0.2.1", "admin", "secret", timeout=60.0)
    client.login.assert_called_once()


@pytest.mark.asyncio
async def test_mcp_server_registers_resources_and_tools() -> None:
    server = create_server(_config())

    tools = await server.list_tools()
    resources = await server.list_resources()
    tool_names = {tool.name for tool in tools}
    catalog_result = await server.call_tool(
        "deco_endpoint_catalog",
        {"safety": "mutation", "include_sensitive": False},
    )
    tmp_verification_queue = await server.call_tool(
        "deco_p9_tmp_mutation_verification_queue",
        {"limit": 4},
    )
    http_verification_queue = await server.call_tool(
        "deco_p9_http_mutation_verification_queue",
        {},
    )
    status_result = await server.read_resource("deco://mcp")
    catalog_resource = await server.read_resource("deco://diagnostics/operations")
    p9_resource = await server.read_resource("deco://profiles/P9")
    p9_operations_resource = await server.read_resource("deco://profiles/P9/operations")
    p9_mutations_resource = await server.read_resource("deco://diagnostics/http/mutations")
    transport_resource = await server.read_resource("deco://diagnostics/transports")
    tmp_opcodes_resource = await server.read_resource("deco://diagnostics/tmp/opcodes")
    tmp_mutations_resource = await server.read_resource("deco://diagnostics/tmp/mutations")
    coverage_resource = await server.read_resource("deco://diagnostics/coverage")

    assert {
        "deco_get_capability",
        "deco_get_router_profile",
        "deco_execute_mutation",
        "deco_plan_capability_mutation",
        "deco_plan_raw_mutation",
        "deco_verify_setting_noop",
        "deco_endpoint_catalog",
        "deco_p9_profile",
        "deco_transport_capabilities",
        "deco_probe_p9_transport_services",
        "deco_p9_tmp_opcode_catalog",
        "deco_p9_tmp_mutation_inventory",
        "deco_p9_access_coverage",
        "deco_plan_tmp_mutation",
        "deco_p9_tmp_mutation_verification_queue",
        "deco_verify_p9_http_noop",
        "deco_tmp_host_key",
        "deco_tmp_read",
        "deco_tmp_read_binary",
        "deco_discover_tmp_read_contracts",
        "deco_discover_tmp_unverified_reads",
        "deco_get_p9_tmp_data",
        "deco_p9_mutation_inventory",
        "deco_p9_http_mutation_verification_queue",
        "deco_operation_compatibility",
        "deco_get_network_overview",
        "deco_get_p9_http_data",
        "deco_discover_p9_untested_http_reads",
        "deco_get_mesh_overview",
        "deco_get_wlan_state",
        "deco_get_cloud_state",
        "deco_get_client_overview",
        "deco_get_system_overview",
        "deco_read_endpoint",
        "deco_validate_operation",
        "deco_plan_mutation",
        "deco_preflight_mutation",
        "deco_read_binary_endpoint",
        "deco_discover_p9_binary_reads",
        "deco_discover_capabilities",
        "deco_discover_p9_reads",
        "deco_discover_all_reads",
        "deco_discover_p9_sensitive_schemas",
        "deco_discover_all_sensitive_schemas",
        "deco_get_clients_by_node",
        "deco_build_compatibility_manifest",
        "deco_compare_manifests",
    } <= tool_names
    assert "deco_invoke_mutation" not in tool_names
    assert len(tool_names) == 47
    assert len(resources) == 22
    assert "admin.network.wan_mode.write" in str(catalog_result)
    assert "password_configured" in str(status_result)
    assert "admin.network.performance.read" in str(catalog_resource)
    assert "1.3.0 Build 20250804" in str(p9_resource)
    assert '"availability": "supported"' in str(p9_operations_resource)
    assert '"candidate_count": 23' in str(p9_mutations_resource)
    assert '"execution_eligible_count": 0' in str(p9_mutations_resource)
    assert '"external_port": 20001' in str(transport_resource)
    assert '"catalogued_opcode_count": 600' in str(tmp_opcodes_resource)
    assert '"p9_opcode_tested_count": 251' in str(tmp_opcodes_resource)
    assert '"protocol_implemented": true' in str(tmp_opcodes_resource)
    assert "TMP_APPV2_OP_PLC_PAIR_GET" in str(tmp_opcodes_resource)
    assert '"candidate_count": 348' in str(tmp_mutations_resource)
    assert '"execution_available": false' in str(tmp_mutations_resource)
    assert '"server_write_policy": "hard_disabled"' in str(tmp_mutations_resource)
    assert '"generic_execution_available": false' in str(tmp_mutations_resource)
    assert '"returned_count": 0' in str(tmp_verification_queue)
    assert '"verification_candidate_count": 0' in str(http_verification_queue)
    assert '"returned_count": 0' in str(http_verification_queue)
    assert "TMP_APPV2_OP_BEAMFORMING_SET" not in str(tmp_verification_queue)
    assert '"all_positive_reads_have_caller_path": true' in str(coverage_resource)
    assert '"catalogued_read_without_transport_count": 0' in str(coverage_resource)
    assert '"returned_data_count": 55' in str(coverage_resource)

    compatibility = await server.call_tool(
        "deco_operation_compatibility",
        {"name": "admin.network.performance.read", "model": "P9"},
    )
    assert '"returned_data": true' in str(compatibility)

    manifest = CompatibilityManifest.from_report(
        CapabilityReport("192.0.2.1", "2026-07-10T00:00:00Z", ()),
        catalog_version=1,
        model="P9",
        hardware_versions=("2.0",),
        firmware_version="1.3.0",
    )
    comparison = await server.call_tool(
        "deco_compare_manifests",
        {"previous_json": manifest.to_json(), "current_json": manifest.to_json()},
    )
    assert '"has_changes": false' in str(comparison)

    with pytest.raises(ToolError):
        await server.call_tool(
            "deco_read_endpoint",
            {"name": "admin.network.performance.read", "params_json": "not-json"},
        )
    with pytest.raises(ToolError):
        await server.call_tool(
            "deco_verify_tmp_ieee80211r_noop",
            {"confirmation": TMP_IEEE80211R_NOOP_CONFIRMATION},
        )
    with pytest.raises(ToolError):
        await server.call_tool(
            "deco_verify_p9_http_noop",
            {
                "operation": "admin.wireless.beamforming.write",
                "confirmation": HTTP_NOOP_CONFIRMATIONS["admin.wireless.beamforming.write"],
            },
        )
    with pytest.raises(ToolError):
        await server.call_tool("deco_discover_p9_binary_reads", {})
    with pytest.raises(ToolError):
        await server.call_tool(
            "deco_invoke_mutation",
            {
                "name": "admin.network.wan_mode.write",
                "confirmation": "admin.network.wan_mode.write",
                "params_json": json.dumps({"mode": "router"}),
            },
        )


@pytest.mark.asyncio
async def test_static_token_verifier_accepts_only_the_configured_token() -> None:
    verifier = _StaticTokenVerifier("x" * 32, "http://192.0.2.10:8000/mcp")

    accepted = await verifier.verify_token("x" * 32)

    assert accepted is not None
    assert accepted.client_id == "deco-mcp-private-client"
    assert accepted.resource == "http://192.0.2.10:8000/mcp"
    assert await verifier.verify_token("y" * 32) is None


def test_streamable_http_server_is_authenticated_and_has_process_health() -> None:
    config = replace(
        _config(),
        transport="streamable-http",
        server_host="0.0.0.0",
        server_port=8000,
        mcp_public_url="http://192.0.2.10:8000/mcp",
        bearer_token="x" * 32,
        allowed_hosts=("testserver", "192.0.2.10:8000"),
        allowed_origins=("https://agent.example",),
    )
    server = create_server(config)

    assert server.settings.host == "0.0.0.0"
    assert server.settings.port == 8000
    assert server.settings.streamable_http_path == "/mcp"
    assert server.settings.auth is not None
    assert server.settings.transport_security is not None
    assert server.settings.transport_security.allowed_hosts == [
        "testserver",
        "192.0.2.10:8000",
    ]

    with TestClient(server.streamable_http_app()) as client:
        assert client.get("/healthz").text == "ok"
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        rejected_origin = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {'x' * 32}",
                "Origin": "https://untrusted.example",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )

    assert response.status_code == 401
    assert rejected_origin.status_code == 403


def test_mcp_main_runs_stdio_server() -> None:
    server = mock.Mock()
    with mock.patch("tplink_deco_api.mcp.server.create_server", return_value=server):
        main()

    server.run.assert_called_once_with(transport="stdio")


def test_mcp_main_runs_configured_streamable_http_server() -> None:
    config = replace(
        _config(),
        transport="streamable-http",
        mcp_public_url="http://192.0.2.10:8000/mcp",
        bearer_token="x" * 32,
        allowed_hosts=("192.0.2.10:8000",),
    )
    server = mock.Mock()
    with (
        mock.patch("tplink_deco_api.mcp.server.ServerConfig.from_env", return_value=config),
        mock.patch("tplink_deco_api.mcp.server.create_server", return_value=server) as factory,
    ):
        main()

    factory.assert_called_once_with(config)
    server.run.assert_called_once_with(transport="streamable-http")
