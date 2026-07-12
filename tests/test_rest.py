"""Contract, security and lifecycle tests for the composite REST and MCP server."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
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
from tplink_deco_api.rest import create_http_application
from tplink_deco_api.rest._in_memory_idempotency_store import _InMemoryIdempotencyStore
from tplink_deco_api.rest.request_capacity_middleware import RequestCapacityMiddleware
from tplink_deco_api.server import ServerConfig, StaticBearerAuthenticator

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
    application = create_http_application(_config())
    service = application.state.deco_service
    methods = (
        "public_status",
        "network_status_resource",
        "configuration_resource",
        "device_inventory",
        "client_devices_resource",
        "traffic_resource",
        "address_reservations_resource",
        "logs_resource",
        "capabilities",
        "read_capability",
        "wlan_state",
        "cloud_state",
    )
    with ExitStack() as stack:
        patched = {
            method: stack.enter_context(
                mock.patch.object(service, method, return_value={"source": method})
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
                client.get("/api/v1/capabilities", headers=_AUTH),
                client.get("/api/v1/capabilities/beamforming", headers=_AUTH),
                client.get("/api/v1/wlan?include_passwords=true", headers=_AUTH),
                client.get("/api/v1/cloud", headers=_AUTH),
            )

    assert all(response.status_code == 200 for response in responses)
    assert [response.json()["source"] for response in responses] == list(methods)
    patched["device_inventory"].assert_called_once_with(refresh=True)
    patched["client_devices_resource"].assert_called_once_with("blocked")
    patched["read_capability"].assert_called_once_with("beamforming")
    patched["wlan_state"].assert_called_once_with(include_passwords=True)


def test_rest_mutation_catalog_and_noncreating_preflight() -> None:
    application = create_http_application(_config())
    service = application.state.deco_service
    catalog = {
        "schema_version": 1,
        "mutations": [{"name": "beamforming", "execution_status": "ready"}],
    }
    preflight = {
        "schema_version": 1,
        "mutation": "beamforming",
        "execution_allowed": True,
        "plan_id": None,
        "blockers": [],
    }
    with (
        mock.patch.object(service, "semantic_mutations", return_value=catalog) as inventory,
        mock.patch.object(
            service,
            "semantic_mutation",
            side_effect=[
                {"name": "beamforming", "execution_status": "ready"},
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

    assert all_mutations.json() == catalog
    assert mutation.json()["name"] == "beamforming"
    assert missing.status_code == 404
    assert response.status_code == 200
    assert response.json()["plan_id"] is None
    inventory.assert_called_once_with()
    assert one_mutation.call_count == 2
    assess.assert_called_once_with("beamforming", {}, mode="verify_current_value_noop")


def test_rest_plan_creation_rejects_blockers_and_returns_created_plan() -> None:
    application = create_http_application(_config())
    service = application.state.deco_service
    blocked = {
        "execution_allowed": False,
        "plan_id": None,
        "blockers": ["state-changing semantic execution is not yet validated"],
    }
    created = {
        "execution_allowed": True,
        "plan_id": "plan-1",
        "required_confirmation": "CONFIRM",
        "blockers": [],
    }
    with (
        mock.patch.object(
            service,
            "plan_semantic_mutation",
            side_effect=[blocked, created],
        ),
        TestClient(application) as client,
    ):
        rejected = client.post(
            "/api/v1/mutation-plans",
            headers=_AUTH,
            json={"name": "beamforming", "changes": {"enable": False}},
        )
        accepted = client.post(
            "/api/v1/mutation-plans",
            headers=_AUTH,
            json={"name": "beamforming", "mode": "verify_current_value_noop"},
        )

    assert rejected.status_code == 409
    assert rejected.headers["content-type"].startswith("application/problem+json")
    assert rejected.json()["code"] == "mutation_ineligible"
    assert rejected.json()["blockers"] == blocked["blockers"]
    assert accepted.status_code == 201
    assert accepted.json()["plan_id"] == "plan-1"


def test_rest_execution_is_synchronous_and_process_idempotent() -> None:
    application = create_http_application(_config())
    service = application.state.deco_service
    with (
        mock.patch.object(
            service,
            "execute_semantic_mutation",
            return_value={"status": "verified_noop", "plan_consumed": True},
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
