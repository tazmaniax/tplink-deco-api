"""FastMCP server exposing capability-aware Deco operations."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, cast

from mcp.server.fastmcp import FastMCP

from .._json import JsonObject, JsonValue, loads
from ..models import CompatibilityManifest
from .config import McpConfig
from .service import DecoMcpService

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


def _json_text(value: JsonValue) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _params(params_json: str) -> JsonObject:
    return loads(params_json)


def _json_value(value_json: str) -> JsonValue:
    return cast("JsonValue", json.loads(value_json))


def create_server(config: McpConfig | None = None) -> FastMCP[None]:
    """Create a stdio-capable MCP server with conservative safety defaults."""
    service = DecoMcpService(config or McpConfig.from_env())

    @asynccontextmanager
    async def lifespan(_: FastMCP[None]) -> AsyncIterator[None]:
        try:
            yield
        finally:
            service.close()

    server = FastMCP(
        "TP-Link Deco",
        instructions=(
            "Inspect endpoint metadata before calls. Read-only operations are enabled by default. "
            "Sensitive reads, mutations, destructive operations, and internal operations each "
            "require a separate server-side environment opt-in. Bulk-secret downloads and "
            "binary content export have additional independent gates. TMP reads have independent "
            "verified and unverified gates and require a pinned SSH host key. Plan every "
            "mutation before requesting execution; a plan never contacts the router. HTTP "
            "setting no-ops and the TMP 802.11r no-op use separate dedicated gates, accept no "
            "desired values, and latch off after any non-verified outcome."
        ),
        lifespan=lifespan,
    )

    @server.resource("deco://endpoint-catalog")
    def endpoint_catalog_resource() -> str:
        """Return the non-secret endpoint catalogue as JSON."""
        return _json_text(service.endpoint_catalog())

    @server.resource("deco://status")
    def status_resource() -> str:
        """Return non-secret configuration and connection status."""
        return _json_text(service.public_status())

    @server.resource("deco://transport-capabilities")
    def transport_capabilities_resource() -> str:
        """Return implemented and catalogued transport coverage."""
        return _json_text(service.transport_capabilities())

    @server.resource("deco://compatibility/p9/tmp-opcodes")
    def p9_tmp_opcodes_resource() -> str:
        """Return TMP/AppV2 opcode metadata with exact P9 observations."""
        return _json_text(service.p9_tmp_opcode_catalog())

    @server.resource("deco://compatibility/p9/tmp-mutations")
    def p9_tmp_mutations_resource() -> str:
        """Return TMP mutation safety evidence and narrowly scoped execution metadata."""
        return _json_text(service.p9_tmp_mutation_inventory())

    @server.resource("deco://compatibility/p9/coverage")
    def p9_coverage_resource() -> str:
        """Return unified P9 access coverage, call paths, and remaining gaps."""
        return _json_text(service.p9_access_coverage())

    @server.resource("deco://compatibility/p9")
    def p9_profile_resource() -> str:
        """Return the bundled value-free P9 compatibility summary."""
        return _json_text(service.p9_profile())

    @server.resource("deco://compatibility/p9/operations")
    def p9_operations_resource() -> str:
        """Return model evidence overlaid on every non-secret catalogue operation."""
        return _json_text(service.endpoint_catalog(model="P9"))

    @server.resource("deco://compatibility/p9/mutations")
    def p9_mutations_resource() -> str:
        """Return P9 mutation evidence and safety-contract coverage."""
        return _json_text(service.p9_mutation_inventory())

    @server.tool()
    def deco_endpoint_catalog(
        safety: str = "",
        include_sensitive: bool = False,
        model: str = "",
    ) -> str:
        """List operations and optionally overlay model-specific compatibility evidence."""
        return _json_text(
            service.endpoint_catalog(
                safety,
                include_sensitive=include_sensitive,
                model=model,
            )
        )

    @server.tool()
    def deco_p9_profile() -> str:
        """List observed P9 reads and clearly labelled untested mutation candidates."""
        return _json_text(service.p9_profile())

    @server.tool()
    def deco_transport_capabilities() -> str:
        """Explain implemented, unsupported, and detected Deco transports."""
        return _json_text(service.transport_capabilities())

    @server.tool()
    def deco_probe_p9_transport_services(
        include_nodes: bool = False,
        timeout: float = 2.0,
    ) -> str:
        """Check documented P9 transport ports without authentication or payloads."""
        return _json_text(
            service.probe_p9_transport_services(
                include_nodes=include_nodes,
                timeout=timeout,
            )
        )

    @server.tool()
    def deco_p9_tmp_opcode_catalog(
        safety: str = "",
        category: str = "",
        query: str = "",
    ) -> str:
        """List TMP/AppV2 opcodes and P9 evidence by safety or category."""
        return _json_text(service.p9_tmp_opcode_catalog(safety, category, query))

    @server.tool()
    def deco_p9_tmp_mutation_inventory() -> str:
        """List all TMP writes with preflight, verification, and rollback evidence."""
        return _json_text(service.p9_tmp_mutation_inventory())

    @server.tool()
    def deco_p9_access_coverage() -> str:
        """Explain what P9 data is callable and which evidence gaps remain."""
        return _json_text(service.p9_access_coverage())

    @server.tool()
    def deco_plan_tmp_mutation(opcode: int) -> str:
        """Plan one TMP mutation offline; no generic TMP execution tool exists."""
        return _json_text(service.plan_tmp_mutation(opcode))

    @server.tool()
    def deco_p9_tmp_mutation_verification_queue(
        include_sensitive: bool = False,
        include_deferred: bool = False,
        include_destructive: bool = False,
        limit: int = 20,
    ) -> str:
        """Rank TMP writes for separate authorization without contacting the router."""
        return _json_text(
            service.p9_tmp_mutation_verification_queue(
                include_sensitive=include_sensitive,
                include_deferred=include_deferred,
                include_destructive=include_destructive,
                limit=limit,
            )
        )

    @server.tool()
    def deco_verify_tmp_ieee80211r_noop(confirmation: str) -> str:
        """Repeat the verified 802.11r current-value no-op under three runtime gates."""
        return _json_text(service.verify_tmp_ieee80211r_noop(confirmation))

    @server.tool()
    def deco_verify_p9_http_noop(operation: str, confirmation: str) -> str:
        """Repeat one verified P9 HTTP setting no-op under two runtime gates."""
        return _json_text(service.verify_p9_http_noop(operation, confirmation))

    @server.tool()
    def deco_tmp_host_key() -> str:
        """Read the P9 TMP SSH host-key fingerprint without authentication."""
        return _json_text(service.tmp_host_key())

    @server.tool()
    def deco_tmp_read(opcode: int, params_json: str = "null") -> str:
        """Invoke a gated read-only AppV2 opcode with model-evidence checks."""
        return _json_text(service.tmp_read(opcode, _json_value(params_json)))

    @server.tool()
    def deco_tmp_read_binary(
        opcode: int,
        params_json: str = "null",
        include_content: bool = False,
    ) -> str:
        """Read an observed binary AppV2 response as digest metadata or opted-in base64."""
        return _json_text(
            service.tmp_read_binary(
                opcode,
                _json_value(params_json),
                include_content=include_content,
            )
        )

    @server.tool()
    def deco_discover_tmp_read_contracts(
        include_inferred_iot_module_contract: bool = False,
    ) -> str:
        """Try bounded parameterized TMP GETs and return only value-free evidence."""
        return _json_text(
            service.discover_tmp_read_contracts(
                include_inferred_iot_module_contract=include_inferred_iot_module_contract,
            )
        )

    @server.tool()
    def deco_discover_tmp_unverified_reads(
        include_sensitive: bool = False,
        max_operations: int | None = None,
    ) -> str:
        """Probe newly catalogued TMP reads and return only schemas and error codes."""
        return _json_text(
            service.discover_tmp_unverified_reads(
                include_sensitive=include_sensitive,
                max_operations=max_operations,
            )
        )

    @server.tool()
    def deco_get_p9_tmp_data(
        category: str = "",
        include_parameterized: bool = False,
    ) -> str:
        """Return all P9-confirmed TMP JSON data, optionally scoped by category."""
        return _json_text(
            service.p9_tmp_data(
                category,
                include_parameterized=include_parameterized,
            )
        )

    @server.tool()
    def deco_p9_mutation_inventory() -> str:
        """List P9 mutation candidates, evidence, safety contracts, and eligibility."""
        return _json_text(service.p9_mutation_inventory())

    @server.tool()
    def deco_p9_http_mutation_verification_queue(
        include_deferred: bool = False,
        include_destructive: bool = False,
        include_verified: bool = False,
        limit: int = 20,
    ) -> str:
        """Rank HTTP writes for separate authorization without contacting the router."""
        return _json_text(
            service.p9_http_mutation_verification_queue(
                include_deferred=include_deferred,
                include_destructive=include_destructive,
                include_verified=include_verified,
                limit=limit,
            )
        )

    @server.tool()
    def deco_operation_compatibility(name: str, model: str = "P9") -> str:
        """Explain generic and model-specific evidence for one operation."""
        return _json_text(service.operation_compatibility(name, model))

    @server.tool()
    def deco_get_network_overview() -> str:
        """Return confirmed network, performance, time, and reservation state."""
        return _json_text(service.network_overview())

    @server.tool()
    def deco_get_p9_http_data(
        controller: str = "",
        include_sensitive: bool = False,
    ) -> str:
        """Return P9-supported HTTP data by controller with explicit secret opt-in."""
        return _json_text(
            service.p9_http_data(
                controller,
                include_sensitive=include_sensitive,
            )
        )

    @server.tool()
    def deco_discover_p9_untested_http_reads() -> str:
        """Probe any remaining untested, non-secret P9 JSON reads with safe transport."""
        return _json_text(service.discover_p9_untested_http_reads())

    @server.tool()
    def deco_get_mesh_overview() -> str:
        """Return mesh nodes and per-node client associations."""
        return _json_text(service.mesh_overview())

    @server.tool()
    def deco_get_wlan_state(include_passwords: bool = False) -> str:
        """Return opted-in WLAN state; passwords remain omitted unless explicitly requested."""
        return _json_text(service.wlan_state(include_passwords=include_passwords))

    @server.tool()
    def deco_get_cloud_state() -> str:
        """Return opted-in DDNS and cloud-manager state."""
        return _json_text(service.cloud_state())

    @server.tool()
    def deco_get_client_overview() -> str:
        """Return client, traffic, blacklist, and address-reservation state."""
        return _json_text(service.client_overview())

    @server.tool()
    def deco_get_system_overview() -> str:
        """Return speed-test, firmware, nickname, and log-type state."""
        return _json_text(service.system_overview())

    @server.tool()
    def deco_read_endpoint(name: str, params_json: str = "{}") -> str:
        """Call one catalogued read operation and return its complete response envelope."""
        return _json_text(service.read_endpoint(name, _params(params_json)).payload)

    @server.tool()
    def deco_validate_operation(
        name: str,
        params_json: str = "{}",
        model: str = "P9",
    ) -> str:
        """Validate parameters, transport, and model evidence without contacting a router."""
        return _json_text(service.validate_operation(name, _params(params_json), model))

    @server.tool()
    def deco_plan_mutation(
        name: str,
        params_json: str = "{}",
        model: str = "P9",
    ) -> str:
        """Plan preflight, verification, and rollback without contacting the router."""
        return _json_text(service.plan_mutation(name, _params(params_json), model))

    @server.tool()
    def deco_preflight_mutation(
        name: str,
        params_json: str = "{}",
        model: str = "P9",
    ) -> str:
        """Evaluate a known mutation preflight using router reads only."""
        return _json_text(service.preflight_mutation(name, _params(params_json), model))

    @server.tool()
    def deco_read_binary_endpoint(name: str, include_content: bool = False) -> str:
        """Download a binary read and return integrity metadata plus optional base64 content."""
        return _json_text(
            service.read_binary_endpoint(
                name,
                include_content=include_content,
            ).to_dict(include_content=include_content)
        )

    @server.tool()
    def deco_discover_p9_binary_reads() -> str:
        """Download P9 bulk-secret candidates but return only size and digest metadata."""
        return _json_text(service.discover_p9_binary_reads())

    @server.tool()
    def deco_discover_capabilities() -> str:
        """Probe dedicated capability endpoints without invoking writes or secret reads."""
        return _json_text(service.discover_capabilities().to_dict())

    @server.tool()
    def deco_discover_p9_reads() -> str:
        """Probe the curated non-secret P9 read surface and classify each result."""
        return _json_text(service.discover_p9_reads().to_dict())

    @server.tool()
    def deco_discover_all_reads() -> str:
        """Probe every catalogued non-secret owner-session read and return its values."""
        return _json_text(service.discover_all_reads().to_dict())

    @server.tool()
    def deco_discover_p9_sensitive_schemas() -> str:
        """Observe opted-in P9 secret response schemas without returning any values."""
        return _json_text(
            {
                "values_retained": False,
                "observations": [
                    observation.to_dict() for observation in service.discover_p9_sensitive_schemas()
                ],
            }
        )

    @server.tool()
    def deco_discover_all_sensitive_schemas() -> str:
        """Observe all opted-in secret JSON schemas without returning any values."""
        return _json_text(
            {
                "values_retained": False,
                "binary_reads_excluded": True,
                "observations": [
                    observation.to_dict()
                    for observation in service.discover_all_sensitive_schemas()
                ],
            }
        )

    @server.tool()
    def deco_get_clients_by_node() -> str:
        """Query every mesh node and preserve its reported client associations."""
        return _json_text(
            {
                "nodes": [
                    node_client_list.to_dict() for node_client_list in service.get_clients_by_node()
                ]
            }
        )

    @server.tool()
    def deco_build_compatibility_manifest(full: bool = False) -> str:
        """Build a privacy-preserving manifest of the live P9 endpoint surface."""
        return service.build_compatibility_manifest(full=full).to_json()

    @server.tool()
    def deco_compare_manifests(previous_json: str, current_json: str) -> str:
        """Compare two compatibility manifests without contacting a router."""
        previous = CompatibilityManifest.from_json(previous_json)
        current = CompatibilityManifest.from_json(current_json)
        return _json_text(current.compare(previous).to_dict())

    @server.tool()
    def deco_invoke_mutation(
        name: str,
        confirmation: str,
        params_json: str = "{}",
        plan_confirmation: str = "",
        model: str = "P9",
    ) -> str:
        """Invoke an opted-in, model-verified operation bound to a reviewed plan."""
        return _json_text(
            service.invoke_mutation(
                name,
                _params(params_json),
                confirmation,
                plan_confirmation,
                model,
            ).payload
        )

    return server


def main() -> None:
    """Run the Deco MCP server over standard input/output."""
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
