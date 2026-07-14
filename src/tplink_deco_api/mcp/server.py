"""FastMCP server exposing capability-aware Deco operations."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, cast

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.responses import PlainTextResponse

from .._json import JsonObject, JsonValue, loads
from ..models import CompatibilityManifest
from ..responses import ResponseDto
from ..server import ServerConfig
from ..service import DecoService
from ._static_token_verifier import _StaticTokenVerifier

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

_PRIMARY_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "deco_get_capability",
        "deco_plan_mutation",
        "deco_execute_mutation",
        "deco_get_wlan_state",
        "deco_get_cloud_state",
    }
)
_PRIMARY_RESOURCE_URIS: frozenset[str] = frozenset(
    {
        "deco://mcp",
        "deco://status",
        "deco://configuration",
        "deco://system/led",
        "deco://mesh",
        "deco://mesh/traffic",
        "deco://wireless/wps",
        "deco://reports/monthly/settings",
        "deco://reports/monthly",
        "deco://notifications",
        "deco://speed-test/servers",
        "deco://parental-controls",
        "deco://parental-controls/filter-levels",
        "deco://parental-controls/catalog",
        "deco://access/permissions",
        "deco://devices",
        "deco://devices/active",
        "deco://devices/inactive",
        "deco://devices/blocked",
        "deco://devices/ipv6",
        "deco://traffic",
        "deco://address-reservations",
        "deco://network/lan",
        "deco://network/dhcp",
        "deco://network/qos",
        "deco://network/vlan",
        "deco://network/port-forwarding",
        "deco://network/iptv",
        "deco://network/sip-alg",
        "deco://network/mac-clone",
        "deco://network/ipv4",
        "deco://network/ipv6",
        "deco://network/ipv6/firewall",
        "deco://logs",
        "deco://capabilities",
        "deco://mutations",
    }
)
_RAW_MUTATION_TOOL_NAMES: frozenset[str] = frozenset({"deco_invoke_mutation"})
_MUTATING_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "deco_execute_mutation",
        "deco_invoke_mutation",
        "deco_verify_p9_http_noop",
        "deco_verify_setting_noop",
    }
)
_STATEFUL_TOOL_NAMES: frozenset[str] = frozenset({"deco_plan_mutation"})
_READ_ONLY_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_STATEFUL_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
_MUTATING_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)


def _json_text(value: JsonValue | ResponseDto) -> str:
    payload = value.to_dict() if isinstance(value, ResponseDto) else value
    return json.dumps(payload, indent=2, sort_keys=True)


def _params(params_json: str) -> JsonObject:
    return loads(params_json)


def _json_value(value_json: str) -> JsonValue:
    return cast("JsonValue", json.loads(value_json))


def create_server(
    config: ServerConfig | None = None,
    service: DecoService | None = None,
    *,
    include_health_route: bool = True,
    streamable_http_path: str | None = None,
) -> FastMCP[None]:
    """Create a transport-configurable MCP server with conservative safety defaults."""
    effective_config = config or ServerConfig.from_env()
    effective_config.validate_server()
    effective_service = service or DecoService(effective_config)
    owns_service = service is None
    service = effective_service
    auth: AuthSettings | None = None
    token_verifier: _StaticTokenVerifier | None = None
    transport_security: TransportSecuritySettings | None = None
    if effective_config.transport == "streamable-http":
        public_url = AnyHttpUrl(effective_config.mcp_public_url)
        auth = AuthSettings(
            issuer_url=public_url,
            resource_server_url=public_url,
            required_scopes=[],
        )
        token_verifier = _StaticTokenVerifier(
            effective_config.bearer_token,
            effective_config.mcp_public_url,
        )
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(effective_config.allowed_hosts),
            allowed_origins=list(effective_config.allowed_origins),
        )

    @asynccontextmanager
    async def lifespan(_: FastMCP[None]) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_service:
                effective_service.close()

    server = FastMCP(
        "TP-Link Deco",
        instructions=(
            "Use semantic resources and protocol-neutral parameterized tools for normal work; "
            "the server selects HTTP/LuCI or TMP/AppV2 and reports provenance. Automatic fallback "
            "is limited to proven equivalent reads and never applies to mutations. Read-only "
            "operations are enabled by default. "
            "Sensitive reads, mutations, destructive operations, and internal operations each "
            "require a separate server-side environment opt-in. Bulk-secret downloads and "
            "binary content export have additional independent gates. TMP reads have independent "
            "verified and unverified gates and require a pinned SSH host key. Read semantic "
            "resources to discover the connected mesh, configuration, capabilities and mutation "
            "eligibility. Plan every mutation before requesting execution; planning may resolve "
            "the controller read-only but never writes. Eligible plans are short-lived, one-shot, "
            "identity-bound and have no mutation fallback. Current verified execution accepts no "
            "desired values and latches off after any non-verified outcome."
        ),
        lifespan=lifespan,
        host=effective_config.server_host,
        port=effective_config.server_port,
        streamable_http_path=streamable_http_path or effective_config.mcp_path,
        auth=auth,
        token_verifier=token_verifier,
        transport_security=transport_security,
    )

    if effective_config.transport == "streamable-http" and include_health_route:

        async def health_resource(_: Request) -> PlainTextResponse:
            """Return process liveness without contacting or authenticating to the router."""
            return PlainTextResponse("ok")

        server.custom_route("/healthz", methods=["GET"], include_in_schema=False)(health_resource)

    @server.resource("deco://diagnostics/operations")
    def endpoint_catalog_resource() -> str:
        """Return the non-secret endpoint catalogue as JSON."""
        return _json_text(effective_service.endpoint_catalog())

    @server.resource("deco://mcp")
    def mcp_resource() -> str:
        """Return non-secret MCP configuration and connection state."""
        return _json_text(service.public_status())

    @server.resource("deco://status")
    def status_resource() -> str:
        """Return a sanitized live health summary of the connected Deco network."""
        return _json_text(service.network_status_resource())

    @server.resource("deco://configuration")
    def configuration_resource() -> str:
        """Return a sanitized live overview of the connected Deco configuration."""
        return _json_text(service.configuration_resource())

    @server.resource("deco://system/led")
    def led_configuration_resource() -> str:
        """Return the gated system LED and night-mode state."""
        return _json_text(service.led_configuration_resource())

    @server.resource("deco://mesh")
    def mesh_resource() -> str:
        """Return a fresh connected-controller and mesh-node inventory."""
        return _json_text(service.device_inventory(refresh=True))

    @server.resource("deco://mesh/traffic")
    def mesh_traffic_resource() -> str:
        """Return firmware-native traffic rates for each mesh node."""
        return _json_text(service.mesh_traffic_resource())

    @server.resource("deco://wireless/wps")
    def wps_status_resource() -> str:
        """Return the current Wi-Fi Protected Setup session status."""
        return _json_text(service.wps_status_resource())

    @server.resource("deco://reports/monthly/settings")
    def monthly_report_settings_resource() -> str:
        """Return whether monthly report generation is enabled."""
        return _json_text(service.monthly_report_settings_resource())

    @server.resource("deco://reports/monthly")
    def monthly_reports_resource() -> str:
        """Return gated monthly client, parental-control, and security reports."""
        return _json_text(service.monthly_reports_resource())

    @server.resource("deco://notifications")
    def notifications_resource() -> str:
        """Return gated notifications from the Deco message centre."""
        return _json_text(service.notifications_resource())

    @server.resource("deco://speed-test/servers")
    def speed_test_servers_resource() -> str:
        """Return speed-test server selection and inventory."""
        return _json_text(service.speed_test_servers_resource())

    @server.resource("deco://parental-controls")
    def parental_controls_resource() -> str:
        """Return gated parental-control profile policies and schedules."""
        return _json_text(service.parental_controls_resource())

    @server.resource("deco://parental-controls/filter-levels")
    def parental_control_filter_levels_resource() -> str:
        """Return gated default parental-control filtering policies."""
        return _json_text(service.parental_control_filter_levels_resource())

    @server.resource("deco://parental-controls/catalog")
    def parental_control_catalog_resource() -> str:
        """Return the gated website and application filter catalogue."""
        return _json_text(service.parental_control_catalog_resource())

    @server.resource("deco://parental-controls/{owner_id}")
    def parental_control_profile_resource(owner_id: str) -> str:
        """Return one gated parental-control profile policy."""
        return _json_text(service.parental_control_profile_resource(owner_id))

    @server.resource("deco://parental-controls/{owner_id}/insights")
    def parental_control_insights_resource(owner_id: str) -> str:
        """Return gated online-usage insights for one parental-control profile."""
        return _json_text(service.parental_control_insights_resource(owner_id))

    @server.resource("deco://parental-controls/{owner_id}/history")
    def parental_control_history_resource(owner_id: str) -> str:
        """Return gated browsing history for one parental-control profile."""
        return _json_text(service.parental_control_history_resource(owner_id))

    @server.resource("deco://access/permissions")
    def access_permissions_resource() -> str:
        """Return gated manager roles and component-access policies."""
        return _json_text(service.access_permissions_resource())

    @server.resource("deco://devices")
    def devices_resource() -> str:
        """Return every known client device in one normalized representation."""
        return _json_text(service.client_devices_resource("all"))

    @server.resource("deco://devices/active")
    def active_devices_resource() -> str:
        """Return normalized client devices currently reported online."""
        return _json_text(service.client_devices_resource("active"))

    @server.resource("deco://devices/inactive")
    def inactive_devices_resource() -> str:
        """Return normalized known client devices not currently reported online."""
        return _json_text(service.client_devices_resource("inactive"))

    @server.resource("deco://devices/blocked")
    def blocked_devices_resource() -> str:
        """Return normalized client devices present in the block list."""
        return _json_text(service.client_devices_resource("blocked"))

    @server.resource("deco://device-details/{mac}")
    def device_resource(mac: str) -> str:
        """Return optional multi-source enrichment for one client device."""
        return _json_text(service.client_device_resource(mac))

    @server.resource("deco://traffic")
    def traffic_resource() -> str:
        """Return normalized per-device and aggregate traffic speeds."""
        return _json_text(service.traffic_resource())

    @server.resource("deco://address-reservations")
    def address_reservations_resource() -> str:
        """Return the gated live address-reservation table."""
        return _json_text(service.address_reservations_resource())

    @server.resource("deco://network/lan")
    def lan_configuration_resource() -> str:
        """Return the gated semantic LAN addressing configuration."""
        return _json_text(service.lan_configuration_resource())

    @server.resource("deco://network/dhcp")
    def dhcp_configuration_resource() -> str:
        """Return the gated semantic DHCP configuration."""
        return _json_text(service.dhcp_configuration_resource())

    @server.resource("deco://network/qos")
    def qos_resource() -> str:
        """Return the gated semantic QoS mode and bandwidth configuration."""
        return _json_text(service.qos_resource())

    @server.resource("deco://network/vlan")
    def vlan_configuration_resource() -> str:
        """Return the gated semantic Internet VLAN state."""
        return _json_text(service.vlan_configuration_resource())

    @server.resource("deco://network/port-forwarding")
    def port_forwarding_resource() -> str:
        """Return the gated semantic port-forwarding table."""
        return _json_text(service.port_forwarding_resource())

    @server.resource("deco://network/iptv")
    def iptv_configuration_resource() -> str:
        """Return the gated semantic IPTV configuration."""
        return _json_text(service.iptv_configuration_resource())

    @server.resource("deco://network/sip-alg")
    def sip_alg_resource() -> str:
        """Return the gated semantic SIP ALG state."""
        return _json_text(service.sip_alg_resource())

    @server.resource("deco://network/mac-clone")
    def mac_clone_resource() -> str:
        """Return the gated semantic WAN MAC-clone state."""
        return _json_text(service.mac_clone_resource())

    @server.resource("deco://network/ipv4")
    def ipv4_configuration_resource() -> str:
        """Return the gated semantic IPv4 WAN and LAN configuration."""
        return _json_text(service.ipv4_configuration_resource())

    @server.resource("deco://network/ipv6")
    def ipv6_configuration_resource() -> str:
        """Return the gated semantic IPv6 WAN and LAN configuration."""
        return _json_text(service.ipv6_configuration_resource())

    @server.resource("deco://network/ipv6/firewall")
    def ipv6_firewall_resource() -> str:
        """Return the gated semantic IPv6 inbound-firewall rules."""
        return _json_text(service.ipv6_firewall_resource())

    @server.resource("deco://devices/ipv6")
    def ipv6_devices_resource() -> str:
        """Return the gated semantic IPv6 client and neighbor inventory."""
        return _json_text(service.ipv6_devices_resource())

    @server.resource("deco://logs")
    def logs_resource() -> str:
        """Return available log levels without reading log contents."""
        return _json_text(service.logs_resource())

    @server.resource("deco://logs/{index}")
    def system_log_page_resource(index: int) -> str:
        """Return one gated page of system-log entries without preparing a new export."""
        return _json_text(service.system_log_page_resource(index))

    @server.resource("deco://capabilities")
    def capabilities_resource() -> str:
        """Return semantic read capabilities for the connected controller."""
        return _json_text(service.capabilities())

    @server.resource("deco://mutations")
    def mutations_resource() -> str:
        """Return semantic mutation candidates and execution eligibility."""
        return _json_text(service.semantic_mutations())

    @server.resource("deco://diagnostics/transports")
    def transport_capabilities_resource() -> str:
        """Return implemented and catalogued transport coverage."""
        return _json_text(service.transport_capabilities())

    @server.resource("deco://diagnostics/routes")
    def capability_routes_resource() -> str:
        """Return logical capability routes and fallback readiness without router contact."""
        return _json_text(service.capability_routes())

    @server.resource("deco://diagnostics/tmp/opcodes")
    def p9_tmp_opcodes_resource() -> str:
        """Return TMP/AppV2 opcode metadata with exact P9 observations."""
        return _json_text(service.p9_tmp_opcode_catalog())

    @server.resource("deco://diagnostics/tmp/mutations")
    def p9_tmp_mutations_resource() -> str:
        """Return TMP mutation safety evidence and narrowly scoped execution metadata."""
        return _json_text(service.p9_tmp_mutation_inventory())

    @server.resource("deco://diagnostics/coverage")
    def p9_coverage_resource() -> str:
        """Return unified P9 access coverage, call paths, and remaining gaps."""
        return _json_text(service.p9_access_coverage())

    @server.resource("deco://profiles/P9")
    def p9_profile_resource() -> str:
        """Return the bundled value-free P9 compatibility summary."""
        return _json_text(service.p9_profile())

    @server.resource("deco://profiles/P9/operations")
    def p9_operations_resource() -> str:
        """Return model evidence overlaid on every non-secret catalogue operation."""
        return _json_text(service.endpoint_catalog(model="P9"))

    @server.resource("deco://diagnostics/http/mutations")
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
    def deco_get_router_profile(refresh: bool = False) -> str:
        """Resolve the connected controller and mesh-node identities read-only."""
        return _json_text(service.device_inventory(refresh=refresh))

    @server.tool()
    def deco_get_capability(name: str) -> str:
        """Read one logical capability while the server selects and normalizes its protocol."""
        return _json_text(service.read_capability(name))

    @server.tool()
    def deco_plan_mutation(
        name: str,
        changes_json: str = "{}",
        mode: str = "change",
    ) -> str:
        """Plan one semantic mutation and issue a one-shot execution ID only when eligible."""
        return _json_text(
            service.plan_semantic_mutation(
                name,
                _params(changes_json),
                mode=mode,
            )
        )

    @server.tool()
    def deco_execute_mutation(plan_id: str, confirmation: str) -> str:
        """Execute one eligible semantic plan exactly once with no protocol fallback."""
        return _json_text(service.execute_semantic_mutation(plan_id, confirmation))

    @server.tool()
    def deco_plan_capability_mutation(name: str) -> str:
        """Plan one semantic verified no-op offline and report its fixed implementation."""
        return _json_text(service.plan_capability_mutation(name))

    @server.tool()
    def deco_verify_setting_noop(name: str, confirmation: str) -> str:
        """Run one semantic current-value no-op through its fixed verified implementation."""
        return _json_text(service.verify_setting_noop(name, confirmation))

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
    def deco_plan_raw_mutation(
        name: str,
        params_json: str = "{}",
        model: str = "P9",
    ) -> str:
        """Plan one raw endpoint mutation for diagnostic analysis only."""
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

    for tool in server._tool_manager.list_tools():
        if tool.name in _MUTATING_TOOL_NAMES:
            tool.annotations = _MUTATING_TOOL_ANNOTATIONS
        elif tool.name in _STATEFUL_TOOL_NAMES:
            tool.annotations = _STATEFUL_TOOL_ANNOTATIONS
        else:
            tool.annotations = _READ_ONLY_TOOL_ANNOTATIONS
        if tool.name in _PRIMARY_TOOL_NAMES:
            continue
        if tool.name in _RAW_MUTATION_TOOL_NAMES:
            if not effective_config.expose_raw_mutation_tools:
                server._tool_manager.remove_tool(tool.name)
            continue
        if not effective_config.expose_diagnostic_tools:
            server._tool_manager.remove_tool(tool.name)
    if not effective_config.expose_diagnostic_tools:
        for uri in tuple(server._resource_manager._resources):
            if uri not in _PRIMARY_RESOURCE_URIS:
                del server._resource_manager._resources[uri]

    return server


def main() -> None:
    """Run the Deco MCP server over the configured transport."""
    config = ServerConfig.from_env()
    create_server(config).run(transport=config.transport)


if __name__ == "__main__":
    main()
