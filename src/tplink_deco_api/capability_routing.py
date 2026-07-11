"""Protocol-neutral routing registries for Deco reads and scoped mutations."""

from __future__ import annotations

from .http_noop_verification import HTTP_NOOP_CONFIRMATIONS
from .models import CapabilityRoute, MutationCapabilityRoute
from .tmp_monthly_report_noop_verification import TMP_MONTHLY_REPORT_NOOP_CONFIRMATION

CAPABILITY_ROUTES: tuple[CapabilityRoute, ...] = (
    CapabilityRoute(
        name="mesh_nodes",
        description="Mesh node inventory and status",
        sensitivity="private",
        primary_interface="http_luci",
        primary_operation="admin.device.device_list.read",
        fallback_interface="tmp_appv2",
        fallback_operation="0x400F",
        fallback_policy="equivalent_read_only",
        equivalence_evidence="p9_live_schema_equivalence",
    ),
    CapabilityRoute(
        name="clients",
        description="Default mesh client inventory",
        sensitivity="secret",
        primary_interface="http_luci",
        primary_operation="admin.client.client_list.read",
        fallback_interface="tmp_appv2",
        fallback_operation="0x4012",
        fallback_policy="equivalent_read_only",
        equivalence_evidence="p9_live_schema_equivalence",
    ),
    CapabilityRoute(
        name="internet_status",
        description="IPv4, IPv6, and physical link status",
        sensitivity="private",
        primary_interface="http_luci",
        primary_operation="admin.network.internet.read",
        fallback_interface="tmp_appv2",
        fallback_operation="0x400C",
        fallback_policy="equivalent_read_only",
        equivalence_evidence="p9_live_schema_equivalence",
    ),
    CapabilityRoute(
        name="address_reservations",
        description="Static DHCP address reservation table",
        sensitivity="secret",
        primary_interface="http_luci",
        primary_operation="admin.client.addr_reservation.getlist",
        fallback_interface="tmp_appv2",
        fallback_operation="0x40C0",
        fallback_policy="equivalent_read_only",
        equivalence_evidence="p9_live_schema_equivalence",
    ),
    CapabilityRoute(
        name="fast_roaming",
        description="802.11r fast-roaming state",
        sensitivity="normal",
        primary_interface="http_luci",
        primary_operation="admin.wireless.ieee80211r.read",
        fallback_interface="tmp_appv2",
        fallback_operation="0x4208",
        fallback_policy="equivalent_read_only",
        equivalence_evidence="p9_live_boolean_contract",
    ),
    CapabilityRoute(
        name="beamforming",
        description="Wireless beamforming state",
        sensitivity="normal",
        primary_interface="http_luci",
        primary_operation="admin.wireless.beamforming.read",
        fallback_interface="tmp_appv2",
        fallback_operation="0x421B",
        fallback_policy="equivalent_read_only",
        equivalence_evidence="p9_live_boolean_contract",
    ),
)

_CAPABILITY_ROUTES_BY_NAME: dict[str, CapabilityRoute] = {
    route.name: route for route in CAPABILITY_ROUTES
}

MUTATION_CAPABILITY_ROUTES: tuple[MutationCapabilityRoute, ...] = (
    MutationCapabilityRoute(
        name="beamforming",
        description="Verify the current beamforming state with an immediate HTTP no-op",
        interface="http_luci",
        operation="admin.wireless.beamforming.write",
        preflight_operation="admin.wireless.beamforming.read",
        confirmation=HTTP_NOOP_CONFIRMATIONS["admin.wireless.beamforming.write"],
        required_environment_gates=(
            "DECO_MCP_ALLOW_MUTATIONS",
            "DECO_MCP_ALLOW_HTTP_NOOP_VERIFICATION",
        ),
        evidence="p9_live_verified_http_noop",
    ),
    MutationCapabilityRoute(
        name="fast_roaming",
        description="Verify the current 802.11r state with an immediate HTTP no-op",
        interface="http_luci",
        operation="admin.wireless.ieee80211r.write",
        preflight_operation="admin.wireless.ieee80211r.read",
        confirmation=HTTP_NOOP_CONFIRMATIONS["admin.wireless.ieee80211r.write"],
        required_environment_gates=(
            "DECO_MCP_ALLOW_MUTATIONS",
            "DECO_MCP_ALLOW_HTTP_NOOP_VERIFICATION",
        ),
        evidence="p9_live_verified_http_noop",
    ),
    MutationCapabilityRoute(
        name="time_settings",
        description="Verify the current time settings with an immediate HTTP no-op",
        interface="http_luci",
        operation="admin.device.timesetting.write",
        preflight_operation="admin.device.timesetting.read",
        confirmation=HTTP_NOOP_CONFIRMATIONS["admin.device.timesetting.write"],
        required_environment_gates=(
            "DECO_MCP_ALLOW_MUTATIONS",
            "DECO_MCP_ALLOW_HTTP_NOOP_VERIFICATION",
        ),
        evidence="p9_live_verified_http_noop",
    ),
    MutationCapabilityRoute(
        name="monthly_report",
        description="Verify the current monthly-report state with an immediate TMP no-op",
        interface="tmp_appv2",
        operation="0x4223",
        preflight_operation="0x4222",
        confirmation=TMP_MONTHLY_REPORT_NOOP_CONFIRMATION,
        required_environment_gates=(
            "DECO_MCP_ALLOW_MUTATIONS",
            "DECO_MCP_ALLOW_TMP_READS",
            "DECO_MCP_ALLOW_TMP_NOOP_VERIFICATION",
        ),
        evidence="p9_live_verified_tmp_noop",
    ),
)

_MUTATION_CAPABILITY_ROUTES_BY_NAME: dict[str, MutationCapabilityRoute] = {
    route.name: route for route in MUTATION_CAPABILITY_ROUTES
}


def get_capability_route(name: str) -> CapabilityRoute:
    """Return one logical route by exact stable capability name."""
    try:
        return _CAPABILITY_ROUTES_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"Unknown Deco capability: {name}") from exc


def get_mutation_capability_route(name: str) -> MutationCapabilityRoute:
    """Return one fixed mutation route by exact stable capability name."""
    try:
        return _MUTATION_CAPABILITY_ROUTES_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"Unknown Deco mutation capability: {name}") from exc
