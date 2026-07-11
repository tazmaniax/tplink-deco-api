"""Protocol-neutral routing registry for proven equivalent Deco reads."""

from __future__ import annotations

from .models import CapabilityRoute

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


def get_capability_route(name: str) -> CapabilityRoute:
    """Return one logical route by exact stable capability name."""
    try:
        return _CAPABILITY_ROUTES_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"Unknown Deco capability: {name}") from exc
