"""Transport-neutral safety boundary over the Deco SDK."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, cast

from .._json import get_bool, get_int, get_str
from ..capability_routing import (
    CAPABILITY_ROUTES,
    MUTATION_CAPABILITY_ROUTES,
    get_capability_route,
    get_mutation_capability_route,
)
from ..client import DecoClient
from ..endpoint_catalog import (
    CATALOG_VERSION,
    ENDPOINT_CATALOG,
    P9_MUTATION_CANDIDATES,
    P9_PROFILE_FIRMWARE,
    P9_PROFILE_HARDWARE_VERSIONS,
    P9_PROFILE_OBSERVED_AT,
    get_endpoint,
)
from ..exceptions import (
    ApiError,
    ConfirmationError,
    ControllerChangedError,
    DecoError,
    ExpiredPlanError,
    TransportError,
    UnknownPlanError,
)
from ..http_mutation_verification import (
    _HTTP_LIVE_PREFLIGHT_NAMES,
    build_http_mutation_verification_queue,
)
from ..http_noop_verification import (
    HTTP_NOOP_CONFIRMATIONS,
    HTTP_NOOP_PREFLIGHT_OPERATIONS,
    verify_http_setting_noop,
)
from ..model_compatibility import (
    P9_COMPATIBILITY_PROFILE,
    P9_SENSITIVE_SCHEMA_ENDPOINTS,
    SENSITIVE_SCHEMA_ENDPOINTS,
    get_compatibility_profile,
)
from ..models import (
    AddressReservationTable,
    ClientDevice,
    CompatibilityManifest,
    Device,
    InternetStatus,
    NodeClientList,
    SpeedTest,
)
from ..mutation_planner import build_mutation_plan
from ..tmp_client import DecoTmpClient
from ..tmp_mutation_planner import build_tmp_mutation_plan
from ..tmp_mutation_verification import build_tmp_mutation_verification_queue
from ..tmp_opcode_catalog import TMP_OPCODE_CATALOG, get_tmp_opcode
from ..tmp_read_contract_probe import probe_tmp_read_contracts
from ..tmp_ssh_config import TmpSshConfig
from ..tmp_unverified_read_probe import probe_tmp_unverified_reads
from ._client_read_normalization import normalize_blocked_clients, normalize_client_traffic
from ._device_inventory_resolution import _DeviceInventoryResolution
from ._firmware_normalization import (
    normalize_http_firmware_status,
    normalize_tmp_firmware_status,
)
from ._ipv6_normalization import (
    normalize_ipv6_clients,
    normalize_ipv6_configuration,
    normalize_ipv6_firewall,
)
from ._network_normalization import (
    normalize_bandwidth_configuration,
    normalize_dhcp_configuration,
    normalize_http_ipv4_configuration,
    normalize_iptv_configuration,
    normalize_lan_configuration,
    normalize_mac_clone,
    normalize_port_forwarding,
    normalize_qos_mode,
    normalize_sip_alg,
    normalize_tmp_ipv4_configuration,
    normalize_vlan_configuration,
)
from ._pending_mutation_plan import _PendingMutationPlan
from ._resource_read_context import _ResourceReadContext
from ._system_normalization import normalize_led_configuration
from ._wlan_normalization import (
    normalize_http_wireless_bridge,
    normalize_http_wireless_operation_mode,
    normalize_http_wlan_configuration,
    normalize_tmp_wireless_bridge,
    normalize_tmp_wireless_operation_mode,
    normalize_tmp_wlan_configuration,
)

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue
    from ..endpoint_spec import EndpointSpec
    from ..models import (
        ApiResponse,
        BinaryResponse,
        CapabilityReport,
        CapabilityRoute,
        EndpointObservation,
        IpInfo,
        MutationPlan,
        TmpOpcodeSpec,
    )
    from ..models.capability_route import CapabilityInterface
    from ..server.config import ServerConfig

_P9_BINARY_READ_NAMES: tuple[str, ...] = (
    "admin.firmware.config.backup",
    "admin.firmware.config_multipart.backup",
    "admin.log_export.save_log.download",
)
_TMP_PARAMETER_SOURCE_OPCODES: tuple[int, ...] = (0x4012, 0x4029, 0x4060)
_TMP_OWNER_PARAMETERIZED_OPCODES: frozenset[int] = frozenset({0x402D, 0x402F, 0x4031})
_WIRELESS_FEATURE_CAPABILITIES: tuple[tuple[str, str], ...] = (
    ("operation_mode", "wireless_operation_mode"),
    ("bridge", "wireless_bridge"),
    ("fast_roaming", "fast_roaming"),
    ("beamforming", "beamforming"),
)
_SEMANTIC_MUTATION_OPERATIONS: dict[str, tuple[str, ...]] = {
    "wan_mode": ("admin.network.wan_mode.write",),
    "lan_ip": ("admin.network.lan_ip.write",),
    "vlan": ("admin.network.vlan.write", "admin.network.vlan.set_vlan"),
    "mac_clone": ("admin.network.mac_clone.write",),
    "wireless_operation_mode": ("admin.wireless.operation_mode.write",),
    "fast_roaming": ("admin.wireless.ieee80211r.write",),
    "beamforming": ("admin.wireless.beamforming.write",),
    "remove_device": ("admin.device.device_list.remove",),
    "speed_test_start": ("admin.device.speedtest.write",),
    "speed_test_stop": ("admin.device.speedtest.stop",),
    "time_settings": ("admin.device.timesetting.write", "admin.device.timesetting.gmt"),
    "language": ("locale.lang.write",),
    "country": ("locale.country.write",),
    "block_client": ("admin.client.black_list.add",),
    "unblock_client": ("admin.client.black_list.remove",),
    "address_reservation_add": ("admin.client.addr_reservation.add",),
    "address_reservation_modify": ("admin.client.addr_reservation.modify",),
    "address_reservation_remove": ("admin.client.addr_reservation.remove",),
    "nickname": ("admin.cloud.nickname.write",),
    "firmware_upgrade": (
        "admin.cloud.firmware_status.upgrade",
        "admin.cloud.firmware_status.local_upgrade",
    ),
    "system_log_prepare": ("admin.log_export.feedback_log.build",),
    "monthly_report": (),
}
_SEMANTIC_MUTATION_DESCRIPTIONS: dict[str, str] = {
    "wan_mode": "Change the WAN operating mode",
    "lan_ip": "Change the LAN IP configuration",
    "vlan": "Change the internet VLAN configuration",
    "mac_clone": "Change WAN MAC-clone configuration",
    "wireless_operation_mode": "Change the wireless operation mode",
    "fast_roaming": "Change 802.11r fast roaming",
    "beamforming": "Change wireless beamforming",
    "remove_device": "Remove a Deco node from the mesh",
    "speed_test_start": "Start the built-in speed test",
    "speed_test_stop": "Stop the built-in speed test",
    "time_settings": "Change timezone and regional time settings",
    "language": "Change the router interface language",
    "country": "Change the router country setting",
    "block_client": "Add a client to the block list",
    "unblock_client": "Remove a client from the block list",
    "address_reservation_add": "Add an address reservation",
    "address_reservation_modify": "Modify an address reservation",
    "address_reservation_remove": "Remove an address reservation",
    "nickname": "Change the mesh nickname",
    "firmware_upgrade": "Start a firmware upgrade",
    "system_log_prepare": "Prepare a paginated system-log snapshot for one level",
    "monthly_report": "Change monthly-report generation",
}
_SEMANTIC_MUTATION_CATEGORIES: dict[str, str] = {
    "wan_mode": "network",
    "lan_ip": "network",
    "vlan": "network",
    "mac_clone": "network",
    "wireless_operation_mode": "wireless",
    "fast_roaming": "wireless",
    "beamforming": "wireless",
    "remove_device": "mesh",
    "speed_test_start": "diagnostics",
    "speed_test_stop": "diagnostics",
    "time_settings": "system",
    "language": "system",
    "country": "system",
    "block_client": "clients",
    "unblock_client": "clients",
    "address_reservation_add": "clients",
    "address_reservation_modify": "clients",
    "address_reservation_remove": "clients",
    "nickname": "mesh",
    "firmware_upgrade": "firmware",
    "system_log_prepare": "diagnostics",
    "monthly_report": "reporting",
}
_SEMANTIC_PLAN_TTL_SECONDS = 300.0
_LIVE_READ_ERRORS = (DecoError, OSError, TimeoutError, ValueError)


class DecoService:
    """Authorize semantic operations and reuse one authenticated router session."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config
        self._client: DecoClient | None = None
        self._tmp_client: DecoTmpClient | None = None
        self._device_cache: tuple[Device, ...] | None = None
        self._device_resolution: _DeviceInventoryResolution | None = None
        self._pending_mutation_plans: dict[str, _PendingMutationPlan] = {}
        self._http_mutation_latched = False
        self._tmp_mutation_latched = False
        self._lock = threading.RLock()

    def close(self) -> None:
        """Close the shared router session, if one was opened."""
        with self._lock:
            client, self._client = self._client, None
            tmp_client, self._tmp_client = self._tmp_client, None
            self._device_cache = None
            self._device_resolution = None
            self._pending_mutation_plans.clear()
            try:
                if client is not None:
                    client.logout()
            finally:
                if tmp_client is not None:
                    tmp_client.close()

    def public_status(self) -> dict[str, JsonValue]:
        """Return non-secret server configuration and connection state."""
        status = self._config.public_settings()
        status["authenticated"] = self._client is not None and self._client.is_authenticated()
        status["tmp_connected"] = self._tmp_client is not None and self._tmp_client.connected
        status["http_mutation_latched"] = self._http_mutation_latched
        status["tmp_mutation_latched"] = self._tmp_mutation_latched
        status["catalogued_operations"] = len(ENDPOINT_CATALOG)
        status["schema_version"] = 1
        status["identity_resolved"] = self._device_cache is not None
        status["pending_mutation_plan_count"] = len(self._pending_mutation_plans)
        return status

    def device_inventory(self, *, refresh: bool = False) -> dict[str, JsonValue]:
        """Return connected Deco identities and cache the controller profile."""
        router_contacted = False
        with self._lock:
            if refresh or self._device_cache is None:
                resolution = self._resolve_device_inventory()
                self._device_cache = resolution.devices
                self._device_resolution = resolution
                router_contacted = True
            devices = self._device_cache
            resolution = self._device_resolution or _DeviceInventoryResolution(
                devices=devices,
                source_interface="http_luci",
                source_operation="admin.device.device_list.read",
                attempts=(),
                fallback_used=False,
            )
        controller = _controller_device(devices)
        profile_match = _profile_match(controller)
        return {
            "schema_version": 1,
            "resolution_status": "resolved",
            "controller": _device_view(controller),
            "nodes": [_device_view(device) for device in devices],
            "node_count": len(devices),
            "mixed_model_mesh": len({device.device_model for device in devices}) > 1,
            "identity_source": resolution.source_operation,
            "identity_interface": resolution.source_interface,
            "identity_attempts": [dict(attempt) for attempt in resolution.attempts],
            "fallback_used": resolution.fallback_used,
            "profile_match": profile_match,
            "profile_name": "P9" if profile_match in {"exact", "model_only"} else None,
            "cached": not router_contacted,
            "router_contacted": router_contacted,
            "mutation_invoked": False,
        }

    def _resolve_device_inventory(self) -> _DeviceInventoryResolution:
        route = get_capability_route("mesh_nodes")
        attempts: list[JsonObject] = []
        try:
            devices = self._read_http_device_inventory()
        except (TransportError, ValueError) as primary_error:
            attempts.append(
                {
                    "interface": route.primary_interface,
                    "operation": route.primary_operation,
                    "status": "error",
                    "error_type": type(primary_error).__name__,
                }
            )
            if not self._tmp_identity_bootstrap_available():
                raise
            try:
                devices = self._read_tmp_device_inventory()
            except (DecoError, OSError, TimeoutError, ValueError) as fallback_error:
                raise fallback_error from primary_error
            if route.fallback_interface is None:
                raise ValueError(
                    "Failed to resolve controller identity: fallback is missing"
                ) from primary_error
            attempts.append(
                {
                    "interface": route.fallback_interface,
                    "operation": route.fallback_operation,
                    "status": "ok",
                }
            )
            return _DeviceInventoryResolution(
                devices=devices,
                source_interface=route.fallback_interface,
                source_operation=route.fallback_operation,
                attempts=tuple(attempts),
                fallback_used=True,
            )
        attempts.append(
            {
                "interface": route.primary_interface,
                "operation": route.primary_operation,
                "status": "ok",
            }
        )
        return _DeviceInventoryResolution(
            devices=devices,
            source_interface=route.primary_interface,
            source_operation=route.primary_operation,
            attempts=tuple(attempts),
            fallback_used=False,
        )

    def _read_http_device_inventory(self) -> tuple[Device, ...]:
        devices = tuple(self._get_client().get_device_list())
        _validate_device_inventory(devices)
        return devices

    def _read_tmp_device_inventory(self) -> tuple[Device, ...]:
        payload = self.tmp_read(0x400F)
        result = payload.get("result")
        if not isinstance(result, Mapping):
            raise ValueError("Failed to resolve controller identity: TMP result is not an object")
        devices = tuple(Device.from_api(row) for row in _mapping_rows(result, "device_list"))
        _validate_device_inventory(devices)
        return devices

    def _tmp_identity_bootstrap_available(self) -> bool:
        return (
            self._config.allow_tmp_reads
            and bool(self._config.tp_link_id)
            and bool(self._config.password)
            and bool(self._config.tmp_host_key_sha256)
        )

    def _interface_configured(self, interface: CapabilityInterface) -> bool:
        if interface == "http_luci":
            return bool(self._config.password)
        return bool(
            self._config.tp_link_id and self._config.password and self._config.tmp_host_key_sha256
        )

    def _interface_connected(self, interface: CapabilityInterface) -> bool:
        if interface == "http_luci":
            return self._client is not None and self._client.is_authenticated()
        return self._tmp_client is not None and self._tmp_client.connected

    def _capability_gate_enabled(self, route: CapabilityRoute) -> bool:
        return (route.primary_interface != "tmp_appv2" or self._config.allow_tmp_reads) and (
            route.sensitivity != "secret" or self._config.allow_sensitive_reads
        )

    def capabilities(self) -> dict[str, JsonValue]:
        """Return semantic read capabilities for the connected controller."""
        inventory = self.device_inventory()
        profile_match = _json_string(inventory, "profile_match")
        capabilities: list[dict[str, JsonValue]] = []
        for route in CAPABILITY_ROUTES:
            support_status = "supported" if profile_match == "exact" else "unverified"
            reason = "" if profile_match == "exact" else "no exact model and firmware profile"
            related_mutations = [route.name] if route.name in _SEMANTIC_MUTATION_OPERATIONS else []
            capabilities.append(
                {
                    "name": route.name,
                    "description": route.description,
                    "category": _capability_category(route.name),
                    "sensitivity": route.sensitivity,
                    "support_status": support_status,
                    "readable": True,
                    "source_configured": self._interface_configured(route.primary_interface),
                    "source_connected": self._interface_connected(route.primary_interface),
                    "runtime_gate_enabled": self._capability_gate_enabled(route),
                    "mutable": bool(related_mutations),
                    "read_operation": "get_capability",
                    "related_mutations": related_mutations,
                    "evidence_level": route.equivalence_evidence
                    if profile_match == "exact"
                    else "unknown",
                    "reason_unavailable": reason,
                }
            )
        counts = Counter(item["support_status"] for item in capabilities)
        return {
            "schema_version": 1,
            "resolution_status": inventory["resolution_status"],
            "controller": inventory["controller"],
            "profile_match": profile_match,
            "capabilities": capabilities,
            "supported_count": counts["supported"],
            "unknown_count": counts["unverified"],
            "unsupported_count": counts["unsupported"],
            "router_contacted": inventory["router_contacted"],
            "mutation_invoked": False,
        }

    def semantic_mutations(self) -> dict[str, JsonValue]:
        """Return every known semantic mutation and its current execution status."""
        inventory = self.device_inventory()
        profile_match = _json_string(inventory, "profile_match")
        mutations = [
            self._semantic_mutation_entry(name, operations, profile_match)
            for name, operations in _SEMANTIC_MUTATION_OPERATIONS.items()
        ]
        execution_counts: Counter[str] = Counter()
        for mutation in mutations:
            execution_status = mutation["execution_status"]
            if isinstance(execution_status, str):
                execution_counts[execution_status] += 1
        return {
            "schema_version": 1,
            "resolution_status": inventory["resolution_status"],
            "controller": inventory["controller"],
            "profile_match": profile_match,
            "mutations": mutations,
            "candidate_count": len(mutations),
            "execution_counts": dict(sorted(execution_counts.items())),
            "mutation_gate_status": {
                "ordinary": self._config.allow_mutations,
                "destructive": self._config.allow_destructive,
                "internal": self._config.allow_internal,
                "http_noop": self._config.allow_http_noop_verification,
                "tmp_noop": self._config.allow_tmp_noop_verification,
                "tmp_writes_hard_disabled": True,
            },
            "router_contacted": inventory["router_contacted"],
            "mutation_invoked": False,
        }

    def semantic_mutation(self, name: str) -> dict[str, JsonValue]:
        """Return one semantic mutation candidate without building the full catalogue."""
        try:
            operations = _SEMANTIC_MUTATION_OPERATIONS[name]
        except KeyError as exc:
            raise ValueError(
                f"Failed to read semantic mutation: unknown mutation {name!r}"
            ) from exc
        inventory = self.device_inventory()
        return self._semantic_mutation_entry(
            name,
            operations,
            _json_string(inventory, "profile_match"),
        )

    def _semantic_mutation_entry(
        self,
        name: str,
        operations: tuple[str, ...],
        profile_match: str,
    ) -> dict[str, JsonValue]:
        route = next((item for item in MUTATION_CAPABILITY_ROUTES if item.name == name), None)
        endpoints = tuple(get_endpoint(operation) for operation in operations)
        compatibilities = (
            tuple(P9_COMPATIBILITY_PROFILE.get(operation) for operation in operations)
            if profile_match in {"exact", "model_only"}
            else ()
        )
        scopes = {compatibility.mutation_test_scope for compatibility in compatibilities}
        tmp_safety_not_established = name == "monthly_report" and profile_match in {
            "exact",
            "model_only",
        }
        if tmp_safety_not_established:
            validation_status = "safety_not_established"
        elif "general" in scopes:
            validation_status = "general_verified"
        elif "noop_only" in scopes or route is not None:
            validation_status = "noop_verified"
        else:
            validation_status = "unverified"
        gates = list(route.required_environment_gates) if route is not None else []
        gate_status = {gate: self._mutation_gate_enabled(gate) for gate in gates}
        exact_route = route is not None and profile_match == "exact"
        execution_scope = "noop_only" if exact_route else "none"
        if not exact_route:
            execution_status = "blocked"
        elif all(gate_status.values()):
            execution_status = "ready"
        else:
            execution_status = "gated"
        blockers: list[str] = []
        if profile_match != "exact":
            blockers.append("no exact connected model, hardware, and firmware profile")
        if route is None:
            blockers.append("no complete verified semantic execution route")
        elif route is not None and validation_status != "general_verified":
            blockers.append("state-changing behavior has not been validated")
        blockers.extend(
            f"{gate} is disabled" for gate, enabled in gate_status.items() if not enabled
        )
        if tmp_safety_not_established:
            blockers.append(
                "TMP current-value write passed immediate verification only; operational "
                "safety is not established"
            )
        required = sorted({key for endpoint in endpoints for key in endpoint.required_params})
        optional = sorted({key for endpoint in endpoints for key in endpoint.optional_params})
        if name == "monthly_report":
            required = ["enable"]
        risks: set[str] = {endpoint.safety for endpoint in endpoints} or {"mutation"}
        sensitivities: set[str] = {endpoint.sensitivity for endpoint in endpoints} or {"normal"}
        return {
            "name": name,
            "description": _SEMANTIC_MUTATION_DESCRIPTIONS[name],
            "category": _SEMANTIC_MUTATION_CATEGORIES[name],
            "risk": _highest_risk(risks),
            "sensitivity": _highest_sensitivity(sensitivities),
            "scope": "mesh" if name not in {"remove_device"} else "node",
            "changes_schema": {"required": required, "optional": optional},
            "support_status": "supported" if profile_match == "exact" else "unverified",
            "validation_status": validation_status,
            "execution_scope": execution_scope,
            "execution_status": execution_status,
            "required_gates": gates,
            "confirmation_required": exact_route,
            "preflight_available": bool(route and route.preflight_operation),
            "verification_available": exact_route,
            "rollback_available": exact_route,
            "plan_operation": "plan_mutation",
            "execute_operation": "execute_mutation" if exact_route else None,
            "blockers": blockers,
        }

    def address_reservations_resource(self) -> dict[str, JsonValue]:
        """Return the live address-reservation table through the semantic read path."""
        result = self.read_capability("address_reservations")
        result["router_contacted"] = True
        return result

    def ipv4_configuration_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic IPv4 WAN and LAN configuration."""
        return self._semantic_capability_resource("ipv4_configuration", "IPv4 configuration")

    def led_configuration_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic system LED and night-mode state."""
        return self._semantic_capability_resource("led_configuration", "LED configuration")

    def ipv6_configuration_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic IPv6 WAN and LAN configuration."""
        return self._semantic_capability_resource("ipv6_configuration", "IPv6 configuration")

    def ipv6_firewall_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic IPv6 inbound-firewall rule table."""
        return self._semantic_capability_resource("ipv6_firewall", "IPv6 firewall")

    def ipv6_devices_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic IPv6 client and neighbor inventory."""
        return self._semantic_capability_resource("ipv6_clients", "IPv6 clients")

    def lan_configuration_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic LAN addressing configuration."""
        return self._semantic_capability_resource("lan_configuration", "LAN configuration")

    def dhcp_configuration_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic DHCP configuration."""
        return self._semantic_capability_resource("dhcp_configuration", "DHCP configuration")

    def qos_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic QoS mode and bandwidth configuration."""
        mode_capability = self.read_capability("qos_mode")
        bandwidth_capability = self.read_capability("bandwidth_configuration")
        mode, mode_provenance = _capability_resource_parts(mode_capability, "QoS mode")
        bandwidth, bandwidth_provenance = _capability_resource_parts(
            bandwidth_capability,
            "bandwidth configuration",
        )
        mode_interface = _json_string(mode_provenance, "source_interface")
        bandwidth_interface = _json_string(bandwidth_provenance, "source_interface")
        if mode_interface != bandwidth_interface:
            raise ValueError("Failed to read QoS: capability sources do not match")
        return {
            "schema_version": 1,
            "status": "available",
            "mode": dict(mode),
            "bandwidth": dict(bandwidth),
            "provenance": {
                "source_interface": mode_interface,
                "source_operations": [
                    _json_string(mode_provenance, "source_operation"),
                    _json_string(bandwidth_provenance, "source_operation"),
                ],
                "single_source_interface": True,
                "capabilities": {
                    "qos_mode": dict(mode_provenance),
                    "bandwidth_configuration": dict(bandwidth_provenance),
                },
            },
            "observed_at_epoch_seconds": time.time(),
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def vlan_configuration_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic Internet VLAN state."""
        return self._semantic_capability_resource("vlan_configuration", "VLAN configuration")

    def port_forwarding_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic port-forwarding table."""
        return self._semantic_capability_resource("port_forwarding", "port forwarding")

    def iptv_configuration_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic IPTV configuration."""
        return self._semantic_capability_resource("iptv_configuration", "IPTV configuration")

    def sip_alg_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic SIP ALG state."""
        return self._semantic_capability_resource("sip_alg", "SIP ALG")

    def mac_clone_resource(self) -> dict[str, JsonValue]:
        """Return the gated semantic WAN MAC-clone state."""
        return self._semantic_capability_resource("mac_clone", "MAC clone")

    def _semantic_capability_resource(
        self,
        name: str,
        dataset: str,
    ) -> dict[str, JsonValue]:
        capability = self.read_capability(name)
        data, provenance = _capability_resource_parts(capability, dataset)
        return {
            "schema_version": 1,
            "status": "available",
            **dict(data),
            "provenance": dict(provenance),
            "observed_at_epoch_seconds": time.time(),
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def client_devices_resource(self, view: str = "all") -> dict[str, JsonValue]:
        """Return one normalized live device view from every known client source."""
        valid_views = {"all", "active", "inactive", "blocked"}
        if view not in valid_views:
            raise ValueError(f"Failed to read client devices: unknown view {view!r}")
        capability = self.read_capability("clients")
        provenance = capability.get("provenance")
        if not isinstance(provenance, Mapping):
            raise ValueError("Failed to read client devices: provenance is not an object")
        source_interface = _json_string(provenance, "source_interface")
        errors: list[dict[str, JsonValue]] = []
        node_clients: tuple[NodeClientList, ...] = ()
        blocked_data: JsonValue = None
        traffic_data: JsonValue = None
        reservation_rows: tuple[JsonObject, ...] = ()
        if source_interface == "http_luci":
            try:
                node_clients = self.get_clients_by_node()
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("clients_by_node", exc))
            try:
                blocked_data = self._read_http_capability("blocked_clients")
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("blocked_devices", exc))
            try:
                traffic_data = self._read_http_capability("traffic")
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("device_speeds", exc))
            with self._lock:
                try:
                    reservations = self._get_client().get_address_reservations()
                    reservation_rows = tuple(
                        {"mac": reservation.mac, "ip": reservation.ip}
                        for reservation in reservations.reservations
                    )
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("address_reservations", exc))
        elif source_interface == "tmp_appv2":
            errors.append(_source_unavailable("clients_by_node"))
            try:
                blocked_data = self._read_tmp_capability("blocked_clients")
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("blocked_devices", exc))
            try:
                traffic_data = self._read_tmp_capability("traffic")
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("device_speeds", exc))
            try:
                reservation_data = self._read_tmp_capability("address_reservations")
                if isinstance(reservation_data, Mapping):
                    reservation_rows = _mapping_rows(reservation_data, "entries")
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("address_reservations", exc))
        else:
            raise ValueError("Failed to read client devices: unknown source interface")

        records: dict[str, dict[str, JsonValue]] = {}
        client_rows = _json_rows(capability.get("data"))
        for row in client_rows:
            _merge_client_device(records, _normalized_client_device(row), "client_list")
        for node in node_clients:
            for client_device in node.clients:
                _merge_client_device(
                    records,
                    client_device,
                    "clients_by_node",
                    connected_node=node.node_mac,
                )
        if isinstance(blocked_data, Mapping):
            for row in _mapping_rows(blocked_data, "devices"):
                _merge_blocked_device(records, _normalized_client_device(row))
        if isinstance(traffic_data, Mapping):
            for row in _mapping_rows(traffic_data, "device_speeds"):
                _merge_device_speed(records, row)
        for reservation in reservation_rows:
            _merge_reserved_device(
                records,
                get_str(reservation, "mac"),
                get_str(reservation, "ip"),
            )

        devices = sorted(
            (record for record in records.values() if _device_record_matches_view(record, view)),
            key=lambda record: _record_string(record, "mac"),
        )
        return {
            "schema_version": 1,
            "view": view,
            "devices": devices,
            "device_count": len(devices),
            "all_device_count": len(records),
            "source_counts": {
                "client_list": len(client_rows),
                "node_client_assignments": sum(len(node.clients) for node in node_clients),
                "blocked_devices": len(_mapping_rows(blocked_data, "devices"))
                if isinstance(blocked_data, Mapping)
                else 0,
                "device_speeds": len(_mapping_rows(traffic_data, "device_speeds"))
                if isinstance(traffic_data, Mapping)
                else 0,
                "address_reservations": len(reservation_rows),
            },
            "provenance": provenance,
            "unavailable_sections": errors,
            "observed_at_epoch_seconds": time.time(),
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def traffic_resource(self) -> dict[str, JsonValue]:
        """Return normalized current per-device and aggregate traffic speeds."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read traffic: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        try:
            capability = self.read_capability("traffic")
            data, provenance = _capability_resource_parts(capability, "traffic")
        except _LIVE_READ_ERRORS as exc:
            return {
                "schema_version": 1,
                "device_speeds": [],
                "device_count": 0,
                "aggregate_speed": {"up_speed": 0, "down_speed": 0},
                "status": "unavailable",
                "provenance": None,
                "unavailable_sections": [_configuration_error("device_speeds", exc)],
                "observed_at_epoch_seconds": time.time(),
                "router_contacted": True,
                "mutation_invoked": False,
            }
        return {
            "schema_version": 1,
            **dict(data),
            "status": "available",
            "provenance": dict(provenance),
            "unavailable_sections": [],
            "observed_at_epoch_seconds": time.time(),
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def logs_resource(self) -> dict[str, JsonValue]:
        """Return log levels and preparation metadata without reading log contents."""
        categories: list[dict[str, JsonValue]] = []
        errors: list[dict[str, JsonValue]] = []
        with self._lock:
            try:
                categories = [
                    {"name": item.name, "value": item.value}
                    for item in self._get_client().get_log_types()
                ]
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("categories", exc))
        return {
            "schema_version": 1,
            "categories": categories,
            "category_count": len(categories),
            "selector_field": "level",
            "web_ui_default_level": 5,
            "all_level": next(
                (item["value"] for item in categories if item["name"] == "ALL"),
                None,
            ),
            "preparation_mutation": "system_log_prepare",
            "status": "available" if not errors else "unavailable",
            "unavailable_sections": errors,
            "log_contents_included": False,
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def system_log_page_resource(
        self,
        index: int,
        limit: int = 100,
    ) -> dict[str, JsonValue]:
        """Return one explicitly enabled page from the prepared system-log snapshot."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read system log: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        if not self._config.allow_bulk_secret_reads:
            raise PermissionError(
                "Failed to read system log: DECO_ALLOW_BULK_SECRET_READS=1 is required"
            )
        if index < 0:
            raise ValueError("Failed to read system log: index must be non-negative")
        if not 1 <= limit <= 100:
            raise ValueError("Failed to read system log: limit must be between 1 and 100")
        with self._lock:
            page = self._get_client().get_system_log(index=index, limit=limit)
        return {
            "schema_version": 1,
            "current_index": page.current_index,
            "total_pages": page.total_pages,
            "page_size": limit,
            "entries": [entry.to_dict() for entry in page.entries],
            "entry_count": len(page.entries),
            "log_contents_included": True,
            "prepared_level": None,
            "level_reported_by_firmware": False,
            "preparation_mutation": "system_log_prepare",
            "source_interface": "http_luci",
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def network_status_resource(self) -> dict[str, JsonValue]:
        """Return a sanitized live health summary without client identities or secrets."""
        inventory = self.device_inventory(refresh=True)
        context = _resource_read_context(inventory)
        devices = self._device_cache or ()
        controller = _controller_device(devices)
        online_nodes = tuple(device for device in devices if _device_is_online(device))
        offline_node_count = len(devices) - len(online_nodes)
        weak_signal_node_count = sum(_device_has_weak_wireless_signal(device) for device in devices)
        backhaul_counts = Counter(
            connection_type for device in devices for connection_type in device.connection_type
        )
        errors: list[dict[str, JsonValue]] = []
        warnings: list[dict[str, JsonValue]] = []
        internet: JsonValue = None
        performance: JsonValue = None
        firmware: JsonValue = None
        speed_test: JsonValue = None
        client_count: JsonValue = None
        client_count_status = "gated"
        try:
            internet_capability = self.read_capability("internet_status")
            internet = internet_capability.get("data")
            context = _capability_read_context(internet_capability, inventory)
        except _LIVE_READ_ERRORS as exc:
            errors.append(_configuration_error("internet", exc))
        if context.interface == "http_luci":
            with self._lock:
                client = self._get_client()
                try:
                    observed_performance = client.get_performance()
                    performance = {
                        "cpu_usage": observed_performance.cpu_usage,
                        "memory_usage": observed_performance.mem_usage,
                    }
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("performance", exc))
                try:
                    firmware = self._read_resource_capability("firmware_status", context)
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("firmware", exc))
                try:
                    speed_test = self._read_resource_capability("speed_test", context)
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("speed_test", exc))
                if self._config.allow_sensitive_reads:
                    try:
                        client_count = len(
                            _json_rows(self._read_resource_capability("clients", context))
                        )
                        client_count_status = "available"
                    except _LIVE_READ_ERRORS as exc:
                        client_count_status = "unavailable"
                        errors.append(_configuration_error("client_count", exc))
        else:
            errors.append(_source_unavailable("performance"))
            try:
                firmware = self._read_resource_capability("firmware_status", context)
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("firmware", exc))
            try:
                speed_test = self._read_resource_capability("speed_test", context)
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("speed_test", exc))
            if self._config.allow_sensitive_reads:
                try:
                    client_count = len(
                        _json_rows(self._read_resource_capability("clients", context))
                    )
                    client_count_status = "available"
                except _LIVE_READ_ERRORS as exc:
                    client_count_status = "unavailable"
                    errors.append(_configuration_error("client_count", exc))

        if offline_node_count:
            warnings.append(
                _network_warning(
                    "mesh_nodes_offline",
                    f"{offline_node_count} mesh node(s) appear offline",
                )
            )
        if weak_signal_node_count:
            warnings.append(
                _network_warning(
                    "weak_wireless_backhaul",
                    f"{weak_signal_node_count} mesh node(s) report weak wireless backhaul",
                )
            )
        if isinstance(internet, Mapping) and not _internet_is_online(internet):
            warnings.append(_network_warning("internet_offline", "Internet connectivity is down"))
        if isinstance(performance, Mapping):
            if _numeric_value(performance.get("cpu_usage")) >= 0.9:
                warnings.append(_network_warning("high_cpu_usage", "Gateway CPU usage is high"))
            if _numeric_value(performance.get("memory_usage")) >= 0.9:
                warnings.append(
                    _network_warning("high_memory_usage", "Gateway memory usage is high")
                )
        if errors:
            warnings.append(
                _network_warning(
                    "partial_data",
                    f"{len(errors)} live status section(s) could not be read",
                )
            )

        return {
            "schema_version": 1,
            "status": "healthy" if not warnings else "degraded",
            "controller": {
                "model": controller.device_model,
                "role": controller.role,
                "hardware_version": controller.hardware_ver,
                "software_version": controller.software_ver,
                "internet_status": controller.inet_status,
                "group_status": controller.group_status,
            },
            "internet": internet,
            "mesh": {
                "total_nodes": len(devices),
                "online_nodes": len(online_nodes),
                "offline_nodes": offline_node_count,
                "controller_online": _device_is_online(controller),
                "mixed_model_mesh": inventory["mixed_model_mesh"],
                "backhaul_type_counts": dict(sorted(backhaul_counts.items())),
                "weak_signal_nodes": weak_signal_node_count,
            },
            "performance": performance,
            "firmware": firmware,
            "speed_test": speed_test,
            "client_count": client_count,
            "client_count_status": client_count_status,
            "provenance": context.provenance(),
            "warnings": warnings,
            "unavailable_sections": errors,
            "observed_at_epoch_seconds": time.time(),
            "passwords_included": False,
            "client_identities_included": False,
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def configuration_resource(self) -> dict[str, JsonValue]:
        """Return a sanitized live configuration overview without secret datasets."""
        inventory = self.device_inventory()
        context = _resource_read_context(inventory)
        sections: dict[str, JsonValue] = {}
        errors: list[dict[str, JsonValue]] = []
        nickname: JsonValue = None
        nickname_status = "gated"
        try:
            internet_capability = self.read_capability("internet_status")
            sections["internet"] = internet_capability.get("data")
            context = _capability_read_context(internet_capability, inventory)
        except _LIVE_READ_ERRORS as exc:
            errors.append(_configuration_error("internet", exc))
        if context.interface == "http_luci":
            with self._lock:
                client = self._get_client()
                try:
                    mode = client.get_device_mode()
                    sections["operating_mode"] = {
                        "workmode": mode.workmode,
                        "sysmode": mode.sysmode,
                        "region": mode.region,
                    }
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("operating_mode", exc))
                try:
                    ipv4 = normalize_http_ipv4_configuration(client.get_wan_info())
                    sections["wan"] = ipv4["wan"]
                    sections["lan"] = ipv4["lan"]
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("wan_lan", exc))
                try:
                    sections["dhcp"] = client.get_dhcp_info()
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("dhcp", exc))
                try:
                    sections["network_features"] = {
                        "wan_mode": client.call(get_endpoint("admin.network.wan_mode.read")).result,
                        "lan_ipv4": client.get_lan_ipv4(),
                        "lan_ip": client.get_lan_ip(),
                        "vlan": client.call(get_endpoint("admin.network.vlan.read")).result,
                        "mac_clone": client.call(
                            get_endpoint("admin.network.mac_clone.read")
                        ).result,
                    }
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("network_features", exc))
                try:
                    time_settings = client.get_time_settings()
                    sections["time_settings"] = {
                        "time": time_settings.time,
                        "date": time_settings.date,
                        "timezone": time_settings.timezone,
                        "tz_region": time_settings.tz_region,
                        "continent": time_settings.continent,
                        "dst_status": time_settings.dst_status,
                    }
                except _LIVE_READ_ERRORS as exc:
                    errors.append(_configuration_error("time_settings", exc))
                if self._config.allow_sensitive_reads:
                    try:
                        nickname = client.call(get_endpoint("admin.cloud.nickname.read")).result
                        nickname_status = "available"
                    except _LIVE_READ_ERRORS as exc:
                        nickname_status = "unavailable"
                        errors.append(_configuration_error("nickname", exc))
        else:
            errors.extend(
                _source_unavailable(section)
                for section in (
                    "operating_mode",
                    "dhcp",
                    "network_features",
                    "time_settings",
                )
            )
            try:
                tmp_ipv4 = self._read_resource_capability("ipv4_configuration", context)
                if not isinstance(tmp_ipv4, Mapping):
                    raise ValueError(
                        "Failed to read configuration: IPv4 configuration is not an object"
                    )
                sections["wan"] = tmp_ipv4.get("wan")
                sections["lan"] = tmp_ipv4.get("lan")
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error("wan_lan", exc))
            if self._config.allow_sensitive_reads:
                nickname_status = "unavailable"
                errors.append(_source_unavailable("nickname"))
        wireless_features: dict[str, JsonValue] = {}
        for field_name, capability_name in _WIRELESS_FEATURE_CAPABILITIES:
            try:
                wireless_features[field_name] = self._read_resource_capability(
                    capability_name, context
                )
            except _LIVE_READ_ERRORS as exc:
                errors.append(_configuration_error(f"wireless_features.{field_name}", exc))
        if wireless_features:
            sections["wireless_features"] = wireless_features
        return {
            "schema_version": 1,
            "controller": inventory["controller"],
            **sections,
            "provenance": context.provenance(),
            "related_sections": [
                "status",
                "mesh",
                "client_devices",
                "traffic",
                "address_reservations",
                "logs",
                "capabilities",
                "mutations",
            ],
            "nickname": nickname,
            "nickname_status": nickname_status,
            "unavailable_sections": errors,
            "passwords_included": False,
            "client_identities_included": False,
            "address_reservations_included": False,
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def capability_routes(self) -> dict[str, JsonValue]:
        """Return logical read and mutation routes offline."""
        tmp_configured = bool(
            self._config.tp_link_id and self._config.password and self._config.tmp_host_key_sha256
        )
        return {
            "model": "P9",
            "router_contacted": False,
            "caller_selects_protocol": False,
            "automatic_mutation_fallback": False,
            "diagnostics_exposed": self._config.expose_diagnostic_tools,
            "routes": [
                {
                    **route.to_dict(),
                    "primary_configured": self._interface_configured(route.primary_interface),
                    "primary_connected": self._interface_connected(route.primary_interface),
                    "primary_gate_enabled": self._capability_gate_enabled(route),
                    "primary_available": self._interface_configured(route.primary_interface)
                    and self._capability_gate_enabled(route),
                    "fallback_configured": route.fallback_interface == "tmp_appv2"
                    and tmp_configured,
                    "fallback_gate_enabled": route.fallback_interface == "tmp_appv2"
                    and self._tmp_fallback_available(route.sensitivity),
                }
                for route in CAPABILITY_ROUTES
            ],
            "mutation_routes": [
                {
                    **route.to_dict(),
                    "environment_gate_status": {
                        gate: self._mutation_gate_enabled(gate)
                        for gate in route.required_environment_gates
                    },
                    "all_environment_gates_enabled": all(
                        self._mutation_gate_enabled(gate)
                        for gate in route.required_environment_gates
                    ),
                }
                for route in MUTATION_CAPABILITY_ROUTES
            ],
        }

    def plan_capability_mutation(self, name: str) -> dict[str, JsonValue]:
        """Plan one fixed semantic no-op without contacting the router."""
        try:
            route = get_mutation_capability_route(name)
        except KeyError as exc:
            raise ValueError(
                f"Failed to plan capability mutation: unknown capability {name!r}"
            ) from exc
        gate_status = {
            gate: self._mutation_gate_enabled(gate) for gate in route.required_environment_gates
        }
        return {
            **route.to_dict(),
            "model": "P9",
            "environment_gate_status": gate_status,
            "all_environment_gates_enabled": all(gate_status.values()),
            "router_contacted": False,
            "mutation_invoked": False,
            "caller_selects_protocol": False,
        }

    def plan_semantic_mutation(
        self,
        name: str,
        changes: Mapping[str, JsonValue] | None,
        *,
        mode: str = "change",
    ) -> dict[str, JsonValue]:
        """Create a short-lived semantic mutation plan bound to this controller."""
        assessment = self.preflight_semantic_mutation(name, changes, mode=mode)
        execution_allowed = assessment["execution_allowed"] is True
        plan_id: str | None = None
        confirmation: str | None = None
        expires_in_seconds: float | None = None
        if execution_allowed:
            route = get_mutation_capability_route(name)
            plan_id = secrets.token_urlsafe(24)
            confirmation = route.confirmation
            expires_at = time.monotonic() + _SEMANTIC_PLAN_TTL_SECONDS
            with self._lock:
                controller_identity = self._controller_identity()
                self._pending_mutation_plans[plan_id] = _PendingMutationPlan(
                    plan_id=plan_id,
                    mutation=name,
                    mode=mode,
                    confirmation=confirmation,
                    controller_identity=controller_identity,
                    expires_at=expires_at,
                )
            expires_in_seconds = _SEMANTIC_PLAN_TTL_SECONDS
        assessment.update(
            {
                "plan_id": plan_id,
                "expires_in_seconds": expires_in_seconds,
                "required_confirmation": confirmation,
            }
        )
        return assessment

    def preflight_semantic_mutation(
        self,
        name: str,
        changes: Mapping[str, JsonValue] | None,
        *,
        mode: str = "change",
    ) -> dict[str, JsonValue]:
        """Assess one semantic mutation without registering an execution plan."""
        if mode not in {"change", "verify_current_value_noop"}:
            raise ValueError(f"Failed to plan semantic mutation: unsupported mode {mode!r}")
        catalog = self.semantic_mutations()
        entries = catalog["mutations"]
        if not isinstance(entries, Sequence):
            raise ValueError("Failed to plan semantic mutation: mutation catalogue is invalid")
        entry = next(
            (item for item in entries if isinstance(item, Mapping) and item.get("name") == name),
            None,
        )
        if entry is None:
            raise ValueError(f"Failed to plan semantic mutation: unknown mutation {name!r}")
        selected_changes = dict(changes or {})
        route = next((item for item in MUTATION_CAPABILITY_ROUTES if item.name == name), None)
        blockers = list(_json_string_list(entry, "blockers"))
        if mode == "change":
            blockers.append(
                "state-changing semantic execution is not yet implemented"
                if entry.get("validation_status") == "general_verified"
                else "state-changing semantic execution is not yet validated"
            )
        elif selected_changes:
            blockers.append("current-value no-op verification does not accept desired changes")
        blockers = list(dict.fromkeys(blockers))
        if mode == "verify_current_value_noop":
            blockers = [
                blocker
                for blocker in blockers
                if blocker != "state-changing behavior has not been validated"
            ]
        execution_allowed = (
            mode == "verify_current_value_noop"
            and not selected_changes
            and route is not None
            and catalog["profile_match"] == "exact"
            and all(self._mutation_gate_enabled(gate) for gate in route.required_environment_gates)
        )
        return {
            "schema_version": 1,
            "mutation": name,
            "mode": mode,
            "changes": selected_changes,
            "model": _controller_model(catalog["controller"]),
            "profile_match": catalog["profile_match"],
            "validation_status": entry.get("validation_status"),
            "execution_scope": entry.get("execution_scope"),
            "execution_allowed": execution_allowed,
            "plan_id": None,
            "expires_in_seconds": None,
            "required_confirmation": None,
            "required_gates": entry.get("required_gates"),
            "preflight_available": entry.get("preflight_available"),
            "verification_available": entry.get("verification_available"),
            "rollback_available": entry.get("rollback_available"),
            "blockers": [] if execution_allowed else blockers,
            "router_contacted": catalog["router_contacted"],
            "mutation_invoked": False,
            "fallback_policy": "none",
        }

    def execute_semantic_mutation(
        self,
        plan_id: str,
        confirmation: str,
    ) -> dict[str, JsonValue]:
        """Execute one unexpired semantic plan exactly once without fallback."""
        with self._lock:
            plan = self._pending_mutation_plans.get(plan_id)
            if plan is None:
                raise UnknownPlanError("Failed to execute semantic mutation: unknown plan ID")
            if time.monotonic() > plan.expires_at:
                del self._pending_mutation_plans[plan_id]
                raise ExpiredPlanError("Failed to execute semantic mutation: plan has expired")
            if confirmation != plan.confirmation:
                raise ConfirmationError(
                    "Failed to execute semantic mutation: exact plan confirmation is required"
                )
            self.device_inventory(refresh=True)
            if self._controller_identity() != plan.controller_identity:
                del self._pending_mutation_plans[plan_id]
                raise ControllerChangedError(
                    "Failed to execute semantic mutation: connected controller identity changed"
                )
            del self._pending_mutation_plans[plan_id]
        if plan.mode != "verify_current_value_noop":
            raise PermissionError("Failed to execute semantic mutation: unsupported execution mode")
        result = self.verify_setting_noop(plan.mutation, confirmation)
        result.update(
            {
                "plan_id": plan.plan_id,
                "plan_consumed": True,
                "fallback_policy": "none",
                "fallback_used": False,
            }
        )
        return result

    def semantic_mutation_plan(self, plan_id: str) -> dict[str, JsonValue]:
        """Return the current status of one pending semantic mutation plan."""
        with self._lock:
            plan = self._pending_mutation_plans.get(plan_id)
            if plan is None:
                raise UnknownPlanError("Failed to read semantic mutation plan: unknown plan ID")
            remaining = plan.expires_at - time.monotonic()
            if remaining <= 0:
                del self._pending_mutation_plans[plan_id]
                raise ExpiredPlanError("Failed to read semantic mutation plan: plan has expired")
            return {
                "schema_version": 1,
                "plan_id": plan.plan_id,
                "mutation": plan.mutation,
                "mode": plan.mode,
                "status": "pending",
                "expires_in_seconds": remaining,
                "fallback_policy": "none",
            }

    def _controller_identity(self) -> str:
        devices = self._device_cache
        if devices is None:
            raise PermissionError(
                "Failed to resolve controller identity: call the device profile first"
            )
        controller = _controller_device(devices)
        identity = "\n".join(
            (
                controller.mac,
                controller.device_model,
                controller.hardware_ver,
                controller.software_ver,
            )
        )
        return hashlib.sha256(identity.encode()).hexdigest()

    def _require_exact_p9_profile(self, label: str) -> None:
        inventory = self.device_inventory()
        if inventory["profile_match"] != "exact":
            raise PermissionError(
                f"Failed to {label}: connected controller lacks the exact verified P9 profile"
            )

    def verify_setting_noop(
        self,
        name: str,
        confirmation: str,
    ) -> dict[str, JsonValue]:
        """Run one fixed P9-verified semantic no-op without protocol fallback."""
        try:
            route = get_mutation_capability_route(name)
        except KeyError as exc:
            raise ValueError(
                f"Failed to verify setting no-op: unknown capability {name!r}"
            ) from exc
        if confirmation != route.confirmation:
            raise PermissionError(
                "Failed to verify setting no-op: exact per-call confirmation is required"
            )
        if route.interface != "http_luci":
            raise PermissionError(
                f"Failed to verify setting no-op: no executor for capability {name!r}"
            )
        evidence = self.verify_p9_http_noop(route.operation, confirmation)
        evidence.update(
            {
                "capability": route.name,
                "selected_interface": route.interface,
                "selected_operation": route.operation,
                "fallback_policy": "none",
                "fallback_used": False,
                "caller_selected_protocol": False,
            }
        )
        return evidence

    def _mutation_gate_enabled(self, gate: str) -> bool:
        states = {
            "DECO_ALLOW_MUTATIONS": self._config.allow_mutations,
            "DECO_ALLOW_HTTP_NOOP_VERIFICATION": (self._config.allow_http_noop_verification),
            "DECO_ALLOW_TMP_READS": self._config.allow_tmp_reads,
            "DECO_ALLOW_TMP_NOOP_VERIFICATION": False,
        }
        return states[gate]

    def read_capability(
        self,
        name: str,
        *,
        include_passwords: bool = False,
    ) -> dict[str, JsonValue]:
        """Read one logical capability and apply only proven read-only fallback."""
        if include_passwords and name != "wlan_state":
            raise ValueError(
                "Failed to read capability: password inclusion is supported only for WLAN state"
            )
        try:
            route = get_capability_route(name)
        except KeyError as exc:
            raise ValueError(f"Failed to read capability: unknown capability {name!r}") from exc
        if route.sensitivity == "secret" and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read capability: DECO_ALLOW_SENSITIVE_READS is disabled"
            )
        if route.primary_interface == "tmp_appv2":
            if not self._config.allow_tmp_reads:
                raise PermissionError("Failed to read capability: DECO_ALLOW_TMP_READS is disabled")
            self._tmp_ssh_config()
        inventory = self.device_inventory()
        if name == "mesh_nodes":
            identity_attempts = [
                dict(item) for item in _json_rows(inventory.get("identity_attempts"))
            ]
            if not identity_attempts:
                identity_attempts.append(
                    {
                        "interface": "http_luci",
                        "operation": route.primary_operation,
                        "status": "ok",
                    }
                )
            return _capability_response(
                route,
                inventory["nodes"],
                identity_attempts,
                fallback_used=get_bool(inventory, "fallback_used"),
            )
        if route.primary_interface == "tmp_appv2":
            if _json_string(inventory, "profile_match") != "exact":
                raise PermissionError("Failed to read capability: no exact compatibility evidence")
            data = self._read_tmp_capability(name, include_passwords=include_passwords)
            return _capability_response(
                route,
                data,
                [
                    {
                        "interface": route.primary_interface,
                        "operation": route.primary_operation,
                        "status": "ok",
                    }
                ],
                fallback_used=False,
            )
        context = _resource_read_context(inventory)
        if (
            context.interface == "tmp_appv2"
            and route.fallback_interface == "tmp_appv2"
            and self._tmp_fallback_available(route.sensitivity)
        ):
            data = self._read_tmp_capability(name, include_passwords=include_passwords)
            return _capability_response(
                route,
                data,
                [
                    {
                        "interface": route.primary_interface,
                        "operation": route.primary_operation,
                        "status": "skipped",
                        "reason": "identity_bootstrap_selected_tmp",
                    },
                    {
                        "interface": route.fallback_interface,
                        "operation": route.fallback_operation,
                        "status": "ok",
                    },
                ],
                fallback_used=True,
            )
        attempts: list[dict[str, JsonValue]] = []
        try:
            data = self._read_http_capability(name, include_passwords=include_passwords)
        except (ApiError, TransportError, ValueError) as primary_error:
            attempts.append(
                {
                    "interface": route.primary_interface,
                    "operation": route.primary_operation,
                    "status": "error",
                    "error_type": type(primary_error).__name__,
                }
            )
            if (
                route.fallback_policy != "equivalent_read_only"
                or route.fallback_interface != "tmp_appv2"
                or not self._tmp_fallback_available(route.sensitivity)
            ):
                raise
            try:
                data = self._read_tmp_capability(name, include_passwords=include_passwords)
            except (DecoError, OSError, TimeoutError, ValueError) as fallback_error:
                raise fallback_error from primary_error
            attempts.append(
                {
                    "interface": route.fallback_interface,
                    "operation": route.fallback_operation,
                    "status": "ok",
                }
            )
            return _capability_response(route, data, attempts, fallback_used=True)
        attempts.append(
            {
                "interface": route.primary_interface,
                "operation": route.primary_operation,
                "status": "ok",
            }
        )
        return _capability_response(route, data, attempts, fallback_used=False)

    def _read_resource_capability(
        self,
        name: str,
        context: _ResourceReadContext,
    ) -> JsonValue:
        route = get_capability_route(name)
        if route.sensitivity == "secret" and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read resource capability: DECO_ALLOW_SENSITIVE_READS is disabled"
            )
        if context.interface == "http_luci":
            return self._read_http_capability(name)
        if not self._tmp_fallback_available(route.sensitivity):
            raise PermissionError("Failed to read resource capability: TMP route is not eligible")
        return self._read_tmp_capability(name)

    def _read_http_capability(
        self,
        name: str,
        *,
        include_passwords: bool = False,
    ) -> JsonValue:
        with self._lock:
            client = self._get_client()
            if name == "mesh_nodes":
                devices = self._device_cache or tuple(client.get_device_list())
                self._device_cache = devices
                return [_device_view(device) for device in devices]
            if name == "clients":
                clients = tuple(client.get_client_list())
                return NodeClientList("default", clients).to_dict()["clients"]
            if name == "internet_status":
                return _internet_status_view(client.get_internet_status())
            if name == "address_reservations":
                return _address_reservation_view(client.get_address_reservations())
            if name == "fast_roaming":
                return _boolean_setting_view(client.get_fast_roaming())
            if name == "beamforming":
                return _boolean_setting_view(client.get_beamforming())
            if name == "wireless_operation_mode":
                return normalize_http_wireless_operation_mode(client.get_wireless_operation_mode())
            if name == "wireless_bridge":
                return normalize_http_wireless_bridge(client.get_bridge_status())
            if name == "traffic":
                return normalize_client_traffic(client.get_traffic_statistics())
            if name == "blocked_clients":
                result = client.call(get_endpoint("admin.client.black_list.list")).result
                if not isinstance(result, Mapping):
                    raise ValueError(
                        "Failed to read HTTP capability: blocked clients result is not an object"
                    )
                return normalize_blocked_clients(result)
            if name == "speed_test":
                return _speed_test_view(client.get_speed_test())
            if name == "firmware_status":
                result = client.call(get_endpoint("admin.cloud.firmware_status.check")).result
                if not isinstance(result, Mapping):
                    raise ValueError(
                        "Failed to read HTTP capability: firmware status result is not an object"
                    )
                return normalize_http_firmware_status(result)
            if name == "ddns":
                result = client.call(get_endpoint("admin.cloud.ddns.get")).result
                if not isinstance(result, Mapping):
                    raise ValueError("Failed to read HTTP capability: DDNS result is not an object")
                return dict(result)
            if name == "wlan_state":
                return normalize_http_wlan_configuration(
                    client.get_wlan_config(),
                    include_passwords=include_passwords,
                )
            if name == "ipv4_configuration":
                return normalize_http_ipv4_configuration(client.get_wan_info())
        raise ValueError(f"Failed to read HTTP capability: unknown capability {name!r}")

    def _read_tmp_capability(
        self,
        name: str,
        *,
        include_passwords: bool = False,
    ) -> JsonValue:
        opcodes = {
            "mesh_nodes": 0x400F,
            "clients": 0x4012,
            "internet_status": 0x400C,
            "address_reservations": 0x40C0,
            "fast_roaming": 0x4208,
            "beamforming": 0x421B,
            "wireless_operation_mode": 0x40A0,
            "wireless_bridge": 0x400A,
            "traffic": 0x4014,
            "blocked_clients": 0x4018,
            "speed_test": 0x4010,
            "firmware_status": 0x401C,
            "ddns": 0x40D0,
            "wlan_state": 0x4009,
            "ipv4_configuration": 0x4004,
            "led_configuration": 0x401A,
            "ipv6_configuration": 0x4006,
            "ipv6_firewall": 0x4230,
            "ipv6_clients": 0x4234,
            "lan_configuration": 0x4211,
            "dhcp_configuration": 0x4213,
            "qos_mode": 0x4036,
            "bandwidth_configuration": 0x4219,
            "vlan_configuration": 0x420D,
            "port_forwarding": 0x40B0,
            "iptv_configuration": 0x4224,
            "sip_alg": 0x421D,
            "mac_clone": 0x4226,
        }
        code = opcodes.get(name)
        if code is None:
            raise ValueError(f"Failed to read TMP capability: unknown capability {name!r}")
        payload = self.tmp_read(code)
        result = payload.get("result")
        if not isinstance(result, Mapping):
            raise ValueError(f"Failed to read TMP capability: {name} result is not an object")
        if name == "mesh_nodes":
            return [
                _device_view(Device.from_api(row)) for row in _mapping_rows(result, "device_list")
            ]
        if name == "clients":
            clients = tuple(
                ClientDevice.from_api(row) for row in _mapping_rows(result, "client_list")
            )
            return NodeClientList("default", clients).to_dict()["clients"]
        if name == "internet_status":
            return _internet_status_view(InternetStatus.from_api(result))
        if name == "address_reservations":
            return _address_reservation_view(AddressReservationTable.from_api(result))
        if name == "wireless_operation_mode":
            return normalize_tmp_wireless_operation_mode(result)
        if name == "wireless_bridge":
            return normalize_tmp_wireless_bridge(result)
        if name == "traffic":
            return normalize_client_traffic(result)
        if name == "blocked_clients":
            return normalize_blocked_clients(result)
        if name == "speed_test":
            return _speed_test_view(SpeedTest.from_api(result))
        if name == "firmware_status":
            return normalize_tmp_firmware_status(result)
        if name == "ddns":
            return dict(result)
        if name == "wlan_state":
            return normalize_tmp_wlan_configuration(
                result,
                include_passwords=include_passwords,
            )
        if name == "ipv4_configuration":
            return normalize_tmp_ipv4_configuration(result)
        if name == "led_configuration":
            return normalize_led_configuration(result)
        if name == "ipv6_configuration":
            return normalize_ipv6_configuration(result)
        if name == "ipv6_firewall":
            return normalize_ipv6_firewall(result)
        if name == "ipv6_clients":
            return normalize_ipv6_clients(result)
        if name == "lan_configuration":
            return normalize_lan_configuration(result)
        if name == "dhcp_configuration":
            return normalize_dhcp_configuration(result)
        if name == "qos_mode":
            return normalize_qos_mode(result)
        if name == "bandwidth_configuration":
            return normalize_bandwidth_configuration(result)
        if name == "vlan_configuration":
            return normalize_vlan_configuration(result)
        if name == "port_forwarding":
            return normalize_port_forwarding(result)
        if name == "iptv_configuration":
            return normalize_iptv_configuration(result)
        if name == "sip_alg":
            return normalize_sip_alg(result)
        if name == "mac_clone":
            return normalize_mac_clone(result)
        return _boolean_setting_view(result)

    def _tmp_fallback_available(self, sensitivity: str) -> bool:
        return (
            self._config.allow_tmp_reads
            and bool(self._config.tp_link_id)
            and bool(self._config.password)
            and bool(self._config.tmp_host_key_sha256)
            and self._device_cache is not None
            and _profile_match(_controller_device(self._device_cache)) == "exact"
            and (sensitivity != "secret" or self._config.allow_sensitive_reads)
        )

    def tmp_host_key(self) -> dict[str, JsonValue]:
        """Probe the TMP SSH host key without authenticating or sending TMP payloads."""
        config = self._tmp_ssh_config(require_host_key=False)
        fingerprint = DecoTmpClient(config).probe_host_key()
        return {
            "host": config.host,
            "port": config.ssh_port,
            "host_key_sha256": fingerprint,
            "authentication_attempted": False,
            "tmp_payload_sent": False,
            "matches_configured": bool(config.host_key_sha256)
            and config.host_key_sha256 == fingerprint,
        }

    def tmp_read(self, opcode: int, params: JsonValue = None) -> JsonObject:
        """Invoke a gated read-only TMP opcode with exact P9 evidence checks."""
        if not self._config.allow_tmp_reads:
            raise PermissionError("Failed to read TMP operation: DECO_ALLOW_TMP_READS is disabled")
        try:
            operation = get_tmp_opcode(opcode)
        except KeyError as exc:
            raise ValueError(
                f"Failed to read TMP operation: unknown opcode 0x{opcode:04X}"
            ) from exc
        if operation.safety != "read_only":
            raise PermissionError(
                f"Failed to read TMP operation: {operation.name} is {operation.safety}"
            )
        if operation.sensitivity == "secret" and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read TMP operation: DECO_ALLOW_SENSITIVE_READS is disabled"
            )
        if operation.p9_observation in {"rejected", "payload_rejected"}:
            raise PermissionError(
                f"Failed to read TMP operation: {operation.name} is rejected by the P9 overlay"
            )
        if operation.p9_observation == "returned_binary":
            raise PermissionError(
                "Failed to read TMP operation: use the binary TMP read operation for this opcode"
            )
        if operation.p9_observation == "untested" and not self._config.allow_unverified_tmp_reads:
            raise PermissionError(
                "Failed to read TMP operation: DECO_ALLOW_UNVERIFIED_TMP_READS is disabled"
            )
        _validate_tmp_read_params(operation.p9_confirmed_parameter_sets, params)
        with self._lock:
            return self._get_tmp_client().request_read_json(opcode, params)

    def tmp_read_binary(
        self,
        opcode: int,
        params: JsonValue = None,
        *,
        include_content: bool = False,
    ) -> dict[str, JsonValue]:
        """Invoke an observed binary TMP read and return digest metadata by default."""
        if not self._config.allow_tmp_reads:
            raise PermissionError(
                "Failed to read binary TMP operation: DECO_ALLOW_TMP_READS is disabled"
            )
        try:
            operation = get_tmp_opcode(opcode)
        except KeyError as exc:
            raise ValueError(
                f"Failed to read binary TMP operation: unknown opcode 0x{opcode:04X}"
            ) from exc
        if operation.safety != "read_only":
            raise PermissionError(
                f"Failed to read binary TMP operation: {operation.name} is {operation.safety}"
            )
        if operation.p9_observation != "returned_binary":
            raise PermissionError(
                "Failed to read binary TMP operation: opcode lacks a P9 binary observation"
            )
        if include_content and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read binary TMP operation: content requires DECO_ALLOW_SENSITIVE_READS=1"
            )
        if include_content and not self._config.allow_binary_content:
            raise PermissionError(
                "Failed to read binary TMP operation: content export requires "
                "DECO_ALLOW_BINARY_CONTENT=1"
            )
        envelope: dict[str, JsonValue] = {
            "configVersion": time.time_ns() // 1_000_000,
            "params": params,
        }
        payload = json.dumps(envelope, separators=(",", ":")).encode()
        with self._lock:
            response = self._get_tmp_client().request_read(opcode, payload)
        return {
            "opcode": opcode,
            "hex_code": operation.hex_code,
            "name": operation.name,
            "size": len(response),
            "sha256": hashlib.sha256(response).hexdigest(),
            "content_base64": (base64.b64encode(response).decode() if include_content else None),
        }

    def verify_tmp_ieee80211r_noop(self, confirmation: str) -> dict[str, JsonValue]:
        """Reject TMP writes from the deployed service regardless of runtime gates."""
        raise PermissionError(
            "Failed to verify TMP 802.11r write: server-side TMP writes are hard-disabled; "
            "use the source-checkout lab harness in an isolated environment"
        )

    def _verify_tmp_monthly_report_noop(self, confirmation: str) -> dict[str, JsonValue]:
        raise PermissionError(
            "Failed to verify TMP monthly-report write: server-side TMP writes are "
            "hard-disabled; use the source-checkout lab harness in an isolated environment"
        )

    def verify_p9_http_noop(
        self,
        operation: str,
        confirmation: str,
    ) -> dict[str, JsonValue]:
        """Repeat one P9-verified HTTP setting no-op behind independent gates."""
        expected = HTTP_NOOP_CONFIRMATIONS.get(operation)
        if expected is None:
            raise ValueError(f"Failed to verify P9 HTTP no-op: unsupported operation {operation!r}")
        if confirmation != expected:
            raise PermissionError(
                "Failed to verify P9 HTTP no-op: exact per-call confirmation is required"
            )
        if not self._config.allow_mutations:
            raise PermissionError(
                "Failed to verify P9 HTTP no-op: DECO_ALLOW_MUTATIONS is disabled"
            )
        if not self._config.allow_http_noop_verification:
            raise PermissionError(
                "Failed to verify P9 HTTP no-op: DECO_ALLOW_HTTP_NOOP_VERIFICATION is disabled"
            )
        compatibility = P9_COMPATIBILITY_PROFILE.get(operation)
        if (
            not compatibility.mutation_tested
            or compatibility.mutation_test_scope != "noop_only"
            or compatibility.error_code != 0
        ):
            raise PermissionError(
                "Failed to verify P9 HTTP no-op: P9 safety evidence is incomplete"
            )
        self._require_exact_p9_profile("verify P9 HTTP no-op")
        with self._lock:
            if self._http_mutation_latched:
                raise PermissionError(
                    "Failed to verify P9 HTTP no-op: safety latch requires server restart"
                )
            result = verify_http_setting_noop(
                self._get_client(),
                operation,
                confirmation,
            )
            if not result.verified_noop:
                self._http_mutation_latched = True
        evidence = result.to_dict()
        evidence.update(
            {
                "model": "P9",
                "execution_scope": "verified_current_value_noop_only",
                "runtime_gates": [
                    "DECO_ALLOW_MUTATIONS",
                    "DECO_ALLOW_HTTP_NOOP_VERIFICATION",
                ],
                "generic_http_noop_execution_supported": False,
                "requires_attention": not result.verified_noop,
            }
        )
        return evidence

    def discover_tmp_read_contracts(
        self,
        *,
        include_inferred_iot_module_contract: bool = False,
    ) -> dict[str, JsonValue]:
        """Probe bounded parameterized TMP reads without returning source values."""
        if not self._config.allow_tmp_reads:
            raise PermissionError(
                "Failed to discover TMP read contracts: DECO_ALLOW_TMP_READS is disabled"
            )
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to discover TMP read contracts: DECO_ALLOW_SENSITIVE_READS is disabled"
            )
        if include_inferred_iot_module_contract and not self._config.allow_unverified_tmp_reads:
            raise PermissionError(
                "Failed to discover inferred TMP read contract: "
                "DECO_ALLOW_UNVERIFIED_TMP_READS is disabled"
            )
        with self._lock:
            return probe_tmp_read_contracts(
                self._get_tmp_client(),
                include_inferred_iot_module_contract=include_inferred_iot_module_contract,
            )

    def discover_tmp_unverified_reads(
        self,
        *,
        include_sensitive: bool = False,
        max_operations: int | None = None,
    ) -> dict[str, JsonValue]:
        """Probe newly catalogued reads while retaining only schemas and error codes."""
        if not self._config.allow_tmp_reads:
            raise PermissionError(
                "Failed to discover unverified TMP reads: DECO_ALLOW_TMP_READS is disabled"
            )
        if not self._config.allow_unverified_tmp_reads:
            raise PermissionError(
                "Failed to discover unverified TMP reads: "
                "DECO_ALLOW_UNVERIFIED_TMP_READS is disabled"
            )
        if include_sensitive and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to discover unverified TMP reads: DECO_ALLOW_SENSITIVE_READS is disabled"
            )
        with self._lock:
            return probe_tmp_unverified_reads(
                self._get_tmp_client(),
                include_sensitive=include_sensitive,
                max_operations=max_operations,
            )

    def p9_tmp_data(
        self,
        category: str = "",
        *,
        include_parameterized: bool = False,
    ) -> dict[str, JsonValue]:
        """Return all positively observed TMP JSON data in an optional category."""
        if not self._config.allow_tmp_reads:
            raise PermissionError("Failed to read P9 TMP data: DECO_ALLOW_TMP_READS is disabled")
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read P9 TMP data: DECO_ALLOW_SENSITIVE_READS is disabled"
            )
        categories = {opcode.category for opcode in TMP_OPCODE_CATALOG}
        if category and category not in categories:
            raise ValueError(f"Failed to read P9 TMP data: unknown category {category!r}")
        available = tuple(
            opcode
            for opcode in TMP_OPCODE_CATALOG
            if opcode.p9_observation == "returned_data"
            and (not category or opcode.category == category)
        )
        selected = tuple(opcode for opcode in available if not opcode.p9_confirmed_parameter_sets)
        skipped_parameterized = tuple(
            opcode
            for opcode in available
            if opcode.p9_confirmed_parameter_sets and not include_parameterized
        )
        selected_parameterized = tuple(
            opcode
            for opcode in available
            if opcode.p9_confirmed_parameter_sets and include_parameterized
        )
        results: list[dict[str, JsonValue]] = []
        responses_by_code: dict[int, JsonObject] = {}
        attempted_codes: set[int] = set()
        dependency_errors: list[dict[str, JsonValue]] = []
        dependency_request_count = 0
        with self._lock:
            client = self._get_tmp_client()
            for opcode in selected:
                attempted_codes.add(opcode.code)
                try:
                    response = client.request_read_json(opcode.code)
                except (DecoError, OSError, TimeoutError, ValueError) as exc:
                    results.append(
                        {
                            "code": opcode.code,
                            "hex_code": opcode.hex_code,
                            "name": opcode.name,
                            "category": opcode.category,
                            "status": "error",
                            "error_type": type(exc).__name__,
                        }
                    )
                    continue
                responses_by_code[opcode.code] = response
                results.append(
                    {
                        "code": opcode.code,
                        "hex_code": opcode.hex_code,
                        "name": opcode.name,
                        "category": opcode.category,
                        "status": "ok",
                        "response": response,
                    }
                )
            owner_ids = _tmp_owner_ids(responses_by_code)
            if (
                any(
                    opcode.code in _TMP_OWNER_PARAMETERIZED_OPCODES
                    for opcode in selected_parameterized
                )
                and not owner_ids
            ):
                for source_code in _TMP_PARAMETER_SOURCE_OPCODES:
                    if source_code in attempted_codes:
                        continue
                    dependency_request_count += 1
                    try:
                        source_response = client.request_read_json(source_code)
                    except (DecoError, OSError, TimeoutError, ValueError) as exc:
                        dependency_errors.append(
                            {
                                "code": source_code,
                                "hex_code": f"0x{source_code:04X}",
                                "error_type": type(exc).__name__,
                            }
                        )
                        continue
                    responses_by_code[source_code] = source_response
                    owner_ids = _tmp_owner_ids(responses_by_code)
                    if owner_ids:
                        break
            for opcode in selected_parameterized:
                requests = _tmp_parameterized_requests(opcode.code, owner_ids)
                if not requests:
                    results.append(
                        {
                            "code": opcode.code,
                            "hex_code": opcode.hex_code,
                            "name": opcode.name,
                            "category": opcode.category,
                            "status": "skipped",
                            "skip_reason": (
                                "confirmed owner identifier unavailable"
                                if opcode.code in _TMP_OWNER_PARAMETERIZED_OPCODES
                                else "parameter resolver unavailable"
                            ),
                            "parameter_keys": list(opcode.p9_confirmed_parameter_sets[0]),
                        }
                    )
                    continue
                for variant_index, (params, parameter_source) in enumerate(requests, start=1):
                    base: dict[str, JsonValue] = {
                        "code": opcode.code,
                        "hex_code": opcode.hex_code,
                        "name": opcode.name,
                        "category": opcode.category,
                        "parameter_keys": sorted(params),
                        "parameter_source": parameter_source,
                        "variant_index": variant_index,
                    }
                    try:
                        response = client.request_read_json(opcode.code, params)
                    except (DecoError, OSError, TimeoutError, ValueError) as exc:
                        results.append(
                            {
                                **base,
                                "status": "error",
                                "error_type": type(exc).__name__,
                            }
                        )
                        continue
                    results.append({**base, "status": "ok", "response": response})
        succeeded_count = sum(result["status"] == "ok" for result in results)
        failed_count = sum(result["status"] == "error" for result in results)
        skipped_count = sum(result["status"] == "skipped" for result in results)
        resolved_parameterized_codes = {
            result["code"]
            for result in results
            if "parameter_source" in result and isinstance(result["code"], int)
        }
        return {
            "transport": "tmp_appv2_over_ssh",
            "model": "P9",
            "category": category,
            "available_count": len(available),
            "selected_count": len(selected) + len(selected_parameterized),
            "include_parameterized": include_parameterized,
            "parameterized_selected_count": len(selected_parameterized),
            "parameterized_resolved_count": len(resolved_parameterized_codes),
            "dependency_request_count": dependency_request_count,
            "dependency_errors": dependency_errors,
            "dependency_response_values_included": False,
            "skipped_parameterized_count": len(skipped_parameterized),
            "skipped_parameterized_operations": [
                {
                    "code": opcode.code,
                    "hex_code": opcode.hex_code,
                    "name": opcode.name,
                    "confirmed_parameter_sets": [
                        list(parameter_set) for parameter_set in opcode.p9_confirmed_parameter_sets
                    ],
                    "read_operation": "tmp_read",
                }
                for opcode in skipped_parameterized
            ],
            "request_count": succeeded_count + failed_count,
            "succeeded_count": succeeded_count,
            "failed_count": failed_count,
            "skipped_count": skipped_count,
            "all_available_operations_attempted": (
                len(selected) + len(resolved_parameterized_codes) == len(available)
            ),
            "values_included": True,
            "request_parameter_values_included": False,
            "mutation_invoked": False,
            "results": results,
        }

    def transport_capabilities(self) -> dict[str, JsonValue]:
        """Return catalogue transport coverage without contacting the router."""
        transports: list[dict[str, JsonValue]] = []
        for authentication in sorted({endpoint.authentication for endpoint in ENDPOINT_CATALOG}):
            endpoints = tuple(
                endpoint
                for endpoint in ENDPOINT_CATALOG
                if endpoint.authentication == authentication
            )
            safety = Counter(endpoint.safety for endpoint in endpoints)
            generic_supported = sum(endpoint.generic_call_supported for endpoint in endpoints)
            binary_supported = sum(endpoint.binary_call_supported for endpoint in endpoints)
            bootstrap_supported = sum(endpoint.bootstrap_call_supported for endpoint in endpoints)
            transports.append(
                {
                    "authentication": authentication,
                    "operation_count": len(endpoints),
                    "safety_counts": dict(sorted(safety.items())),
                    "generic_call_supported": generic_supported,
                    "binary_call_supported": binary_supported,
                    "bootstrap_call_supported": bootstrap_supported,
                    "implemented": bool(
                        generic_supported or binary_supported or bootstrap_supported
                    ),
                    "notes": _transport_notes(authentication),
                }
            )
        return {
            "catalogued_http_operations": len(ENDPOINT_CATALOG),
            "transports": transports,
            "binary_policy": {
                "bulk_secret_gate_required": True,
                "bulk_secret_gate_enabled": (
                    self._config.allow_sensitive_reads and self._config.allow_bulk_secret_reads
                ),
                "content_export_gate_required": True,
                "content_export_gate_enabled": self._config.allow_binary_content,
                "digest_discovery_operation": "discover_p9_binary_reads",
                "binary_content_returned_by_discovery": False,
            },
            "tmp_appv2": {
                "transport": "TMP/AppV2 over Dropbear SSH",
                "external_port": 20001,
                "tunnel_destination": "127.0.0.1:20002",
                "protocol_implemented": True,
                "read_only_session_implemented": True,
                "experimental": True,
                "scoped_noop_verification_implemented": False,
                "scoped_noop_runtime_gate_enabled": False,
                "server_writes_hard_disabled": True,
                "source_checkout_lab_harness_available": True,
                "generic_mutation_implemented": False,
                "ssh_adapter_implemented": True,
                "generic_call_supported": False,
                "p9_service_detected": True,
                "p9_transport_authenticated": True,
                "p9_association_succeeded": True,
                "p9_opcode_tested_count": sum(
                    opcode.p9_opcode_tested for opcode in TMP_OPCODE_CATALOG
                ),
                "evidence": (
                    "P9 SSH/TMP authentication and read audit; three current-value writes "
                    "passed immediate verification but did not establish operational safety; "
                    "a later incident is temporally associated with aggregate TMP activity "
                    "but unattributed"
                ),
            },
        }

    def p9_access_coverage(self) -> dict[str, JsonValue]:
        """Return one offline matrix of P9 evidence, call paths, and remaining gaps."""
        http_reads = tuple(
            endpoint for endpoint in ENDPOINT_CATALOG if endpoint.safety == "read_only"
        )
        http_observations = {
            endpoint.name: P9_COMPATIBILITY_PROFILE.get(endpoint.name) for endpoint in http_reads
        }
        http_supported = tuple(
            endpoint
            for endpoint in http_reads
            if http_observations[endpoint.name].availability == "supported"
        )
        http_supported_without_path = tuple(
            endpoint.name
            for endpoint in http_supported
            if not endpoint.generic_call_supported
            and not endpoint.bootstrap_call_supported
            and not endpoint.binary_call_supported
        )
        http_without_transport = tuple(
            endpoint.name
            for endpoint in http_reads
            if not endpoint.generic_call_supported
            and not endpoint.bootstrap_call_supported
            and not endpoint.binary_call_supported
        )
        http_untested = tuple(
            endpoint.name
            for endpoint in http_reads
            if http_observations[endpoint.name].availability == "untested"
        )
        http_safe_untested = tuple(
            endpoint.name
            for endpoint in http_reads
            if http_observations[endpoint.name].availability == "untested"
            and endpoint.sensitivity != "secret"
            and (endpoint.generic_call_supported or endpoint.bootstrap_call_supported)
        )
        tmp_reads = tuple(opcode for opcode in TMP_OPCODE_CATALOG if opcode.safety == "read_only")
        tmp_returned_data = tuple(
            opcode for opcode in tmp_reads if opcode.p9_observation == "returned_data"
        )
        tmp_returned_binary = tuple(
            opcode for opcode in tmp_reads if opcode.p9_observation == "returned_binary"
        )
        tmp_payload_rejected = tuple(
            opcode for opcode in tmp_reads if opcode.p9_observation == "payload_rejected"
        )
        tmp_payload_exact_app_contract = tuple(
            opcode
            for opcode in tmp_payload_rejected
            if opcode.app_contract_status != "no_app_call_site"
        )
        tmp_payload_unresolved_app_contract = tuple(
            opcode
            for opcode in tmp_payload_rejected
            if opcode.app_contract_status == "no_app_call_site"
        )
        tmp_rejected = tuple(opcode for opcode in tmp_reads if opcode.p9_observation == "rejected")
        tmp_untested = tuple(opcode for opcode in tmp_reads if opcode.p9_observation == "untested")
        http_mutations = self.p9_mutation_inventory()
        tmp_mutations = self.p9_tmp_mutation_inventory()
        tmp_verification_queue = self.p9_tmp_mutation_verification_queue()
        http_mutation_tested_count = sum(
            P9_COMPATIBILITY_PROFILE.get(endpoint.name).mutation_tested
            for endpoint in P9_MUTATION_CANDIDATES
        )
        http_mutation_general_scope_count = sum(
            P9_COMPATIBILITY_PROFILE.get(endpoint.name).mutation_test_scope == "general"
            for endpoint in P9_MUTATION_CANDIDATES
        )
        tmp_write_operations = tuple(
            opcode for opcode in TMP_OPCODE_CATALOG if opcode.safety in {"mutation", "destructive"}
        )
        tmp_mutation_tested_count = sum(
            opcode.p9_mutation_observation != "untested" for opcode in tmp_write_operations
        )
        positive_http_paths = not http_supported_without_path
        positive_tmp_paths = all(
            opcode.p9_observation in {"returned_data", "returned_binary"}
            for opcode in (*tmp_returned_data, *tmp_returned_binary)
        )
        tmp_untested_gaps: list[dict[str, JsonValue]] = []
        if tmp_untested:
            tmp_untested_gaps.append(
                {
                    "surface": "tmp_reads_untested",
                    "count": len(tmp_untested),
                    "gap": "signed-app registry reads have not been exercised on P9",
                    "next_action": "run deco_discover_tmp_unverified_reads",
                }
            )
        http_transport_gaps: list[dict[str, JsonValue]] = []
        if http_without_transport:
            http_transport_gaps.append(
                {
                    "surface": "http_transports",
                    "count": len(http_without_transport),
                    "gap": "catalogued read transport not implemented",
                    "next_action": "implement only if P9 capability evidence justifies it",
                }
            )
        return {
            "model": "P9",
            "firmware_version": P9_PROFILE_FIRMWARE,
            "catalog_version": CATALOG_VERSION,
            "offline": True,
            "router_contacted": False,
            "unified_semantic_surface": {
                "capability_count": len(CAPABILITY_ROUTES),
                "mutation_capability_count": len(MUTATION_CAPABILITY_ROUTES),
                "caller_selects_protocol": False,
                "automatic_fallback_scope": "proven_equivalent_reads_only",
                "automatic_mutation_fallback": False,
                "routes": [route.to_dict() for route in CAPABILITY_ROUTES],
                "mutation_routes": [route.to_dict() for route in MUTATION_CAPABILITY_ROUTES],
            },
            "http": {
                "catalogued_read_count": len(http_reads),
                "p9_observation_counts": dict(
                    sorted(
                        Counter(
                            observation.availability for observation in http_observations.values()
                        ).items()
                    )
                ),
                "supported_count": len(http_supported),
                "returned_data_count": sum(
                    http_observations[endpoint.name].returned_data is True
                    for endpoint in http_supported
                ),
                "accepted_empty_count": sum(
                    http_observations[endpoint.name].returned_data is False
                    for endpoint in http_supported
                ),
                "supported_sensitivity_counts": dict(
                    sorted(Counter(endpoint.sensitivity for endpoint in http_supported).items())
                ),
                "supported_individual_callable_count": sum(
                    endpoint.generic_call_supported
                    or endpoint.bootstrap_call_supported
                    or endpoint.binary_call_supported
                    for endpoint in http_supported
                ),
                "supported_batch_json_count": sum(
                    endpoint.generic_call_supported or endpoint.bootstrap_call_supported
                    for endpoint in http_supported
                ),
                "supported_without_call_path": list(http_supported_without_path),
                "untested_count": len(http_untested),
                "untested_operations": list(http_untested),
                "untested_binary_count": sum(
                    endpoint.response_kind == "binary"
                    for endpoint in http_reads
                    if http_observations[endpoint.name].availability == "untested"
                ),
                "untested_binary_operations": [
                    endpoint.name
                    for endpoint in http_reads
                    if http_observations[endpoint.name].availability == "untested"
                    and endpoint.response_kind == "binary"
                ],
                "bulk_secret_runtime_gate_enabled": (
                    self._config.allow_sensitive_reads and self._config.allow_bulk_secret_reads
                ),
                "binary_content_export_gate_enabled": self._config.allow_binary_content,
                "untested_operation_details": [
                    {
                        "name": endpoint.name,
                        "authentication": endpoint.authentication,
                        "response_kind": endpoint.response_kind,
                        "sensitivity": endpoint.sensitivity,
                        "sdk_call_path": bool(
                            endpoint.generic_call_supported
                            or endpoint.bootstrap_call_supported
                            or endpoint.binary_call_supported
                        ),
                        "exclusion_reason": _http_read_gap_reason(endpoint),
                    }
                    for endpoint in http_reads
                    if http_observations[endpoint.name].availability == "untested"
                ],
                "safe_untested_json_count": len(http_safe_untested),
                "safe_untested_json_operations": list(http_safe_untested),
                "catalogued_read_without_transport_count": len(http_without_transport),
                "catalogued_read_without_transport": list(http_without_transport),
                "access_operations": [
                    "read_endpoint",
                    "read_binary_endpoint",
                    "discover_p9_binary_reads",
                    "get_p9_http_data",
                ],
            },
            "tmp": {
                "catalogued_opcode_count": len(TMP_OPCODE_CATALOG),
                "read_count": len(tmp_reads),
                "catalogued_read_count": len(tmp_reads),
                "p9_tested_read_count": sum(opcode.p9_opcode_tested for opcode in tmp_reads),
                "p9_observation_counts": dict(
                    sorted(Counter(opcode.p9_observation for opcode in tmp_reads).items())
                ),
                "returned_data_count": len(tmp_returned_data),
                "returned_binary_count": len(tmp_returned_binary),
                "parameterized_returned_data_count": sum(
                    bool(opcode.p9_confirmed_parameter_sets) for opcode in tmp_returned_data
                ),
                "batch_without_params_count": sum(
                    not opcode.p9_confirmed_parameter_sets for opcode in tmp_returned_data
                ),
                "batch_with_confirmed_params_count": len(tmp_returned_data),
                "parameterized_batch_opt_in_supported": True,
                "parameterized_batch_request_values_returned": False,
                "payload_rejected_count": len(tmp_payload_rejected),
                "payload_rejected_operations": [opcode.name for opcode in tmp_payload_rejected],
                "payload_rejected_exact_app_contract_count": len(tmp_payload_exact_app_contract),
                "payload_rejected_exact_app_contract_operations": [
                    opcode.name for opcode in tmp_payload_exact_app_contract
                ],
                "payload_rejected_unresolved_app_contract_count": len(
                    tmp_payload_unresolved_app_contract
                ),
                "payload_rejected_unresolved_app_contract_operations": [
                    opcode.name for opcode in tmp_payload_unresolved_app_contract
                ],
                "appv2_rejected_count": len(tmp_rejected),
                "appv2_rejected_operations": [opcode.name for opcode in tmp_rejected],
                "untested_read_count": len(tmp_untested),
                "all_reads_tested": not tmp_untested,
                "access_operations": [
                    "tmp_read",
                    "tmp_read_binary",
                    "get_p9_tmp_data",
                    "discover_tmp_read_contracts",
                    "discover_tmp_unverified_reads",
                ],
            },
            "mutations": {
                "http": {
                    "p9_candidate_count": http_mutations["candidate_count"],
                    "tested_count": http_mutations["mutation_tested_count"],
                    "execution_eligible_count": http_mutations["execution_eligible_count"],
                    "execution_available": True,
                    "execution_policy": "general_scope_model_evidence_required",
                    "verification_candidate_count": http_mutations["verification_candidate_count"],
                    "verification_queue_operation": "p9_http_mutation_verification_queue",
                    "scoped_noop_operation_count": http_mutations["scoped_noop_operation_count"],
                    "scoped_noop_runtime_gate_enabled": http_mutations[
                        "scoped_noop_runtime_gate_enabled"
                    ],
                    "scoped_noop_execution_eligible_count": http_mutations[
                        "scoped_noop_execution_eligible_count"
                    ],
                    "scoped_noop_executors": http_mutations["scoped_noop_executors"],
                },
                "tmp": {
                    "candidate_count": tmp_mutations["candidate_count"],
                    "tested_count": tmp_mutations["mutation_tested_count"],
                    "static_app_contract_count": tmp_mutations["static_app_contract_count"],
                    "direct_static_app_contract_count": tmp_mutations[
                        "direct_static_app_contract_count"
                    ],
                    "indirect_static_app_contract_count": tmp_mutations[
                        "indirect_static_app_contract_count"
                    ],
                    "static_app_contract_missing_count": tmp_mutations[
                        "static_app_contract_missing_count"
                    ],
                    "complete_safety_contract_count": tmp_mutations[
                        "complete_safety_contract_count"
                    ],
                    "p9_static_key_preflight_count": tmp_mutations["p9_static_key_preflight_count"],
                    "preflight_candidate_key_coverage_complete_count": tmp_mutations[
                        "preflight_candidate_key_coverage_complete_count"
                    ],
                    "preflight_candidate_key_coverage_blocked_count": tmp_mutations[
                        "preflight_candidate_key_coverage_blocked_count"
                    ],
                    "execution_eligible_count": tmp_mutations["execution_eligible_count"],
                    "execution_available": tmp_mutations["execution_available"],
                    "generic_execution_available": tmp_mutations["generic_execution_available"],
                    "scoped_noop_executor_count": tmp_mutations["scoped_noop_executor_count"],
                    "scoped_noop_runtime_gate_enabled": tmp_mutations[
                        "scoped_noop_runtime_gate_enabled"
                    ],
                    "scoped_noop_executors": [],
                    "server_write_policy": "hard_disabled",
                    "source_checkout_lab_harness_available": True,
                    "verification_candidate_count": tmp_verification_queue[
                        "verification_candidate_count"
                    ],
                    "default_verification_queue_count": tmp_verification_queue["returned_count"],
                    "verification_queue_operation": "p9_tmp_mutation_verification_queue",
                },
            },
            "invariants": {
                "all_positive_http_reads_have_caller_path": positive_http_paths,
                "all_positive_tmp_reads_have_caller_path": positive_tmp_paths,
                "all_positive_tmp_json_reads_have_batch_path": True,
                "all_positive_reads_have_caller_path": (positive_http_paths and positive_tmp_paths),
                "all_tmp_reads_tested_on_p9": not tmp_untested,
                "mutations_default_disabled": True,
                "http_generic_noop_only_execution_absent": True,
                "http_scoped_noop_execution_exposed": True,
                "tmp_generic_mutation_execution_absent": True,
                "tmp_scoped_noop_execution_exposed": False,
                "tmp_server_writes_hard_disabled": True,
            },
            "unresolved_summary": {
                "http_binary_reads_untested": len(http_untested),
                "http_binary_reads_transport_error": 2,
                "http_binary_reads_invalid_response": 1,
                "tmp_reads_payload_rejected": len(tmp_payload_rejected),
                "tmp_read_contract_unresolved": len(tmp_payload_unresolved_app_contract),
                "http_mutations_untested": (
                    len(P9_MUTATION_CANDIDATES) - http_mutation_tested_count
                ),
                "http_mutations_general_scope_verified": http_mutation_general_scope_count,
                "tmp_mutations_untested": (len(tmp_write_operations) - tmp_mutation_tested_count),
                "tmp_mutations_general_scope_verified": 0,
            },
            "completed_live_audits": [
                {
                    "id": "p9_tmp_iot_module_contract_discovery",
                    "artifact": ("docs/api-responses/p9-tmp-iot-module-contract-probe.json"),
                    "outcome": "all_11_bounded_module_variants_payload_rejected",
                    "mutation_invoked": False,
                    "response_values_retained": False,
                },
                {
                    "id": "p9_http_binary_digest_discovery",
                    "artifact": "docs/api-responses/p9-http-binary-digest-audit.json",
                    "outcome": "two_transport_errors_one_unvalidated_text_response",
                    "mutation_invoked": False,
                    "binary_content_returned": False,
                },
                {
                    "id": "p9_http_system_log_prepare",
                    "artifact": "docs/api-responses/p9-system-log-compatibility.json",
                    "outcome": "notice_level_snapshot_prepared_and_page_zero_read",
                    "mutation_invoked": True,
                    "response_values_retained": False,
                },
                {
                    "id": "p9_mcp_complete_tmp_batch_audit",
                    "artifact": ("docs/api-responses/p9-mcp-complete-tmp-batch-audit.json"),
                    "outcome": "55_of_55_datasets_succeeded_across_61_requests",
                    "mutation_invoked": False,
                    "response_values_retained": False,
                },
                {
                    "id": "p9_tmp_beamforming_noop_verification",
                    "artifact": "docs/api-responses/p9-tmp-beamforming-noop.json",
                    "outcome": "same_value_immediate_verification_passed",
                    "safety_status": "safety_not_established",
                    "operation_code": 0x421C,
                    "mutation_request_count": 1,
                    "state_unchanged": True,
                    "rollback_attempted": False,
                    "response_values_retained": False,
                },
                {
                    "id": "p9_tmp_monthly_report_noop_verification",
                    "artifact": "docs/api-responses/p9-tmp-monthly-report-noop.json",
                    "outcome": "same_value_immediate_verification_passed",
                    "safety_status": "safety_not_established",
                    "operation_code": 0x4223,
                    "mutation_request_count": 1,
                    "state_unchanged": True,
                    "rollback_attempted": False,
                    "response_values_retained": False,
                },
            ],
            "authorization_ready_action_count": 0,
            "authorization_ready_actions": [],
            "remaining_gaps": [
                {
                    "surface": "tmp_reads",
                    "count": len(tmp_payload_rejected),
                    "gap": (
                        "three exact Deco app request contracts are rejected by P9; "
                        "one request contract is absent from the reference app"
                    ),
                    "next_action": (
                        "obtain explicit authorization, then run the opt-in inferred module "
                        "variants through discover_tmp_read_contracts"
                    ),
                },
                *tmp_untested_gaps,
                {
                    "surface": "http_reads",
                    "count": len(http_untested),
                    "gap": "P9 compatibility untested",
                    "next_action": (
                        "obtain explicit authorization, then run digest-only "
                        "discover_p9_binary_reads behind both bulk-secret gates"
                    ),
                },
                *http_transport_gaps,
                {
                    "surface": "http_mutations",
                    "count": len(P9_MUTATION_CANDIDATES) - http_mutation_general_scope_count,
                    "gap": "general-scope mutation evidence absent for remaining operations",
                    "next_action": (
                        "retain remaining operations as planning-only until stronger "
                        "contract or external evidence exists"
                    ),
                },
                {
                    "surface": "tmp_mutations",
                    "count": (len(tmp_write_operations) - tmp_mutation_tested_count),
                    "gap": (
                        "345 mutations untested; three same-value writes passed immediate "
                        "verification but did not establish operational safety"
                    ),
                    "next_action": (
                        "keep server writes hard-disabled; use only the isolated source-checkout "
                        "lab harness for future controlled validation"
                    ),
                },
            ],
        }

    def p9_tmp_opcode_catalog(
        self,
        safety: str = "",
        category: str = "",
        query: str = "",
    ) -> dict[str, JsonValue]:
        """Return reverse-engineered TMP opcodes without implying P9 opcode support."""
        valid_safety = {"", "read_only", "mutation", "destructive", "internal"}
        if safety not in valid_safety:
            raise ValueError(f"Failed to list TMP opcodes: invalid safety level {safety!r}")
        opcodes = tuple(
            opcode
            for opcode in TMP_OPCODE_CATALOG
            if (not safety or opcode.safety == safety)
            and (not category or opcode.category == category)
            and _tmp_opcode_matches_query(opcode, query)
        )
        all_safety = Counter(opcode.safety for opcode in TMP_OPCODE_CATALOG)
        all_categories = Counter(opcode.category for opcode in TMP_OPCODE_CATALOG)
        observations = Counter(opcode.p9_observation for opcode in TMP_OPCODE_CATALOG)
        mutation_observations = Counter(
            opcode.p9_mutation_observation
            for opcode in TMP_OPCODE_CATALOG
            if opcode.safety in {"mutation", "destructive"}
        )
        untested_read_count = sum(
            opcode.safety == "read_only" and opcode.p9_observation == "untested"
            for opcode in TMP_OPCODE_CATALOG
        )
        return {
            "transport": "tmp_appv2_over_ssh",
            "p9_transport_detected": True,
            "p9_transport_authenticated": True,
            "p9_opcode_tested_count": sum(opcode.p9_opcode_tested for opcode in TMP_OPCODE_CATALOG),
            "p9_observation_counts": dict(sorted(observations.items())),
            "p9_mutation_observation_counts": dict(sorted(mutation_observations.items())),
            "protocol_implemented": True,
            "read_only_session_implemented": True,
            "ssh_adapter_implemented": True,
            "sources": [
                "https://github.com/roger-/tmpkit",
                "signed TP-Link Deco Android 3.10.215 build 1484",
            ],
            "source_scope": (
                "signed Deco Android apps 1.10.5 and 3.10.215; tmpkit tested only "
                "on X5000; this project tested the original 74 reads and two "
                "protocol operations plus three current-value writes on P9; the writes passed "
                "immediate verification but operational safety is not established; a later "
                "incident is temporally associated with aggregate TMP activity but unattributed; "
                "server writes are hard-disabled; "
                f"{untested_read_count} reads remain untested"
            ),
            "incident_context": {
                "activity_scope": "aggregate_tmp_activity",
                "association": "temporally_associated_unattributed",
                "causality": "undetermined",
                "observed_at": "2026-07-12",
                "reference": "docs/incidents/2026-07-12-p9-tmp-topology-loss.md",
            },
            "catalogued_opcode_count": len(TMP_OPCODE_CATALOG),
            "safety_counts": dict(sorted(all_safety.items())),
            "category_counts": dict(sorted(all_categories.items())),
            "filter": {"safety": safety, "category": category, "query": query},
            "returned_opcode_count": len(opcodes),
            "opcodes": [opcode.to_dict() for opcode in opcodes],
        }

    def p9_tmp_mutation_inventory(self) -> dict[str, JsonValue]:
        """Return TMP mutation evidence without exposing a server executor."""
        plans = tuple(
            build_tmp_mutation_plan(opcode.code)
            for opcode in TMP_OPCODE_CATALOG
            if opcode.safety in {"mutation", "destructive"}
        )
        plan_payloads: list[dict[str, JsonValue]] = []
        for plan in plans:
            payload = plan.to_dict()
            if plan.code == 0x4209:
                payload.update(
                    {
                        "verification_harness": "examples/verify_tmp_ieee80211r_noop.py",
                        "verification_harness_scope": "isolated_source_checkout_lab_only",
                        "scoped_execution_supported": False,
                        "runtime_gate_enabled": False,
                        "execution_eligible": False,
                    }
                )
            elif plan.code == 0x421C:
                payload.update(
                    {
                        "verification_harness": "examples/verify_tmp_beamforming_noop.py",
                        "verification_harness_scope": "isolated_source_checkout_lab_only",
                        "live_verification_invoked": plan.p9_opcode_tested,
                        "scoped_execution_supported": False,
                        "runtime_gate_enabled": False,
                        "execution_eligible": False,
                    }
                )
            elif plan.code == 0x4223:
                payload.update(
                    {
                        "verification_harness": ("examples/verify_tmp_monthly_report_noop.py"),
                        "verification_harness_scope": "isolated_source_checkout_lab_only",
                        "live_verification_invoked": plan.p9_opcode_tested,
                        "scoped_execution_supported": False,
                        "runtime_gate_enabled": False,
                        "execution_eligible": False,
                    }
                )
            plan_payloads.append(payload)
        return {
            "transport": "tmp_appv2_over_ssh",
            "model": "P9",
            "candidate_count": len(plans),
            "safety_counts": dict(sorted(Counter(plan.safety for plan in plans).items())),
            "preflight_relationship_count": sum(plan.preflight_code is not None for plan in plans),
            "p9_supported_preflight_count": sum(
                plan.preflight_observation == "returned_data" for plan in plans
            ),
            "p9_static_key_preflight_count": sum(
                plan.preflight_observation == "returned_data"
                and bool(plan.app_candidate_parameter_keys)
                for plan in plans
            ),
            "preflight_candidate_key_coverage_complete_count": sum(
                plan.preflight_observation == "returned_data"
                and bool(plan.app_candidate_parameter_keys)
                and not plan.preflight_missing_candidate_keys
                for plan in plans
            ),
            "preflight_candidate_key_coverage_blocked_count": sum(
                plan.preflight_observation == "returned_data"
                and bool(plan.preflight_missing_candidate_keys)
                for plan in plans
            ),
            "rollback_relationship_count": sum(plan.rollback_code is not None for plan in plans),
            "preflight_relationship_evidence_counts": dict(
                sorted(
                    Counter(
                        plan.preflight_relationship_evidence
                        for plan in plans
                        if plan.preflight_relationship_evidence
                    ).items()
                )
            ),
            "rollback_relationship_evidence_counts": dict(
                sorted(
                    Counter(
                        plan.rollback_relationship_evidence
                        for plan in plans
                        if plan.rollback_relationship_evidence
                    ).items()
                )
            ),
            "known_parameter_contract_count": sum(
                plan.parameter_contract != "unknown" for plan in plans
            ),
            "static_app_contract_count": sum(
                plan.parameter_contract != "unknown" for plan in plans
            ),
            "direct_static_app_contract_count": sum(
                plan.app_contract_provenance == "direct" for plan in plans
            ),
            "indirect_static_app_contract_count": sum(
                plan.app_contract_provenance == "indirect_virtual_dispatch" for plan in plans
            ),
            "static_app_candidate_keys_count": sum(
                bool(plan.app_candidate_parameter_keys) for plan in plans
            ),
            "static_app_null_payload_count": sum(
                plan.parameter_contract == "static_app_null_payload" for plan in plans
            ),
            "static_app_model_only_count": sum(
                plan.parameter_contract.startswith("static_app_request_models:") for plan in plans
            ),
            "static_app_contract_missing_count": sum(
                plan.parameter_contract == "unknown" for plan in plans
            ),
            "mutation_tested_count": sum(plan.p9_opcode_tested for plan in plans),
            "complete_safety_contract_count": sum(plan.complete_safety_contract for plan in plans),
            "execution_eligible_count": 0,
            "execution_available": False,
            "generic_execution_available": False,
            "scoped_noop_executor_count": 0,
            "scoped_noop_runtime_gate_enabled": False,
            "scoped_noop_operations": [],
            "server_write_policy": "hard_disabled",
            "tmp_transport_status": "experimental",
            "lab_write_environment_gate": "DECO_TMP_LAB_ALLOW_WRITES",
            "prepared_verification_harness_count": 3,
            "prepared_verification_harnesses": [
                {
                    "code": 0x4209,
                    "hex_code": "0x4209",
                    "name": "TMP_APPV2_OP_11R_SET",
                    "harness": "examples/verify_tmp_ieee80211r_noop.py",
                    "scope": "isolated_source_checkout_lab_only",
                    "exact_confirmation_required": True,
                    "live_target_binding_required": True,
                    "execution_available": False,
                },
                {
                    "code": 0x421C,
                    "hex_code": "0x421C",
                    "name": "TMP_APPV2_OP_BEAMFORMING_SET",
                    "harness": "examples/verify_tmp_beamforming_noop.py",
                    "scope": "isolated_source_checkout_lab_only",
                    "exact_confirmation_required": True,
                    "live_target_binding_required": True,
                    "live_invoked": True,
                    "execution_available": False,
                },
                {
                    "code": 0x4223,
                    "hex_code": "0x4223",
                    "name": "TMP_APPV2_OP_MONTHLY_REPORT_MGR_SET",
                    "harness": "examples/verify_tmp_monthly_report_noop.py",
                    "scope": "isolated_source_checkout_lab_only",
                    "exact_confirmation_required": True,
                    "live_target_binding_required": True,
                    "live_invoked": True,
                    "execution_available": False,
                },
            ],
            "evidence": (
                "opcode name-pair inference, P9 read observations, and signed "
                "Deco Android 1.10.5 plus 3.10.215 static request contracts; "
                "three value-free P9 current-value writes passed immediate verification but "
                "did not establish operational safety; the later incident is associated only "
                "with aggregate TMP activity and remains unattributed; "
                "server execution is hard-disabled"
            ),
            "plans": plan_payloads,
        }

    def plan_tmp_mutation(self, opcode: int) -> dict[str, JsonValue]:
        """Return one offline TMP mutation plan without opening a router session."""
        return build_tmp_mutation_plan(opcode).to_dict()

    def p9_tmp_mutation_verification_queue(
        self,
        *,
        include_sensitive: bool = False,
        include_deferred: bool = False,
        include_destructive: bool = False,
        limit: int = 20,
    ) -> dict[str, JsonValue]:
        """Rank TMP mutations for future authorization without router contact."""
        all_candidates = build_tmp_mutation_verification_queue(
            include_sensitive=True,
            include_deferred=True,
            include_destructive=True,
            limit=None,
        )
        selected = build_tmp_mutation_verification_queue(
            include_sensitive=include_sensitive,
            include_deferred=include_deferred,
            include_destructive=include_destructive,
            limit=limit,
        )
        candidate_payloads: list[dict[str, JsonValue]] = []
        for candidate in selected:
            payload = candidate.to_dict()
            if candidate.plan.code == 0x4209:
                payload.update(
                    {
                        "verification_harness": "examples/verify_tmp_ieee80211r_noop.py",
                        "verification_harness_scope": "isolated_source_checkout_lab_only",
                        "live_target_binding_required": True,
                        "lab_write_environment_gate": "DECO_TMP_LAB_ALLOW_WRITES",
                        "execution_available": False,
                    }
                )
            elif candidate.plan.code == 0x421C:
                payload.update(
                    {
                        "verification_harness": "examples/verify_tmp_beamforming_noop.py",
                        "verification_harness_scope": "isolated_source_checkout_lab_only",
                        "live_target_binding_required": True,
                        "lab_write_environment_gate": "DECO_TMP_LAB_ALLOW_WRITES",
                        "live_invoked": candidate.plan.p9_opcode_tested,
                        "execution_available": False,
                    }
                )
            elif candidate.plan.code == 0x4223:
                payload.update(
                    {
                        "verification_harness": ("examples/verify_tmp_monthly_report_noop.py"),
                        "verification_harness_scope": "isolated_source_checkout_lab_only",
                        "live_target_binding_required": True,
                        "lab_write_environment_gate": "DECO_TMP_LAB_ALLOW_WRITES",
                        "live_invoked": candidate.plan.p9_opcode_tested,
                        "execution_available": False,
                    }
                )
            candidate_payloads.append(payload)
        return {
            "transport": "tmp_appv2_over_ssh",
            "model": "P9",
            "offline": True,
            "router_contacted": False,
            "candidate_count": len(all_candidates),
            "tier_counts": dict(
                sorted(Counter(candidate.tier for candidate in all_candidates).items())
            ),
            "verification_candidate_count": sum(
                candidate.verification_candidate for candidate in all_candidates
            ),
            "returned_count": len(selected),
            "returned_tier_counts": dict(
                sorted(Counter(candidate.tier for candidate in selected).items())
            ),
            "filter": {
                "include_sensitive": include_sensitive,
                "include_deferred": include_deferred,
                "include_destructive": include_destructive,
                "limit": limit,
            },
            "explicit_per_operation_authorization_required": True,
            "parameter_values_included": False,
            "payloads_generated": False,
            "mutation_invoked": False,
            "execution_eligible_count": 0,
            "execution_available": False,
            "server_write_policy": "hard_disabled",
            "lab_write_environment_gate": "DECO_TMP_LAB_ALLOW_WRITES",
            "candidates": candidate_payloads,
        }

    def probe_p9_transport_services(
        self,
        *,
        include_nodes: bool = False,
        timeout: float = 2.0,
    ) -> dict[str, JsonValue]:
        """Probe documented transport TCP ports without authenticating or sending payloads."""
        if timeout <= 0 or timeout > 10:
            raise ValueError("Failed to probe P9 services: timeout must be between 0 and 10")
        hosts = [self._config.host]
        if include_nodes:
            with self._lock:
                hosts.extend(
                    device.device_ip
                    for device in self._get_client().get_device_list()
                    if device.device_ip
                )
        unique_hosts = tuple(dict.fromkeys(hosts))
        services = (
            (22, "conventional_ssh"),
            (20001, "tmp_ssh"),
            (20002, "tmp_direct"),
        )
        return {
            "authentication_attempted": False,
            "payload_sent": False,
            "hosts": [
                {
                    "host": host,
                    "services": [
                        _probe_tcp_service(host, port, service, timeout)
                        for port, service in services
                    ],
                }
                for host in unique_hosts
            ],
        }

    def endpoint_catalog(
        self,
        safety: str = "",
        *,
        include_sensitive: bool = False,
        model: str = "",
    ) -> list[dict[str, JsonValue]]:
        """Return operations with optional model-specific compatibility overlays."""
        valid_safety = {"", "read_only", "mutation", "destructive", "internal"}
        if safety not in valid_safety:
            raise ValueError(f"Failed to list endpoints: invalid safety level {safety!r}")
        profile = get_compatibility_profile(model) if model else None
        results: list[dict[str, JsonValue]] = []
        for endpoint in ENDPOINT_CATALOG:
            if safety and endpoint.safety != safety:
                continue
            if not include_sensitive and endpoint.sensitivity == "secret":
                continue
            metadata = endpoint.to_dict()
            if profile is not None:
                metadata["model_compatibility"] = profile.get(endpoint.name).to_dict()
            results.append(metadata)
        return results

    def operation_compatibility(
        self,
        name: str,
        model: str = "P9",
    ) -> dict[str, JsonValue]:
        """Return generic metadata and model evidence for one operation."""
        endpoint = get_endpoint(name)
        profile = get_compatibility_profile(model)
        return {
            "model": profile.model,
            "firmware_version": profile.firmware_version,
            "endpoint": endpoint.to_dict(),
            "compatibility": profile.get(name).to_dict(),
        }

    def network_overview(self) -> dict[str, JsonValue]:
        """Return a compact view of confirmed P9 network and reservation state."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read network overview: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        with self._lock:
            client = self._get_client()
            mode = client.get_device_mode()
            internet = client.get_internet_status()
            wan_info = client.get_wan_info()
            performance = client.get_performance()
            time_settings = client.get_time_settings()
            reservations = client.get_address_reservations()
            wan_mode = client.call(get_endpoint("admin.network.wan_mode.read")).result
            lan_ipv4 = client.get_lan_ipv4()
            lan_ip = client.get_lan_ip()
            vlan = client.call(get_endpoint("admin.network.vlan.read")).result
            mac_clone = client.call(get_endpoint("admin.network.mac_clone.read")).result
        return {
            "device_mode": {
                "workmode": mode.workmode,
                "sysmode": mode.sysmode,
                "region": mode.region,
            },
            "internet": {
                "link_status": internet.link_status,
                "ipv4": {
                    "inet_status": internet.ipv4.inet_status,
                    "dial_status": internet.ipv4.dial_status,
                    "connect_type": internet.ipv4.connect_type,
                    "auto_detect_type": internet.ipv4.auto_detect_type,
                    "error_code": internet.ipv4.error_code,
                },
                "ipv6": {
                    "inet_status": internet.ipv6.inet_status,
                    "dial_status": internet.ipv6.dial_status,
                    "connect_type": internet.ipv6.connect_type,
                    "auto_detect_type": internet.ipv6.auto_detect_type,
                    "error_code": internet.ipv6.error_code,
                },
            },
            "wan": {
                "ip_info": _ip_info(wan_info.wan.ip_info),
                "dial_type": wan_info.wan.dial_type,
                "enable_auto_dns": wan_info.wan.enable_auto_dns,
            },
            "lan": {"ip_info": _ip_info(wan_info.lan.ip_info)},
            "configuration": {
                "wan_mode": wan_mode,
                "lan_ipv4": lan_ipv4,
                "lan_ip": lan_ip,
                "vlan": vlan,
                "mac_clone": mac_clone,
            },
            "performance": {
                "cpu_usage": performance.cpu_usage,
                "mem_usage": performance.mem_usage,
            },
            "time": {
                "time": time_settings.time,
                "date": time_settings.date,
                "timezone": time_settings.timezone,
                "tz_region": time_settings.tz_region,
                "continent": time_settings.continent,
                "dst_status": time_settings.dst_status,
            },
            "address_reservations": {
                "count": len(reservations.reservations),
                "max_count": reservations.max_count,
                "is_full": reservations.is_full,
                "entries": [
                    {"mac": reservation.mac, "ip": reservation.ip}
                    for reservation in reservations.reservations
                ],
            },
        }

    def mesh_overview(self) -> dict[str, JsonValue]:
        """Return mesh-node state with clients queried separately for each node."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read mesh overview: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        with self._lock:
            client = self._get_client()
            devices = client.get_device_list()
            self._device_cache = tuple(devices)
            clients_by_node = client.get_clients_by_node()
        return {
            "node_count": len(devices),
            "nodes": [_device_view(device) for device in devices],
            "clients_by_node": [item.to_dict() for item in clients_by_node],
            "client_assignments": sum(len(item.clients) for item in clients_by_node),
        }

    def wlan_state(self, *, include_passwords: bool = False) -> dict[str, JsonValue]:
        """Return WLAN state, omitting passwords unless the caller explicitly requests them."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read WLAN state: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        capability = self.read_capability(
            "wlan_state",
            include_passwords=include_passwords,
        )
        data, provenance = _capability_resource_parts(capability, "WLAN state")
        inventory = self.device_inventory()
        context = _capability_read_context(capability, inventory)
        features: dict[str, JsonValue] = {
            field_name: None for field_name, _ in _WIRELESS_FEATURE_CAPABILITIES
        }
        unavailable_sections: list[dict[str, JsonValue]] = []
        for field_name, capability_name in _WIRELESS_FEATURE_CAPABILITIES:
            try:
                features[field_name] = self._read_resource_capability(capability_name, context)
            except _LIVE_READ_ERRORS as exc:
                unavailable_sections.append(_configuration_error(f"features.{field_name}", exc))
        return {
            "schema_version": 1,
            "status": "available" if not unavailable_sections else "partial",
            **dict(data),
            "features": features,
            "provenance": dict(provenance),
            "unavailable_sections": unavailable_sections,
            "observed_at_epoch_seconds": time.time(),
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def cloud_state(self) -> dict[str, JsonValue]:
        """Return observed DDNS and cloud-manager state behind the sensitive-read gate."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read cloud state: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        capability = self.read_capability("ddns")
        ddns, provenance = _capability_resource_parts(capability, "DDNS")
        unavailable_sections: list[dict[str, JsonValue]] = []
        manager: JsonValue = None
        if _json_string(provenance, "source_interface") == "http_luci":
            try:
                manager = self.read_endpoint("admin.cloud.manager.get").result
            except _LIVE_READ_ERRORS as exc:
                unavailable_sections.append(_configuration_error("manager", exc))
        else:
            unavailable_sections.append(_source_unavailable("manager"))
        return {
            "schema_version": 1,
            "status": "available" if not unavailable_sections else "partial",
            "ddns": dict(ddns),
            "manager": manager,
            "provenance": dict(provenance),
            "unavailable_sections": unavailable_sections,
            "observed_at_epoch_seconds": time.time(),
            "router_contacted": True,
            "mutation_invoked": False,
        }

    def client_overview(self) -> dict[str, JsonValue]:
        """Return confirmed client, traffic, blacklist, and reservation state."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read client overview: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        with self._lock:
            client = self._get_client()
            clients = tuple(client.get_client_list())
            traffic = client.get_traffic_statistics()
            blacklist = client.call(get_endpoint("admin.client.black_list.list")).result
            reservations = client.get_address_reservations()
        return {
            "clients": NodeClientList("default", clients).to_dict()["clients"],
            "client_count": len(clients),
            "traffic_statistics": traffic,
            "blacklist": blacklist,
            "address_reservations": {
                "count": len(reservations.reservations),
                "max_count": reservations.max_count,
                "is_full": reservations.is_full,
                "entries": [
                    {"mac": reservation.mac, "ip": reservation.ip}
                    for reservation in reservations.reservations
                ],
            },
        }

    def system_overview(self) -> dict[str, JsonValue]:
        """Return confirmed speed-test, firmware, nickname, and log-type state."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read system overview: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        with self._lock:
            client = self._get_client()
            speed_test = client.get_speed_test()
            firmware = client.call(get_endpoint("admin.cloud.firmware_status.read")).result
            nickname = client.call(get_endpoint("admin.cloud.nickname.read")).result
            log_types = client.get_log_types()
        return {
            "speed_test": _speed_test_view(speed_test),
            "firmware_status": firmware,
            "nickname": nickname,
            "log_types": [
                {"name": log_type.name, "value": log_type.value} for log_type in log_types
            ],
        }

    def plan_mutation(
        self,
        name: str,
        params: Mapping[str, JsonValue] | None,
        model: str = "P9",
    ) -> dict[str, JsonValue]:
        """Describe preflight, verification, and rollback without contacting the router."""
        endpoint = get_endpoint(name)
        if endpoint.safety == "read_only":
            raise PermissionError("Failed to plan mutation: operation is read-only")
        compatibility = get_compatibility_profile(model).get(name)
        gate_enabled = {
            "mutation": self._config.allow_mutations,
            "destructive": self._config.allow_destructive,
            "internal": self._config.allow_internal,
        }[endpoint.safety]
        return build_mutation_plan(
            endpoint,
            compatibility,
            params,
            model=model,
            gate_enabled=gate_enabled,
        ).to_dict()

    def preflight_mutation(
        self,
        name: str,
        params: Mapping[str, JsonValue] | None,
        model: str = "P9",
    ) -> dict[str, JsonValue]:
        """Evaluate a known mutation preflight using reads only."""
        endpoint = get_endpoint(name)
        if endpoint.safety == "read_only":
            raise PermissionError("Failed to preflight mutation: operation is read-only")
        endpoint.validate_params(params)
        compatibility = get_compatibility_profile(model).get(name)
        gate_enabled = {
            "mutation": self._config.allow_mutations,
            "destructive": self._config.allow_destructive,
            "internal": self._config.allow_internal,
        }[endpoint.safety]
        plan = build_mutation_plan(
            endpoint,
            compatibility,
            params,
            model=model,
            gate_enabled=gate_enabled,
        )
        if not plan.preflight_read:
            return {
                "plan": plan.to_dict(),
                "preflight_supported": False,
                "preflight_passed": False,
                "reasons": ["no live preflight contract is known"],
                "mutation_invoked": False,
            }
        if endpoint.name not in _HTTP_LIVE_PREFLIGHT_NAMES:
            return {
                "plan": plan.to_dict(),
                "preflight_supported": False,
                "preflight_passed": False,
                "reasons": ["catalogued preflight does not have an evaluator"],
                "mutation_invoked": False,
            }
        _validate_live_preflight_params(plan)
        if endpoint.path != "admin/client" or endpoint.form != "addr_reservation":
            response = self.read_endpoint(plan.preflight_read)
            return _state_preflight(plan, response.result_object())
        with self._lock:
            client = self._get_client()
            try:
                table = client.get_address_reservations()
            except (ApiError, TransportError) as exc:
                if not self._should_relogin(exc):
                    raise
                client.invalidate_session()
                table = self._get_client().get_address_reservations()
        return _reservation_preflight(plan, table)

    def p9_profile(self) -> dict[str, JsonValue]:
        """Return observed P9 reads and untested same-form mutation candidates."""
        observed_reads = tuple(
            endpoint for endpoint in ENDPOINT_CATALOG if endpoint.safety == "read_only"
        )
        supported_reads = tuple(
            endpoint
            for endpoint in observed_reads
            if P9_COMPATIBILITY_PROFILE.get(endpoint.name).availability == "supported"
        )
        return {
            "model": "P9",
            "hardware_versions": list(P9_PROFILE_HARDWARE_VERSIONS),
            "firmware_version": P9_PROFILE_FIRMWARE,
            "observed_at": P9_PROFILE_OBSERVED_AT,
            "catalog_version": CATALOG_VERSION,
            "model_compatibility": P9_COMPATIBILITY_PROFILE.to_dict(include_operations=False),
            "read_observation_counts": dict(
                sorted(
                    Counter(
                        P9_COMPATIBILITY_PROFILE.get(endpoint.name).availability
                        for endpoint in observed_reads
                    ).items()
                )
            ),
            "supported_reads": [endpoint.to_dict() for endpoint in supported_reads],
            "client_topology": {
                "per_node_query": "supported",
                "default_set_matches_per_node_union": True,
                "duplicate_assignments_observed": False,
                "node_association_source": "queried device_mac",
                "access_host_semantics": (
                    "opaque; does not match the queried node MAC or device ID"
                ),
            },
            "fuzzy_read_observation": {
                "observed_at": "2026-07-10T20:55:48.128101+00:00",
                "candidate_count": 237,
                "consistent": 237,
                "rejected": 191,
                "accepted_null": 40,
                "transport_error": 6,
                "returned_data": 0,
                "session_recovered": 1,
                "conclusion": (
                    "bounded read/get/getlist/list aliases and safe parameter variants did not "
                    "identify any additional data-returning P9 endpoint"
                ),
            },
            "web_asset_observation": {
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
            },
            "sensitive_schema_observation": {
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
            },
            "bootstrap_observation": {
                "observed_at": "2026-07-11",
                "attempted": 4,
                "supported": 3,
                "transport_error": 1,
                "authenticated": False,
                "values_retained": False,
                "credential_values_emitted": False,
                "evidence": "docs/api-responses/p9-bootstrap-compatibility.json",
            },
            "domain_login_observation": {
                "observed_at": "2026-07-11T08:40:28Z",
                "authentication": "encrypted_owner_session",
                "availability": "supported",
                "returned_data": False,
                "values_retained": False,
                "evidence": "docs/api-responses/p9-domain-login-compatibility.json",
            },
            "mutation_candidates": [endpoint.to_dict() for endpoint in P9_MUTATION_CANDIDATES],
            "mutation_evidence": (
                "address reservation modify accepted one explicitly authorized unchanged-value "
                "request and preserved complete table equality; beamforming write accepted one "
                "explicitly authorized current-value request and preserved setting equality; "
                "802.11r write accepted one explicitly authorized current-value request and "
                "preserved setting equality; time-settings write accepted one explicitly "
                "authorized current-value request and preserved setting equality; all four are "
                "noop_only and all other candidates remain inferred"
            ),
        }

    def p9_mutation_inventory(self) -> dict[str, JsonValue]:
        """Return P9 mutation evidence and safety-contract coverage without connecting."""
        verification_queue = build_http_mutation_verification_queue(
            include_deferred=True,
            include_destructive=True,
            include_verified=True,
            limit=None,
        )
        candidates: list[dict[str, JsonValue]] = []
        complete_contract_count = 0
        live_preflight_count = 0
        execution_eligible_count = 0
        for endpoint in P9_MUTATION_CANDIDATES:
            compatibility = P9_COMPATIBILITY_PROFILE.get(endpoint.name)
            gate_enabled = {
                "mutation": self._config.allow_mutations,
                "destructive": self._config.allow_destructive,
                "internal": self._config.allow_internal,
            }[endpoint.safety]
            plan = build_mutation_plan(
                endpoint,
                compatibility,
                None,
                model="P9",
                gate_enabled=gate_enabled,
            )
            complete_contract = bool(
                plan.preflight_read and plan.verification_read and plan.rollback_operation
            )
            execution_eligible = bool(
                compatibility.mutation_test_scope == "general"
                and gate_enabled
                and plan.transport_supported
            )
            complete_contract_count += int(complete_contract)
            live_preflight_supported = endpoint.name in _HTTP_LIVE_PREFLIGHT_NAMES
            live_preflight_count += int(live_preflight_supported)
            execution_eligible_count += int(execution_eligible)
            preflight_compatibility = (
                P9_COMPATIBILITY_PROFILE.get(plan.preflight_read).to_dict()
                if plan.preflight_read
                else None
            )
            candidates.append(
                {
                    "endpoint": endpoint.to_dict(),
                    "compatibility": compatibility.to_dict(),
                    "runtime_gate_enabled": gate_enabled,
                    "mutation_test_scope": compatibility.mutation_test_scope,
                    "complete_safety_contract": complete_contract,
                    "live_preflight_supported": live_preflight_supported,
                    "preflight_read": plan.preflight_read,
                    "preflight_compatibility": preflight_compatibility,
                    "preflight_condition": plan.preflight_condition,
                    "verification_read": plan.verification_read,
                    "success_condition": plan.success_condition,
                    "rollback_operation": plan.rollback_operation,
                    "rollback_requires_preflight": plan.rollback_requires_preflight,
                    "plan_warnings": list(plan.warnings),
                    "execution_eligible": execution_eligible,
                    "scoped_noop_execution_supported": (endpoint.name in HTTP_NOOP_CONFIRMATIONS),
                    "scoped_noop_runtime_gate_enabled": (
                        endpoint.name in HTTP_NOOP_CONFIRMATIONS
                        and self._config.allow_mutations
                        and self._config.allow_http_noop_verification
                        and not self._http_mutation_latched
                    ),
                }
            )
        scoped_noop_gate_enabled = (
            self._config.allow_mutations
            and self._config.allow_http_noop_verification
            and not self._http_mutation_latched
        )
        return {
            "model": "P9",
            "firmware_version": P9_PROFILE_FIRMWARE,
            "candidate_count": len(candidates),
            "mutation_tested_count": sum(
                P9_COMPATIBILITY_PROFILE.get(endpoint.name).mutation_tested
                for endpoint in P9_MUTATION_CANDIDATES
            ),
            "complete_safety_contract_count": complete_contract_count,
            "live_preflight_count": live_preflight_count,
            "execution_eligible_count": execution_eligible_count,
            "verification_candidate_count": sum(
                candidate.verification_candidate for candidate in verification_queue
            ),
            "verification_tier_counts": dict(
                sorted(Counter(candidate.tier for candidate in verification_queue).items())
            ),
            "verification_queue_operation": "p9_http_mutation_verification_queue",
            "scoped_noop_executor_count": 2,
            "scoped_noop_operation_count": len(HTTP_NOOP_CONFIRMATIONS),
            "scoped_noop_runtime_gate_enabled": scoped_noop_gate_enabled,
            "scoped_noop_execution_eligible_count": (
                len(HTTP_NOOP_CONFIRMATIONS) if scoped_noop_gate_enabled else 0
            ),
            "scoped_noop_executors": [
                "verify_setting_noop",
                "verify_p9_http_noop",
            ],
            "scoped_noop_operations": [
                {
                    "operation": operation,
                    "preflight_operation": HTTP_NOOP_PREFLIGHT_OPERATIONS[operation],
                    "confirmation": confirmation,
                    "execution_scope": "verified_current_value_noop_only",
                    "required_environment_gates": [
                        "DECO_ALLOW_MUTATIONS",
                        "DECO_ALLOW_HTTP_NOOP_VERIFICATION",
                    ],
                }
                for operation, confirmation in HTTP_NOOP_CONFIRMATIONS.items()
            ],
            "execution_policy": {
                "model_verification_required": True,
                "general_scope_verification_required": True,
                "plan_confirmation_required": True,
                "exact_name_confirmation_required": True,
                "runtime_safety_gate_required": True,
                "noop_only_requires_scoped_executor": True,
            },
            "candidates": candidates,
        }

    def p9_http_mutation_verification_queue(
        self,
        *,
        include_deferred: bool = False,
        include_destructive: bool = False,
        include_verified: bool = False,
        limit: int = 20,
    ) -> dict[str, JsonValue]:
        """Rank HTTP mutations for future authorization without router contact."""
        all_candidates = build_http_mutation_verification_queue(
            include_deferred=True,
            include_destructive=True,
            include_verified=True,
            limit=None,
        )
        selected = build_http_mutation_verification_queue(
            include_deferred=include_deferred,
            include_destructive=include_destructive,
            include_verified=include_verified,
            limit=limit,
        )
        return {
            "transport": "http_encrypted_owner_session",
            "model": "P9",
            "offline": True,
            "router_contacted": False,
            "candidate_count": len(all_candidates),
            "tier_counts": dict(
                sorted(Counter(candidate.tier for candidate in all_candidates).items())
            ),
            "verification_candidate_count": sum(
                candidate.verification_candidate for candidate in all_candidates
            ),
            "returned_count": len(selected),
            "returned_tier_counts": dict(
                sorted(Counter(candidate.tier for candidate in selected).items())
            ),
            "filter": {
                "include_deferred": include_deferred,
                "include_destructive": include_destructive,
                "include_verified": include_verified,
                "limit": limit,
            },
            "explicit_per_operation_authorization_required": True,
            "parameter_values_included": False,
            "payloads_generated": False,
            "mutation_invoked": False,
            "execution_eligible_count": 0,
            "verification_execution_available": False,
            "generic_mutation_operation": "invoke_mutation",
            "generic_mutation_requires_general_scope_evidence": True,
            "candidates": [candidate.to_dict() for candidate in selected],
        }

    def read_endpoint(
        self,
        name: str,
        params: Mapping[str, JsonValue] | None = None,
    ) -> ApiResponse:
        """Call a read-only operation after enforcing the sensitive-data gate."""
        endpoint = get_endpoint(name)
        if endpoint.safety != "read_only":
            raise PermissionError(
                f"Failed to read endpoint: {name} is classified as {endpoint.safety}"
            )
        if endpoint.sensitivity == "secret" and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read endpoint: sensitive reads require DECO_ALLOW_SENSITIVE_READS=1"
            )
        if not endpoint.generic_call_supported and not endpoint.bootstrap_call_supported:
            raise PermissionError(
                f"Failed to read endpoint: transport {endpoint.authentication!r} "
                "is catalogued but not supported by the SDK"
            )
        endpoint.validate_params(params)
        with self._lock:
            if endpoint.bootstrap_call_supported:
                client = DecoClient(
                    self._config.host,
                    "",
                    "",
                    timeout=self._config.timeout,
                )
                return client.call_bootstrap(endpoint, params)
            client = self._get_client()
            try:
                return client.call(endpoint, params)
            except (ApiError, TransportError) as exc:
                if not self._should_relogin(exc):
                    raise
                client.invalidate_session()
                return self._get_client().call(endpoint, params)

    def p9_http_data(
        self,
        controller: str = "",
        *,
        include_sensitive: bool = False,
    ) -> dict[str, JsonValue]:
        """Return complete envelopes for P9-supported HTTP reads by controller."""
        supported = tuple(
            endpoint
            for endpoint in ENDPOINT_CATALOG
            if endpoint.safety == "read_only"
            and (endpoint.generic_call_supported or endpoint.bootstrap_call_supported)
            and P9_COMPATIBILITY_PROFILE.get(endpoint.name).availability == "supported"
        )
        controllers = {endpoint.path for endpoint in supported}
        if controller and controller not in controllers:
            raise ValueError(f"Failed to read P9 HTTP data: unknown controller {controller!r}")
        if include_sensitive and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read P9 HTTP data: DECO_ALLOW_SENSITIVE_READS is disabled"
            )
        in_scope = tuple(
            endpoint for endpoint in supported if not controller or endpoint.path == controller
        )
        selected = tuple(
            endpoint
            for endpoint in in_scope
            if include_sensitive or endpoint.sensitivity != "secret"
        )
        skipped_sensitive = tuple(
            endpoint.name for endpoint in in_scope if endpoint.sensitivity == "secret"
        )
        results: list[dict[str, JsonValue]] = []
        for endpoint in selected:
            try:
                response = self.read_endpoint(endpoint.name, endpoint.default_params)
            except (DecoError, OSError, TimeoutError, ValueError) as exc:
                results.append(
                    {
                        "name": endpoint.name,
                        "controller": endpoint.path,
                        "form": endpoint.form,
                        "status": "error",
                        "error_type": type(exc).__name__,
                    }
                )
                continue
            results.append(
                {
                    "name": endpoint.name,
                    "controller": endpoint.path,
                    "form": endpoint.form,
                    "status": "ok" if response.error_code == 0 else "firmware_error",
                    "response": response.payload,
                }
            )
        return {
            "transport": "http",
            "model": "P9",
            "controller": controller,
            "include_sensitive": include_sensitive,
            "selected_count": len(selected),
            "skipped_sensitive_count": 0 if include_sensitive else len(skipped_sensitive),
            "skipped_sensitive_operations": [] if include_sensitive else list(skipped_sensitive),
            "succeeded_count": sum(result["status"] == "ok" for result in results),
            "firmware_error_count": sum(result["status"] == "firmware_error" for result in results),
            "failed_count": sum(result["status"] == "error" for result in results),
            "values_included": True,
            "mutation_invoked": False,
            "results": results,
        }

    def discover_p9_untested_http_reads(self) -> dict[str, JsonValue]:
        """Probe only untested non-secret P9 HTTP reads with implemented transport."""
        selected = tuple(
            endpoint
            for endpoint in ENDPOINT_CATALOG
            if endpoint.safety == "read_only"
            and endpoint.sensitivity != "secret"
            and (endpoint.generic_call_supported or endpoint.bootstrap_call_supported)
            and P9_COMPATIBILITY_PROFILE.get(endpoint.name).availability == "untested"
        )
        results: list[dict[str, JsonValue]] = []
        for endpoint in selected:
            try:
                response = self.read_endpoint(endpoint.name, endpoint.default_params)
            except (DecoError, OSError, TimeoutError, ValueError) as exc:
                results.append(
                    {
                        "name": endpoint.name,
                        "controller": endpoint.path,
                        "form": endpoint.form,
                        "status": "error",
                        "error_type": type(exc).__name__,
                    }
                )
                continue
            results.append(
                {
                    "name": endpoint.name,
                    "controller": endpoint.path,
                    "form": endpoint.form,
                    "status": "supported" if response.error_code == 0 else "rejected",
                    "error_code": response.error_code,
                    "response": response.payload,
                }
            )
        return {
            "model": "P9",
            "probe_kind": "targeted_untested_nonsecret_http_reads",
            "selected_count": len(selected),
            "selected_operations": [endpoint.name for endpoint in selected],
            "supported_count": sum(result["status"] == "supported" for result in results),
            "rejected_count": sum(result["status"] == "rejected" for result in results),
            "failed_count": sum(result["status"] == "error" for result in results),
            "sensitive_operations_included": False,
            "binary_operations_included": False,
            "mutation_invoked": False,
            "results": results,
        }

    def read_binary_endpoint(
        self,
        name: str,
        *,
        include_content: bool = False,
    ) -> BinaryResponse:
        """Download an explicitly enabled read-only binary endpoint."""
        endpoint = get_endpoint(name)
        if endpoint.safety != "read_only" or endpoint.response_kind != "binary":
            raise PermissionError("Failed to read binary endpoint: operation is not a binary read")
        if endpoint.sensitivity == "secret" and not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read binary endpoint: sensitive reads require "
                "DECO_ALLOW_SENSITIVE_READS=1"
            )
        if not self._config.allow_bulk_secret_reads:
            raise PermissionError(
                "Failed to read binary endpoint: bulk secret reads require "
                "DECO_ALLOW_BULK_SECRET_READS=1"
            )
        if include_content and not self._config.allow_binary_content:
            raise PermissionError(
                "Failed to read binary endpoint: content export requires "
                "DECO_ALLOW_BINARY_CONTENT=1"
            )
        with self._lock:
            client = self._get_client()
            try:
                return client.call_binary(endpoint)
            except TransportError as exc:
                if not self._should_relogin(exc):
                    raise
                client.invalidate_session()
                return self._get_client().call_binary(endpoint)

    def discover_p9_binary_reads(self) -> dict[str, JsonValue]:
        """Download the three P9 binary candidates and return digest metadata only."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to discover P9 binary reads: sensitive reads require "
                "DECO_ALLOW_SENSITIVE_READS=1"
            )
        if not self._config.allow_bulk_secret_reads:
            raise PermissionError(
                "Failed to discover P9 binary reads: bulk secret reads require "
                "DECO_ALLOW_BULK_SECRET_READS=1"
            )
        results: list[dict[str, JsonValue]] = []
        for name in _P9_BINARY_READ_NAMES:
            try:
                response = self.read_binary_endpoint(name)
            except (DecoError, OSError, TimeoutError, ValueError) as exc:
                results.append(
                    {
                        "name": name,
                        "status": "error",
                        "error_type": type(exc).__name__,
                        "binary_content_returned": False,
                    }
                )
                continue
            results.append(
                {
                    "name": name,
                    "status": "received",
                    "media_type": response.media_type,
                    "size": response.size,
                    "sha256": response.sha256,
                    "binary_content_returned": False,
                }
            )
        return {
            "model": "P9",
            "probe_kind": "bulk_secret_binary_digest_only",
            "selected_count": len(_P9_BINARY_READ_NAMES),
            "selected_operations": list(_P9_BINARY_READ_NAMES),
            "received_count": sum(result["status"] == "received" for result in results),
            "failed_count": sum(result["status"] == "error" for result in results),
            "digest_metadata_only": True,
            "binary_content_held_transiently": True,
            "binary_content_returned": False,
            "binary_content_persisted": False,
            "mutation_invoked": False,
            "live_compatibility_promoted": False,
            "results": results,
        }

    def invoke_mutation(
        self,
        name: str,
        params: Mapping[str, JsonValue] | None,
        confirmation: str,
        plan_confirmation: str = "",
        model: str = "P9",
    ) -> ApiResponse:
        """Invoke a model-verified operation bound to an exact reviewed plan."""
        endpoint = get_endpoint(name)
        if endpoint.safety == "read_only":
            raise PermissionError(
                "Failed to mutate endpoint: use the read operation for read-only calls"
            )
        if confirmation != name:
            raise PermissionError(
                "Failed to mutate endpoint: confirmation must exactly match its name"
            )
        if endpoint.safety == "mutation" and not self._config.allow_mutations:
            raise PermissionError(
                "Failed to mutate endpoint: mutations require DECO_ALLOW_MUTATIONS=1"
            )
        if endpoint.safety == "destructive" and not self._config.allow_destructive:
            raise PermissionError(
                "Failed to mutate endpoint: destructive calls require DECO_ALLOW_DESTRUCTIVE=1"
            )
        if endpoint.safety == "internal" and not self._config.allow_internal:
            raise PermissionError(
                "Failed to mutate endpoint: internal calls require DECO_ALLOW_INTERNAL=1"
            )
        if not endpoint.generic_call_supported:
            raise PermissionError(
                f"Failed to mutate endpoint: transport {endpoint.authentication!r} "
                "is catalogued but not supported by the owner-session client"
            )
        endpoint.validate_params(params)
        compatibility = get_compatibility_profile(model).get(name)
        plan = build_mutation_plan(
            endpoint,
            compatibility,
            params,
            model=model,
            gate_enabled=True,
        )
        if plan_confirmation != plan.confirmation_sha256:
            raise PermissionError(
                "Failed to mutate endpoint: plan confirmation must match the reviewed parameters"
            )
        if not compatibility.mutation_tested:
            raise PermissionError(
                f"Failed to mutate endpoint: {name} has not been verified on {model}"
            )
        if compatibility.mutation_test_scope != "general":
            raise PermissionError(
                f"Failed to mutate endpoint: {name} verification is limited to "
                f"{compatibility.mutation_test_scope}"
            )
        with self._lock:
            return self._get_client().call(endpoint, params)

    def validate_operation(
        self,
        name: str,
        params: Mapping[str, JsonValue] | None,
        model: str = "P9",
    ) -> dict[str, JsonValue]:
        """Validate parameters, transport, and model evidence without connecting."""
        endpoint = get_endpoint(name)
        compatibility = get_compatibility_profile(model).get(name)
        missing = endpoint.missing_params(params)
        effective_authentication = compatibility.transport_override or endpoint.authentication
        transport_supported = endpoint.bootstrap_call_supported or (
            effective_authentication in {"encrypted", "plain"}
            and endpoint.response_kind != "binary"
        )
        return {
            "valid": not missing and transport_supported,
            "missing_params": list(missing),
            "provided_params": sorted(params) if params is not None else [],
            "effective_authentication": effective_authentication,
            "transport_supported": transport_supported,
            "endpoint": endpoint.to_dict(),
            "model_compatibility": compatibility.to_dict(),
        }

    def discover_capabilities(self) -> CapabilityReport:
        """Probe only dedicated non-secret capability endpoints."""
        with self._lock:
            return self._get_client().discover_capabilities()

    def discover_p9_reads(self) -> CapabilityReport:
        """Probe the curated non-secret P9 read surface."""
        with self._lock:
            return self._get_client().discover_p9_read_endpoints()

    def discover_all_reads(self) -> CapabilityReport:
        """Probe every non-secret owner-session read catalogued by the SDK."""
        with self._lock:
            return self._get_client().discover_read_endpoints()

    def discover_p9_sensitive_schemas(self) -> tuple[EndpointObservation, ...]:
        """Observe P9 asset-backed secret schemas without returning response values."""
        return self._discover_sensitive_schemas(P9_SENSITIVE_SCHEMA_ENDPOINTS)

    def discover_all_sensitive_schemas(self) -> tuple[EndpointObservation, ...]:
        """Observe every secret owner-session JSON schema without returning values."""
        return self._discover_sensitive_schemas(SENSITIVE_SCHEMA_ENDPOINTS)

    def _discover_sensitive_schemas(
        self,
        endpoints: tuple[EndpointSpec, ...],
    ) -> tuple[EndpointObservation, ...]:
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to discover sensitive schemas: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        with self._lock:
            client = self._get_client()
            return tuple(
                client.observe_endpoint_schema(endpoint, include_sensitive=True)
                for endpoint in endpoints
            )

    def get_clients_by_node(self) -> tuple[NodeClientList, ...]:
        """Return client lists queried separately from every mesh node."""
        if not self._config.allow_sensitive_reads:
            raise PermissionError(
                "Failed to read clients by node: DECO_ALLOW_SENSITIVE_READS=1 is required"
            )
        with self._lock:
            client = self._get_client()
            try:
                return client.get_clients_by_node()
            except (ApiError, TransportError) as exc:
                if not self._should_relogin(exc):
                    raise
                client.invalidate_session()
                return self._get_client().get_clients_by_node()

    def build_compatibility_manifest(self, *, full: bool = False) -> CompatibilityManifest:
        """Build a privacy-preserving compatibility manifest from live reads."""
        with self._lock:
            client = self._get_client()
            devices = client.get_device_list()
            mode = client.get_device_mode()
            report = (
                client.discover_read_endpoints() if full else client.discover_p9_read_endpoints()
            )
        models = tuple(sorted({device.device_model for device in devices if device.device_model}))
        firmware_versions = tuple(
            sorted({device.software_ver for device in devices if device.software_ver})
        )
        return CompatibilityManifest.from_report(
            report,
            catalog_version=CATALOG_VERSION,
            model=", ".join(models),
            hardware_versions=tuple(device.hardware_ver for device in devices),
            firmware_version=", ".join(firmware_versions),
            system_mode=mode.sysmode,
        )

    def _get_client(self) -> DecoClient:
        if not self._config.password:
            raise ValueError("Failed to connect to Deco: DECO_PASSWORD is not configured")
        if self._client is None:
            self._client = DecoClient(
                self._config.host,
                self._config.username,
                self._config.password,
                timeout=self._config.timeout,
            )
        if not self._client.is_authenticated():
            self._client.login()
        return self._client

    def _tmp_ssh_config(self, *, require_host_key: bool = True) -> TmpSshConfig:
        if not self._config.tp_link_id:
            raise ValueError("Failed to connect to TMP: DECO_TP_LINK_ID is not configured")
        if not self._config.password:
            raise ValueError("Failed to connect to TMP: DECO_PASSWORD is not configured")
        if require_host_key and not self._config.tmp_host_key_sha256:
            raise ValueError("Failed to connect to TMP: DECO_TMP_HOST_KEY_SHA256 is not configured")
        return TmpSshConfig(
            host=self._config.host,
            tp_link_id=self._config.tp_link_id,
            password=self._config.password,
            host_key_sha256=self._config.tmp_host_key_sha256,
            timeout=self._config.timeout,
        )

    def _get_tmp_client(self) -> DecoTmpClient:
        if self._tmp_client is None:
            self._tmp_client = DecoTmpClient(self._tmp_ssh_config())
        if not self._tmp_client.connected:
            self._tmp_client.open()
        return self._tmp_client

    @staticmethod
    def _should_relogin(error: ApiError | TransportError) -> bool:
        if isinstance(error, TransportError):
            return error.status_code in {401, 403}
        return error.error_code == -1


def _ip_info(info: IpInfo) -> dict[str, JsonValue]:
    return {
        "ip": info.ip,
        "mask": info.mask,
        "mac": info.mac,
        "gateway": info.gateway,
        "dns1": info.dns1,
        "dns2": info.dns2,
    }


def _capability_response(
    route: CapabilityRoute,
    data: JsonValue,
    attempts: list[dict[str, JsonValue]],
    *,
    fallback_used: bool,
) -> dict[str, JsonValue]:
    selected = attempts[-1]
    return {
        "capability": route.name,
        "schema_version": route.schema_version,
        "data": data,
        "provenance": {
            "source_interface": selected["interface"],
            "source_operation": selected["operation"],
            "fallback_used": fallback_used,
            "fallback_policy": route.fallback_policy,
            "equivalence_evidence": route.equivalence_evidence,
            "attempts": attempts,
        },
        "mutation_invoked": False,
    }


def _capability_resource_parts(
    capability: Mapping[str, JsonValue],
    dataset: str,
) -> tuple[JsonObject, JsonObject]:
    data = capability.get("data")
    provenance = capability.get("provenance")
    if not isinstance(data, Mapping):
        raise ValueError(f"Failed to read {dataset}: data is not an object")
    if not isinstance(provenance, Mapping):
        raise ValueError(f"Failed to read {dataset}: provenance is not an object")
    return data, provenance


def _resource_read_context(
    inventory: Mapping[str, JsonValue],
) -> _ResourceReadContext:
    interface = _json_string(inventory, "identity_interface")
    if interface not in {"http_luci", "tmp_appv2"}:
        raise ValueError("Failed to select resource interface: unknown identity interface")
    return _ResourceReadContext(
        interface=cast("CapabilityInterface", interface),
        source_operation=_json_string(inventory, "identity_source"),
        attempts=_json_rows(inventory.get("identity_attempts")),
        identity_attempts=_json_rows(inventory.get("identity_attempts")),
        fallback_used=get_bool(inventory, "fallback_used"),
    )


def _capability_read_context(
    capability: Mapping[str, JsonValue],
    inventory: Mapping[str, JsonValue],
) -> _ResourceReadContext:
    provenance = capability.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("Failed to select resource interface: provenance is not an object")
    interface = _json_string(provenance, "source_interface")
    if interface not in {"http_luci", "tmp_appv2"}:
        raise ValueError("Failed to select resource interface: unknown capability interface")
    return _ResourceReadContext(
        interface=cast("CapabilityInterface", interface),
        source_operation=_json_string(provenance, "source_operation"),
        attempts=_json_rows(provenance.get("attempts")),
        identity_attempts=_json_rows(inventory.get("identity_attempts")),
        fallback_used=get_bool(provenance, "fallback_used"),
    )


def _mapping_rows(data: Mapping[str, JsonValue], key: str) -> tuple[JsonObject, ...]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(row for row in value if isinstance(row, Mapping))


def _json_rows(value: JsonValue | None) -> tuple[JsonObject, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(row for row in value if isinstance(row, Mapping))


def _merge_client_device(
    records: dict[str, dict[str, JsonValue]],
    client: ClientDevice,
    source: str,
    *,
    connected_node: str | None = None,
) -> None:
    if not client.mac:
        return
    record = records.setdefault(client.mac, _client_device_record(client))
    string_values = {
        "ip": client.ip,
        "name": client.name,
        "client_type": client.client_type,
        "wire_type": client.wire_type,
        "connection_type": client.connection_type,
        "interface": client.interface,
        "space_id": client.space_id,
        "access_host": client.access_host,
        "owner_id": client.owner_id,
    }
    for key, value in string_values.items():
        if value:
            record[key] = value
    record["up_speed"] = client.up_speed
    record["down_speed"] = client.down_speed
    record["remain_time"] = client.remain_time
    active = record.get("active") is True or client.online
    record["active"] = active
    record["status"] = "active" if active else "inactive"
    record["client_mesh"] = record.get("client_mesh") is True or client.client_mesh
    record["prioritized"] = record.get("prioritized") is True or client.enable_priority
    if connected_node:
        record["connected_node"] = connected_node
    _append_device_source(record, source)


def _normalized_client_device(row: JsonObject) -> ClientDevice:
    normalized_mac = ClientDevice.from_api({"mac": get_str(row, "mac")}).mac
    return ClientDevice(
        mac=normalized_mac,
        ip=get_str(row, "ip"),
        name=get_str(row, "name"),
        up_speed=get_int(row, "up_speed"),
        down_speed=get_int(row, "down_speed"),
        wire_type=get_str(row, "wire_type"),
        connection_type=get_str(row, "connection_type"),
        space_id=get_str(row, "space_id"),
        access_host=get_str(row, "access_host"),
        interface=get_str(row, "interface"),
        client_type=get_str(row, "client_type"),
        owner_id=get_str(row, "owner_id"),
        remain_time=get_int(row, "remain_time"),
        online=get_bool(row, "online"),
        client_mesh=get_bool(row, "client_mesh"),
        enable_priority=get_bool(row, "enable_priority"),
    )


def _merge_blocked_device(
    records: dict[str, dict[str, JsonValue]],
    client: ClientDevice,
) -> None:
    if not client.mac:
        return
    record = records.setdefault(client.mac, _client_device_record(client))
    if client.name:
        record["name"] = client.name
    if client.client_type:
        record["client_type"] = client.client_type
    record["blocked"] = True
    record["access_status"] = "blocked"
    _append_device_source(record, "blocked_devices")


def _merge_device_speed(
    records: dict[str, dict[str, JsonValue]],
    speed: JsonObject,
) -> None:
    client = ClientDevice.from_api({"mac": get_str(speed, "mac")})
    if not client.mac:
        return
    record = records.setdefault(client.mac, _client_device_record(client))
    record["up_speed"] = get_int(speed, "up_speed")
    record["down_speed"] = get_int(speed, "down_speed")
    _append_device_source(record, "device_speeds")


def _merge_reserved_device(
    records: dict[str, dict[str, JsonValue]],
    mac: str,
    ip: str,
) -> None:
    client = ClientDevice.from_api({"mac": mac, "ip": ip})
    if not client.mac:
        return
    record = records.setdefault(client.mac, _client_device_record(client))
    if not _record_string(record, "ip"):
        record["ip"] = ip
    record["reserved"] = True
    record["reservation_ip"] = ip
    _append_device_source(record, "address_reservations")


def _client_device_record(client: ClientDevice) -> dict[str, JsonValue]:
    return {
        "mac": client.mac,
        "ip": client.ip,
        "name": client.name,
        "client_type": client.client_type,
        "status": "active" if client.online else "inactive",
        "active": client.online,
        "access_status": "allowed",
        "blocked": False,
        "reserved": False,
        "prioritized": client.enable_priority,
        "reservation_ip": None,
        "up_speed": client.up_speed,
        "down_speed": client.down_speed,
        "wire_type": client.wire_type,
        "connection_type": client.connection_type,
        "interface": client.interface,
        "connected_node": None,
        "space_id": client.space_id,
        "access_host": client.access_host,
        "owner_id": client.owner_id,
        "remain_time": client.remain_time,
        "client_mesh": client.client_mesh,
        "sources": [],
    }


def _append_device_source(record: dict[str, JsonValue], source: str) -> None:
    sources = record.get("sources")
    if isinstance(sources, list) and source not in sources:
        sources.append(source)


def _device_record_matches_view(record: Mapping[str, JsonValue], view: str) -> bool:
    if view == "all":
        return True
    if view == "active":
        return record.get("active") is True
    if view == "inactive":
        return record.get("active") is not True
    return record.get("blocked") is True


def _record_string(record: Mapping[str, JsonValue], key: str) -> str:
    return get_str(record, key)


def _record_integer(record: Mapping[str, JsonValue], key: str) -> int:
    return get_int(record, key)


def _internet_status_view(status: InternetStatus) -> dict[str, JsonValue]:
    return {
        "link_status": status.link_status,
        "ipv4": {
            "inet_status": status.ipv4.inet_status,
            "dial_status": status.ipv4.dial_status,
            "connect_type": status.ipv4.connect_type,
            "auto_detect_type": status.ipv4.auto_detect_type,
            "error_code": status.ipv4.error_code,
        },
        "ipv6": {
            "inet_status": status.ipv6.inet_status,
            "dial_status": status.ipv6.dial_status,
            "connect_type": status.ipv6.connect_type,
            "auto_detect_type": status.ipv6.auto_detect_type,
            "error_code": status.ipv6.error_code,
        },
    }


def _speed_test_view(speed_test: SpeedTest) -> dict[str, JsonValue]:
    return {
        "down_speed": speed_test.down_speed,
        "up_speed": speed_test.up_speed,
        "status": speed_test.status,
        "ever_tested": speed_test.ever_tested,
        "last_speed_test_time": speed_test.last_speed_test_time,
    }


def _address_reservation_view(table: AddressReservationTable) -> dict[str, JsonValue]:
    return {
        "count": len(table.reservations),
        "max_count": table.max_count,
        "is_full": table.is_full,
        "entries": [
            {"mac": reservation.mac, "ip": reservation.ip} for reservation in table.reservations
        ],
    }


def _boolean_setting_view(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    enabled = value.get("enable", value.get("enabled"))
    if not isinstance(enabled, bool):
        raise ValueError("Failed to normalize boolean capability: enable is not a boolean")
    return {"enabled": enabled}


def _tmp_opcode_matches_query(opcode: TmpOpcodeSpec, query: str) -> bool:
    if not query:
        return True
    normalized = query.casefold()
    name = opcode.name.casefold()
    aliases = tuple(alias.casefold() for alias in opcode.aliases)
    hex_code = opcode.hex_code.casefold()
    code = str(opcode.code)
    return any(normalized in value for value in (name, *aliases, hex_code, code))


def _transport_notes(authentication: str) -> str:
    notes = {
        "bootstrap": "four plaintext login reads supported through call_bootstrap()",
        "download": "authenticated binary download supported through call_binary()",
        "encrypted": "owner-session RSA/AES JSON supported",
        "group_key": "mesh discovery/group-key transport is catalogued but not implemented",
        "multipart": (
            "read-only configuration backup is supported; upload, restore, and firmware "
            "upgrade remain unimplemented"
        ),
        "plain": "owner-session plaintext JSON supported",
        "token": "per-node sync token transport is catalogued but not implemented",
    }
    return notes[authentication]


def _http_read_gap_reason(endpoint: EndpointSpec) -> str:
    if endpoint.name in {
        "admin.firmware.config.backup",
        "admin.firmware.config_multipart.backup",
    }:
        return "secret configuration backup intentionally excluded from discovery"
    if endpoint.name == "admin.log_export.save_log.download":
        return "secret log content intentionally excluded from discovery"
    return "model compatibility is untested"


def _probe_tcp_service(
    host: str,
    port: int,
    service: str,
    timeout: float,
) -> dict[str, JsonValue]:
    started = time.monotonic()
    status = "open"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except ConnectionRefusedError:
        status = "refused"
    except TimeoutError:
        status = "timeout"
    except OSError:
        status = "unreachable"
    return {
        "service": service,
        "port": port,
        "status": status,
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }


def _device_view(device: Device) -> dict[str, JsonValue]:
    return {
        "mac": device.mac,
        "ip": device.device_ip,
        "model": device.device_model,
        "type": device.device_type,
        "role": device.role,
        "nickname": device.custom_nickname or device.nickname,
        "hardware_version": device.hardware_ver,
        "software_version": device.software_ver,
        "internet_status": device.inet_status,
        "internet_error": device.inet_error_msg,
        "group_status": device.group_status,
        "connection_type": list(device.connection_type),
        "supports_plc": device.support_plc,
        "signal": {
            "2.4ghz": device.signal_level.band2_4,
            "5ghz": device.signal_level.band5,
            "6ghz": device.signal_level.band6,
        },
    }


def _device_is_online(device: Device) -> bool:
    offline_states = {"disconnected", "down", "error", "failed", "offline"}
    observed_states = {device.group_status.casefold(), device.inet_status.casefold()}
    return observed_states.isdisjoint(offline_states)


def _device_has_weak_wireless_signal(device: Device) -> bool:
    if device.role == "master":
        return False
    band_signals = {
        "band2_4": device.signal_level.band2_4,
        "band5": device.signal_level.band5,
        "band6": device.signal_level.band6,
    }
    active_signals = [
        _signal_level(value)
        for connection_type, value in band_signals.items()
        if connection_type in device.connection_type and _signal_level(value) > 0
    ]
    return bool(active_signals) and max(active_signals) <= 1


def _signal_level(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def _internet_is_online(internet: Mapping[str, JsonValue]) -> bool:
    link_status = internet.get("link_status")
    if isinstance(link_status, str) and link_status.casefold() in {"down", "offline"}:
        return False
    ipv4 = internet.get("ipv4")
    ipv6 = internet.get("ipv6")
    statuses = tuple(
        value.get("inet_status") for value in (ipv4, ipv6) if isinstance(value, Mapping)
    )
    return not statuses or any(
        isinstance(status, str) and status.casefold() in {"connected", "online", "up"}
        for status in statuses
    )


def _numeric_value(value: JsonValue | None) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _network_warning(code: str, message: str) -> dict[str, JsonValue]:
    return {"code": code, "message": message}


def _controller_device(devices: tuple[Device, ...]) -> Device:
    if not devices:
        raise ValueError("Failed to resolve controller identity: device list is empty")
    return next((device for device in devices if device.role == "master"), devices[0])


def _validate_device_inventory(devices: tuple[Device, ...]) -> None:
    controller = _controller_device(devices)
    if not controller.mac or not controller.device_model.strip():
        raise ValueError(
            "Failed to resolve controller identity: controller model and MAC are required"
        )


def _profile_match(controller: Device) -> str:
    if controller.device_model.strip().upper() != "P9":
        return "unknown"
    if (
        controller.hardware_ver in P9_PROFILE_HARDWARE_VERSIONS
        and controller.software_ver == P9_PROFILE_FIRMWARE
    ):
        return "exact"
    return "model_only"


def _controller_model(value: JsonValue) -> str:
    if not isinstance(value, Mapping):
        return ""
    model = value.get("model")
    return model if isinstance(model, str) else ""


def _json_string(value: Mapping[str, JsonValue], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str):
        raise ValueError(f"Failed to read service data: {key} is not a string")
    return selected


def _json_string_list(value: Mapping[str, JsonValue], key: str) -> tuple[str, ...]:
    selected = value.get(key)
    if not isinstance(selected, Sequence) or isinstance(selected, (str, bytes)):
        return ()
    return tuple(item for item in selected if isinstance(item, str))


def _capability_category(name: str) -> str:
    categories = {
        "mesh_nodes": "mesh",
        "clients": "clients",
        "internet_status": "network",
        "address_reservations": "clients",
        "fast_roaming": "wireless",
        "beamforming": "wireless",
        "wireless_operation_mode": "wireless",
        "wireless_bridge": "wireless",
        "traffic": "clients",
        "blocked_clients": "clients",
        "speed_test": "network",
        "firmware_status": "system",
        "ddns": "network",
        "wlan_state": "wireless",
        "ipv4_configuration": "network",
        "led_configuration": "system",
        "ipv6_configuration": "network",
        "ipv6_firewall": "security",
        "ipv6_clients": "clients",
        "lan_configuration": "network",
        "dhcp_configuration": "network",
        "qos_mode": "qos",
        "bandwidth_configuration": "qos",
        "vlan_configuration": "network",
        "port_forwarding": "nat",
        "iptv_configuration": "network",
        "sip_alg": "nat",
        "mac_clone": "network",
    }
    return categories[name]


def _highest_risk(values: set[str]) -> str:
    order = ("read_only", "mutation", "internal", "destructive")
    return max(values, key=order.index)


def _highest_sensitivity(values: set[str]) -> str:
    order = ("normal", "private", "secret")
    return max(values, key=order.index)


def _configuration_error(section: str, error: BaseException) -> dict[str, JsonValue]:
    return {
        "section": section,
        "status": "unavailable",
        "error_type": type(error).__name__,
    }


def _source_unavailable(section: str) -> dict[str, JsonValue]:
    return {
        "section": section,
        "status": "unavailable",
        "error_type": "SourceUnavailable",
    }


def _reservation_preflight(
    plan: MutationPlan,
    table: AddressReservationTable,
) -> dict[str, JsonValue]:
    target_mac = _mutation_mac(plan.params, "mac")
    target_ip = _mutation_ip(plan.params) if plan.name.endswith((".add", ".modify")) else ""
    old_mac_value = plan.params.get("old_mac")
    old_mac = (
        _mutation_mac(plan.params, "old_mac") if isinstance(old_mac_value, str) else target_mac
    )
    by_mac = {reservation.mac: reservation for reservation in table.reservations}
    mac_match = by_mac.get(old_mac)
    ip_match = next(
        (reservation for reservation in table.reservations if reservation.ip == target_ip),
        None,
    )
    reasons: list[str] = []
    rollback_params: dict[str, JsonValue] | None = None
    no_op = False

    if plan.name.endswith(".add"):
        if table.is_full:
            reasons.append("reservation table is full")
        if target_mac in by_mac:
            reasons.append("target MAC already has a reservation")
        if ip_match is not None:
            reasons.append("target IP is already reserved")
    elif plan.name.endswith(".modify"):
        if old_mac != target_mac:
            reasons.append("MAC-changing modify rollback is not verified")
        if mac_match is None:
            reasons.append("target reservation does not exist")
        else:
            rollback_params = {"mac": mac_match.mac, "ip": mac_match.ip}
            no_op = mac_match.mac == target_mac and mac_match.ip == target_ip
        if ip_match is not None and ip_match.mac != old_mac:
            reasons.append("target IP belongs to another reservation")
    elif mac_match is None:
        reasons.append("target reservation does not exist")
    else:
        rollback_params = {"mac": mac_match.mac, "ip": mac_match.ip}

    return {
        "plan": plan.to_dict(),
        "preflight_supported": True,
        "preflight_passed": not reasons,
        "reasons": reasons,
        "observation": {
            "reservation_count": len(table.reservations),
            "max_count": table.max_count,
            "is_full": table.is_full,
            "target_mac_exists": mac_match is not None,
            "target_ip_exists": ip_match is not None if target_ip else None,
            "no_op": no_op,
        },
        "rollback_params": rollback_params,
        "mutation_invoked": False,
    }


def _state_preflight(plan: MutationPlan, state: JsonObject) -> dict[str, JsonValue]:
    if plan.name == "admin.network.wan_mode.write":
        return _wan_mode_preflight(plan, state)
    if plan.name in {
        "admin.wireless.ieee80211r.write",
        "admin.wireless.beamforming.write",
    }:
        return _toggle_preflight(plan, state)
    if plan.name == "admin.wireless.operation_mode.write":
        return _operation_mode_preflight(plan, state)
    if plan.name == "admin.device.timesetting.write":
        return _time_setting_preflight(plan, state)
    return _blacklist_preflight(plan, state)


def _wan_mode_preflight(plan: MutationPlan, state: JsonObject) -> dict[str, JsonValue]:
    target = _mutation_string(plan.params, "mode")
    wan = state.get("wan")
    current = wan.get("mode") if isinstance(wan, dict) else None
    reasons = [] if isinstance(current, str) else ["current WAN mode is unavailable"]
    rollback: dict[str, JsonValue] | None = {"mode": current} if isinstance(current, str) else None
    return _preflight_result(
        plan,
        reasons,
        rollback,
        {"no_op": current == target if isinstance(current, str) else None},
    )


def _toggle_preflight(plan: MutationPlan, state: JsonObject) -> dict[str, JsonValue]:
    target = _mutation_bool(plan.params, "enable")
    current = state.get("enable")
    reasons = [] if isinstance(current, bool) else ["current enable state is unavailable"]
    rollback: dict[str, JsonValue] | None = (
        {"enable": current} if isinstance(current, bool) else None
    )
    return _preflight_result(
        plan,
        reasons,
        rollback,
        {"no_op": current == target if isinstance(current, bool) else None},
    )


def _operation_mode_preflight(plan: MutationPlan, state: JsonObject) -> dict[str, JsonValue]:
    target = _mutation_string(plan.params, "mode")
    current = state.get("mode")
    reasons = [] if isinstance(current, str) else ["current wireless mode is unavailable"]
    rollback: dict[str, JsonValue] | None = {"mode": current} if isinstance(current, str) else None
    return _preflight_result(
        plan,
        reasons,
        rollback,
        {"no_op": current == target if isinstance(current, str) else None},
    )


def _time_setting_preflight(plan: MutationPlan, state: JsonObject) -> dict[str, JsonValue]:
    keys = ("timezone", "continent", "tz_region")
    target = {key: _mutation_string(plan.params, key) for key in keys}
    current = {key: state.get(key) for key in keys}
    valid = all(isinstance(value, str) and value for value in current.values())
    reasons = [] if valid else ["current timezone fields are unavailable"]
    rollback = dict(current) if valid else None
    return _preflight_result(
        plan,
        reasons,
        rollback,
        {"no_op": current == target if valid else None},
    )


def _blacklist_preflight(plan: MutationPlan, state: JsonObject) -> dict[str, JsonValue]:
    target_mac = _mutation_mac(plan.params, "mac")
    value = state.get("client_list")
    entries = [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
    match = next(
        (
            item
            for item in entries
            if isinstance(item.get("mac"), str)
            and item["mac"].replace("-", ":").upper() == target_mac
        ),
        None,
    )
    reasons: list[str] = []
    rollback: dict[str, JsonValue] | None = None
    if plan.name.endswith(".add"):
        if match is not None:
            reasons.append("target MAC is already blacklisted")
        rollback = {"mac": target_mac}
    elif match is None:
        reasons.append("target MAC is not blacklisted")
    else:
        rollback = {"mac": target_mac}
        for key in ("name", "client_type"):
            field = match.get(key)
            if isinstance(field, str):
                rollback[key] = field
    return _preflight_result(
        plan,
        reasons,
        rollback,
        {"target_exists": match is not None, "no_op": False},
    )


def _preflight_result(
    plan: MutationPlan,
    reasons: list[str],
    rollback_params: dict[str, JsonValue] | None,
    observation: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    return {
        "plan": plan.to_dict(),
        "preflight_supported": True,
        "preflight_passed": not reasons,
        "reasons": reasons,
        "observation": observation,
        "rollback_params": rollback_params,
        "mutation_invoked": False,
    }


def _validate_live_preflight_params(plan: MutationPlan) -> None:
    if plan.name.startswith("admin.client.addr_reservation."):
        _validate_reservation_mutation_params(plan)
    elif plan.name in {
        "admin.network.wan_mode.write",
        "admin.wireless.operation_mode.write",
    }:
        _mutation_string(plan.params, "mode")
    elif plan.name in {
        "admin.wireless.ieee80211r.write",
        "admin.wireless.beamforming.write",
    }:
        _mutation_bool(plan.params, "enable")
    elif plan.name == "admin.device.timesetting.write":
        for key in ("timezone", "continent", "tz_region"):
            _mutation_string(plan.params, key)
    else:
        _mutation_mac(plan.params, "mac")
        for key in ("name", "client_type"):
            if key in plan.params:
                _mutation_string(plan.params, key)


def _validate_reservation_mutation_params(plan: MutationPlan) -> None:
    _mutation_mac(plan.params, "mac")
    if plan.name.endswith((".add", ".modify")):
        _mutation_ip(plan.params)
    if "old_mac" in plan.params:
        _mutation_mac(plan.params, "old_mac")


def _mutation_mac(params: dict[str, JsonValue], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Failed to preflight mutation: {key} must be a MAC address")
    normalized = value.replace("-", ":").upper()
    if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", normalized) is None:
        raise ValueError(f"Failed to preflight mutation: {key} must be a MAC address")
    return normalized


def _mutation_ip(params: dict[str, JsonValue]) -> str:
    value = params.get("ip")
    if not isinstance(value, str):
        raise ValueError("Failed to preflight mutation: ip must be an IPv4 address")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise ValueError("Failed to preflight mutation: ip must be an IPv4 address") from exc


def _mutation_string(params: dict[str, JsonValue], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Failed to preflight mutation: {key} must be a non-empty string")
    return value


def _mutation_bool(params: dict[str, JsonValue], key: str) -> bool:
    value = params.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to preflight mutation: {key} must be a boolean")
    return value


def _tmp_owner_ids(responses: Mapping[int, JsonObject]) -> tuple[str, ...]:
    values = (
        *_tmp_result_strings(responses.get(0x4012), "client_list", "owner_id"),
        *_tmp_result_strings(responses.get(0x4029), "owner_list", "owner_id"),
        *_tmp_result_strings(responses.get(0x4060), "owner_list", "owner_id"),
    )
    return tuple(dict.fromkeys(values))[:3]


def _tmp_result_strings(
    payload: JsonObject | None,
    list_name: str,
    key: str,
) -> tuple[str, ...]:
    if payload is None:
        return ()
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return ()
    rows = result.get(list_name)
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return ()
    return tuple(
        value
        for row in rows
        if isinstance(row, Mapping) and isinstance((value := row.get(key)), str) and value
    )


def _tmp_parameterized_requests(
    code: int,
    owner_ids: tuple[str, ...],
) -> tuple[tuple[JsonObject, str], ...]:
    if code in _TMP_OWNER_PARAMETERIZED_OPCODES:
        return tuple(({"owner_id": owner_id}, "confirmed_read.owner_id") for owner_id in owner_ids)
    static: dict[int, JsonObject] = {
        0x403A: {"version": 1029},
        0x4049: {"iot_client_list": []},
        0x4201: {"version": 1},
        0x4202: {"version": 1029},
    }
    params = static.get(code)
    if params is None:
        return ()
    return ((params, "signed_app_confirmed_static_contract"),)


def _validate_tmp_read_params(
    confirmed_parameter_sets: tuple[tuple[str, ...], ...],
    params: JsonValue,
) -> None:
    if not confirmed_parameter_sets:
        return
    if not isinstance(params, Mapping):
        raise ValueError("Failed to read TMP operation: parameters are required")
    provided = frozenset(params)
    allowed = tuple(frozenset(parameter_set) for parameter_set in confirmed_parameter_sets)
    if provided not in allowed:
        expected = " or ".join(
            ",".join(parameter_set) for parameter_set in confirmed_parameter_sets
        )
        raise ValueError(
            f"Failed to read TMP operation: parameter keys must exactly match {expected}"
        )
    owner_id = params.get("owner_id")
    if "owner_id" in provided and (not isinstance(owner_id, str) or not owner_id):
        raise ValueError("Failed to read TMP operation: owner_id must be a non-empty string")
    for key in ("start_time", "end_time", "page", "page_size"):
        value = params.get(key)
        if key in provided and (not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError(f"Failed to read TMP operation: {key} must be an integer")
    version = params.get("version")
    if "version" in provided and (
        not isinstance(version, int) or isinstance(version, bool) or version < 0
    ):
        raise ValueError("Failed to read TMP operation: version must be a non-negative integer")
    iot_clients = params.get("iot_client_list")
    if "iot_client_list" in provided and (
        not isinstance(iot_clients, Sequence)
        or isinstance(iot_clients, (str, bytes))
        or any(not isinstance(item, Mapping) for item in iot_clients)
    ):
        raise ValueError(
            "Failed to read TMP operation: iot_client_list must be an array of objects"
        )
