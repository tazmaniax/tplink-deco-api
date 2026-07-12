"""Construct mutation safety plans without opening a router connection."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from .models import MutationPlan

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._json import JsonValue
    from .endpoint_spec import EndpointSpec
    from .models import OperationCompatibility

_FORM_READ_NAMES: dict[tuple[str, str], str] = {
    ("admin/network", "wan_mode"): "admin.network.wan_mode.read",
    ("admin/network", "lan_ip"): "admin.network.lan_ip.read",
    ("admin/network", "vlan"): "admin.network.vlan.read",
    ("admin/network", "mac_clone"): "admin.network.mac_clone.read",
    ("admin/wireless", "operation_mode"): "admin.wireless.operation_mode.read",
    ("admin/wireless", "ieee80211r"): "admin.wireless.ieee80211r.read",
    ("admin/wireless", "beamforming"): "admin.wireless.beamforming.read",
    ("admin/device", "device_list"): "admin.device.device_list.read",
    ("admin/device", "speedtest"): "admin.device.speedtest.read",
    ("admin/device", "timesetting"): "admin.device.timesetting.read",
    ("locale", "lang"): "locale.lang.read",
    ("locale", "country"): "locale.country.read",
    ("admin/client", "black_list"): "admin.client.black_list.list",
    ("admin/client", "addr_reservation"): "admin.client.addr_reservation.getlist",
    ("admin/cloud", "nickname"): "admin.cloud.nickname.read",
    ("admin/cloud", "firmware_status"): "admin.cloud.firmware_status.read",
}

_REVERSIBLE_CONTRACTS: dict[str, tuple[str, str, str]] = {
    "admin.network.wan_mode.write": (
        "capture the current WAN mode before changing it",
        "wan.mode equals the requested mode",
        "admin.network.wan_mode.write",
    ),
    "admin.wireless.ieee80211r.write": (
        "capture the current 802.11r enable state",
        "enable equals the requested boolean",
        "admin.wireless.ieee80211r.write",
    ),
    "admin.wireless.operation_mode.write": (
        "capture the current wireless operation mode",
        "mode equals the requested wireless operation mode",
        "admin.wireless.operation_mode.write",
    ),
    "admin.wireless.beamforming.write": (
        "capture the current beamforming enable state",
        "enable equals the requested boolean",
        "admin.wireless.beamforming.write",
    ),
    "admin.device.timesetting.write": (
        "capture timezone, continent, and region before changing them",
        "timezone, continent, and tz_region equal the requested values",
        "admin.device.timesetting.write",
    ),
    "admin.client.black_list.add": (
        "target MAC is absent from the blacklist",
        "blacklist contains the requested MAC",
        "admin.client.black_list.remove",
    ),
    "admin.client.black_list.remove": (
        "capture the exact existing blacklist entry",
        "blacklist no longer contains the requested MAC",
        "admin.client.black_list.add",
    ),
}

_SUCCESS_CONDITIONS: dict[str, str] = {
    "admin.network.lan_ip.write": "lan_ip contains the requested IP and mask",
    "admin.network.vlan.write": "vlan state reflects the requested configuration",
    "admin.network.vlan.set_vlan": "vlan state reflects the requested VLAN ID and enable state",
    "admin.network.mac_clone.write": "MAC-clone state reflects the requested mode",
    "admin.device.device_list.remove": "device list no longer contains the requested device ID",
    "admin.device.speedtest.write": "speed-test status transitions from idle",
    "admin.device.speedtest.stop": "speed-test status returns to idle",
    "admin.device.timesetting.gmt": "time settings reflect the requested GMT action",
    "locale.lang.write": "language read reflects the requested locale",
    "locale.country.write": "country read reflects the requested value",
    "admin.cloud.nickname.write": "nickname equals the requested value",
    "admin.cloud.firmware_status.upgrade": "firmware status enters an upgrade state",
    "admin.cloud.firmware_status.local_upgrade": "firmware status enters an upgrade state",
}


def build_mutation_plan(
    endpoint: EndpointSpec,
    compatibility: OperationCompatibility,
    params: Mapping[str, JsonValue] | None,
    *,
    model: str,
    gate_enabled: bool,
) -> MutationPlan:
    """Build a dry-run plan with model evidence and rollback metadata."""
    selected_params = dict(params if params is not None else endpoint.default_params or {})
    missing = endpoint.missing_params(selected_params)
    effective_authentication = compatibility.transport_override or endpoint.authentication
    transport_supported = (
        effective_authentication in {"encrypted", "plain"} and endpoint.response_kind != "binary"
    )
    preflight_read = _FORM_READ_NAMES.get((endpoint.path, endpoint.form), "")
    preflight_condition = (
        "capture current state and confirm target-specific safety checks" if preflight_read else ""
    )
    verification_read = preflight_read
    success_condition = _SUCCESS_CONDITIONS.get(
        endpoint.name,
        "manual verification required",
    )
    rollback_operation = ""
    rollback_params: dict[str, JsonValue] | None = None
    rollback_requires_preflight = False

    if endpoint.path == "admin/client" and endpoint.form == "addr_reservation":
        preflight_read = _FORM_READ_NAMES[(endpoint.path, endpoint.form)]
        preflight_condition = _reservation_preflight_condition(endpoint.operation)
        verification_read = preflight_read
        success_condition = _reservation_success_condition(endpoint.operation)
        rollback_operation, rollback_params, rollback_requires_preflight = _reservation_rollback(
            endpoint.operation,
            selected_params,
        )
    elif endpoint.name in _REVERSIBLE_CONTRACTS:
        preflight_condition, success_condition, rollback_operation = _REVERSIBLE_CONTRACTS[
            endpoint.name
        ]
        rollback_requires_preflight = True
        if endpoint.name == "admin.client.black_list.add":
            rollback_params = {"mac": selected_params["mac"]} if "mac" in selected_params else None

    warnings: list[str] = []
    if missing:
        warnings.append(f"missing required params: {', '.join(missing)}")
    if not transport_supported:
        warnings.append(f"transport {effective_authentication!r} is not implemented")
    if not compatibility.mutation_tested:
        warnings.append(f"{model} mutation has not been tested")
    elif compatibility.mutation_test_scope != "general":
        warnings.append(
            f"{model} mutation evidence is limited to {compatibility.mutation_test_scope}"
        )
    if not gate_enabled:
        warnings.append(f"{endpoint.safety} gate is disabled")
    if not preflight_read:
        warnings.append("no preflight read contract is known")
    if not verification_read:
        warnings.append("no verification read contract is known")
    if not rollback_operation:
        warnings.append("no automatic rollback contract is known")
    if endpoint.name == "admin.network.lan_ip.write":
        warnings.append("firmware asset and documented LAN IP parameter names conflict")
    if endpoint.contract_source == "none":
        warnings.append("mutation parameter contract is not documented")

    return MutationPlan(
        name=endpoint.name,
        params=selected_params,
        safety=endpoint.safety,
        model=model,
        model_availability=compatibility.availability,
        model_confidence=compatibility.confidence,
        model_verified=compatibility.mutation_tested,
        model_test_scope=compatibility.mutation_test_scope,
        parameters_valid=not missing,
        missing_params=missing,
        transport_supported=transport_supported,
        gate_enabled=gate_enabled,
        preflight_read=preflight_read,
        preflight_condition=preflight_condition,
        verification_read=verification_read,
        success_condition=success_condition,
        rollback_operation=rollback_operation,
        rollback_params=rollback_params,
        rollback_requires_preflight=rollback_requires_preflight,
        confirmation_sha256=_confirmation_sha256(endpoint.name, selected_params),
        warnings=tuple(warnings),
    )


def _confirmation_sha256(name: str, params: dict[str, JsonValue]) -> str:
    payload = json.dumps(
        {"name": name, "params": params},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _reservation_success_condition(operation: str) -> str:
    if operation == "add":
        return "reservation list contains the requested MAC and IP"
    if operation == "modify":
        return "reservation list contains the requested MAC and updated IP"
    return "reservation list no longer contains the requested MAC"


def _reservation_preflight_condition(operation: str) -> str:
    if operation == "add":
        return "requested MAC and IP are absent and the reservation table has capacity"
    return "the exact existing reservation is captured for rollback before mutation"


def _reservation_rollback(
    operation: str,
    params: dict[str, JsonValue],
) -> tuple[str, dict[str, JsonValue] | None, bool]:
    if operation == "add":
        rollback = {name: params[name] for name in ("mac", "ip") if name in params}
        return "admin.client.addr_reservation.remove", rollback, True
    if operation == "modify":
        return "admin.client.addr_reservation.modify", None, True
    if operation == "remove":
        return "admin.client.addr_reservation.add", None, True
    return "", None, False
