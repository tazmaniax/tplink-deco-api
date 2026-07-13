"""Normalize positively evidenced network-configuration TMP datasets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_lan_configuration(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical LAN addressing and upstream address inventory."""
    lan_ip = _required_object(data, "lan_ip", "LAN configuration")
    return {
        "ip": _required_string(lan_ip, "ip", "LAN configuration"),
        "subnet_mask": _required_string(lan_ip, "mask", "LAN configuration"),
        "dns_servers": _required_string_list(data, "dns_server_ip", "LAN configuration"),
        "wan_addresses": _required_string_list(data, "wan_ip", "LAN configuration"),
    }


def normalize_dhcp_configuration(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical DHCP pool and resolver configuration."""
    return {
        "start_ip": _required_string(data, "start_ip", "DHCP configuration"),
        "end_ip": _required_string(data, "end_ip", "DHCP configuration"),
        "gateway": _required_string(data, "gateway", "DHCP configuration"),
        "dns_servers": [
            _required_string(data, "dns1", "DHCP configuration"),
            _required_string(data, "dns2", "DHCP configuration"),
        ],
        "addresses_in_use": _required_int(
            data,
            "ip_amount_in_use",
            "DHCP configuration",
        ),
    }


def normalize_qos_mode(data: JsonObject) -> dict[str, JsonValue]:
    """Return the firmware-provided QoS mode details without inventing semantics."""
    custom_detail = data.get("custom_detail")
    if not isinstance(custom_detail, Sequence) or isinstance(custom_detail, (str, bytes)):
        raise ValueError("Failed to normalize QoS mode: custom_detail is not an array")
    return {
        "custom_detail": list(custom_detail),
        "custom_detail_count": len(custom_detail),
    }


def normalize_bandwidth_configuration(data: JsonObject) -> dict[str, JsonValue]:
    """Return the evidenced bandwidth fields while preserving firmware names."""
    return {
        "has_set_bandwidth": _required_bool(
            data,
            "has_set_bandwidth",
            "bandwidth configuration",
        ),
        "upstream_bandwidth": _required_int(
            data,
            "upstream_bandwidth",
            "bandwidth configuration",
        ),
        "upstream_bandwidth_max": _required_int(
            data,
            "upstream_bandwidth_max",
            "bandwidth configuration",
        ),
        "downstream_bandwidth": _required_int(
            data,
            "downstream_bandwidth",
            "bandwidth configuration",
        ),
        "downstream_bandwidth_max": _required_int(
            data,
            "downstream_bandwidth_max",
            "bandwidth configuration",
        ),
    }


def normalize_vlan_configuration(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical Internet VLAN state."""
    vlan = _required_object(data, "vlan", "VLAN configuration")
    return {"enabled": _required_bool(vlan, "enable", "VLAN configuration")}


def normalize_port_forwarding(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical port-forwarding rules and capacity."""
    rows = _required_object_rows(data, "port_forwarding_list", "port forwarding")
    rules = [
        {
            "id": _required_string(row, "port_forwarding_id", "port-forwarding rule"),
            "service_name": _required_string(row, "service_name", "port-forwarding rule"),
            "service_type": _required_string(row, "service_type", "port-forwarding rule"),
            "internal_ip": _required_string(row, "internal_ip", "port-forwarding rule"),
            "internal_port": _required_string(row, "internal_port", "port-forwarding rule"),
            "external_port": _required_string(row, "external_port", "port-forwarding rule"),
            "protocol": _required_string(row, "protocol", "port-forwarding rule"),
        }
        for row in rows
    ]
    return {
        "rules": rules,
        "rule_count": len(rules),
        "rule_limit": _required_int(
            data,
            "port_forwarding_list_max_count",
            "port forwarding",
        ),
    }


def normalize_iptv_configuration(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical IPTV state and mode."""
    return {
        "enabled": _required_bool(data, "enable", "IPTV configuration"),
        "mode": _required_string(data, "type", "IPTV configuration"),
    }


def normalize_sip_alg(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical SIP ALG state."""
    return {"enabled": _required_bool(data, "enable", "SIP ALG")}


def normalize_mac_clone(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical WAN MAC-clone state."""
    return {"enabled": _required_bool(data, "enable", "MAC clone")}


def _required_object(data: JsonObject, key: str, dataset: str) -> JsonObject:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an object")
    return value


def _required_object_rows(
    data: JsonObject,
    key: str,
    dataset: str,
) -> tuple[JsonObject, ...]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an array")
    if any(not isinstance(item, Mapping) for item in value):
        raise ValueError(f"Failed to normalize {dataset}: {key} contains a non-object")
    return tuple(item for item in value if isinstance(item, Mapping))


def _required_string_list(data: JsonObject, key: str, dataset: str) -> list[JsonValue]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an array")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"Failed to normalize {dataset}: {key} contains a non-string")
    return [item for item in value if isinstance(item, str)]


def _required_string(data: JsonObject, key: str, dataset: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not a string")
    return value


def _required_bool(data: JsonObject, key: str, dataset: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not a boolean")
    return value


def _required_int(data: JsonObject, key: str, dataset: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an integer")
    return value
