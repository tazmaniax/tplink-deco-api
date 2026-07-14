"""Normalize positively evidenced IPv6 TMP datasets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from ..models import ClientDevice

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_ipv6_configuration(data: JsonObject) -> dict[str, JsonValue]:
    """Return the canonical IPv6 WAN and LAN configuration."""
    wan = _required_object(data, "wan", "IPv6 configuration")
    wan_ip = _required_object(wan, "ip_info", "IPv6 WAN configuration")
    lan = _required_object(data, "lan", "IPv6 configuration")
    return {
        "enabled": _required_bool(data, "enable_ipv6", "IPv6 configuration"),
        "wan": {
            "dial_type": _required_string(wan, "dial_type", "IPv6 WAN configuration"),
            "automatic_dns": _required_bool(
                wan,
                "enable_auto_dns",
                "IPv6 WAN configuration",
            ),
            "prefix_delegation": _required_bool(
                wan,
                "enable_prefix_delegation",
                "IPv6 WAN configuration",
            ),
            "address_type": _required_string(
                wan,
                "get_addr_type",
                "IPv6 WAN configuration",
            ),
            "ip": _required_string(wan_ip, "ip", "IPv6 WAN address"),
            "dns_servers": [
                _required_string(wan_ip, "dns1", "IPv6 WAN address"),
                _required_string(wan_ip, "dns2", "IPv6 WAN address"),
            ],
        },
        "lan": {
            "assignment_type": _required_string(
                lan,
                "assigned_type",
                "IPv6 LAN configuration",
            ),
            "ip": _required_string(lan, "ip", "IPv6 LAN configuration"),
            "prefix": _required_string(lan, "prefix", "IPv6 LAN configuration"),
        },
    }


def normalize_ipv6_firewall(data: JsonObject) -> dict[str, JsonValue]:
    """Return the canonical IPv6 inbound-firewall rule table."""
    rules = _required_object_rows(data, "firewall_list", "IPv6 firewall")
    return {
        "rules": [dict(rule) for rule in rules],
        "rule_count": len(rules),
        "rule_limit": _required_int(data, "firewall_list_limit", "IPv6 firewall"),
    }


def normalize_ipv6_clients(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical IPv6 client identities from the neighbor table."""
    rows = _required_object_rows(data, "client_list", "IPv6 clients")
    devices = tuple(ClientDevice.from_api(row) for row in rows)
    return {
        "devices": [
            {
                "mac": device.mac,
                "ip": device.ip,
                "name": device.name,
                "client_type": device.client_type,
            }
            for device in devices
        ],
        "device_count": len(devices),
    }


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
