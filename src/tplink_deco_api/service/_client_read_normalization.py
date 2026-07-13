"""Normalize equivalent HTTP and TMP client-enrichment datasets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from ..models import ClientDevice

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_client_traffic(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical per-device and aggregate traffic speeds."""
    rows = _required_object_rows(data, "client_list_speed", "client traffic")
    device_speeds: list[dict[str, JsonValue]] = []
    for row in rows:
        device = ClientDevice.from_api(row)
        device_speeds.append(
            {
                "mac": device.mac,
                "up_speed": _required_int(row, "up_speed", "client traffic"),
                "down_speed": _required_int(row, "down_speed", "client traffic"),
            }
        )
    return {
        "device_speeds": device_speeds,
        "device_count": len(device_speeds),
        "aggregate_speed": {
            "up_speed": sum(_required_int(row, "up_speed", "client traffic") for row in rows),
            "down_speed": sum(_required_int(row, "down_speed", "client traffic") for row in rows),
        },
    }


def normalize_blocked_clients(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical blocked-client identities."""
    rows = _required_object_rows(data, "client_list", "blocked clients")
    devices = tuple(ClientDevice.from_api(row) for row in rows)
    return {
        "devices": [
            {
                "mac": device.mac,
                "name": device.name,
                "client_type": device.client_type,
            }
            for device in devices
        ],
        "device_count": len(devices),
    }


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


def _required_int(data: JsonObject, key: str, dataset: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an integer")
    return value
