"""Normalize positively evidenced mesh-level TMP datasets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_mesh_traffic(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical per-node traffic speeds without inferring firmware units."""
    value = data.get("device_list_speed")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("Failed to normalize mesh traffic: device_list_speed is not an array")
    if any(not isinstance(item, Mapping) for item in value):
        raise ValueError(
            "Failed to normalize mesh traffic: device_list_speed contains a non-object"
        )
    node_speeds: list[dict[str, JsonValue]] = [
        {
            "device_id": _required_string(row, "device_id"),
            "up_speed": _required_int(row, "up_speed"),
            "down_speed": _required_int(row, "down_speed"),
        }
        for row in value
        if isinstance(row, Mapping)
    ]
    node_speeds.sort(key=lambda row: str(row["device_id"]))
    return {
        "node_speeds": node_speeds,
        "node_count": len(node_speeds),
    }


def _required_string(data: JsonObject, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Failed to normalize mesh traffic: {key} is not a non-empty string")
    return value


def _required_int(data: JsonObject, key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize mesh traffic: {key} is not an integer")
    return value
