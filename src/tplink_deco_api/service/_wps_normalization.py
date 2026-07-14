"""Normalize positively evidenced Wi-Fi Protected Setup reads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_wps_status(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical WPS state while correcting firmware field spelling."""
    value = data.get("wps_list")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("Failed to normalize WPS status: wps_list is not an array")
    if any(not isinstance(item, Mapping) for item in value):
        raise ValueError("Failed to normalize WPS status: wps_list contains a non-object")
    sessions: list[dict[str, JsonValue]] = [
        {
            "device_id": _required_string(row, "device_id"),
            "state": _required_string(row, "wps_state"),
            "remaining_time": _required_int(row, "remaing_time"),
            "client_accessed": _required_bool(row, "client_accessed"),
            "last_error_code": _required_int(row, "last_error_code"),
        }
        for row in value
        if isinstance(row, Mapping)
    ]
    return {
        "scanning_time": _required_int(data, "scanning_time"),
        "sessions": sessions,
        "session_count": len(sessions),
    }


def _required_string(data: JsonObject, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Failed to normalize WPS status: {key} is not a string")
    return value


def _required_int(data: JsonObject, key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize WPS status: {key} is not an integer")
    return value


def _required_bool(data: JsonObject, key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to normalize WPS status: {key} is not a boolean")
    return value
