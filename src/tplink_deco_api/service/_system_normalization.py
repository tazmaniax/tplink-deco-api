"""Normalize positively evidenced system-level TMP datasets."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_led_configuration(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical LED state while preserving firmware-native schedule values."""
    return {
        "enabled": _required_bool(data, "enable"),
        "night_mode": {
            "enabled": _required_bool(data, "enable_night_mode"),
            "time_begin": _required_int(data, "time_begin"),
            "time_end": _required_int(data, "time_end"),
        },
    }


def _required_bool(data: JsonObject, key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to normalize LED configuration: {key} is not a boolean")
    return value


def _required_int(data: JsonObject, key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize LED configuration: {key} is not an integer")
    return value
