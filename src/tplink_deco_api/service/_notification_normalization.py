"""Normalize positively evidenced Deco notification reads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_notifications(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical notifications while preserving type-specific content."""
    notifications: list[dict[str, JsonValue]] = [
        {
            "id": _required_string(row, "message_id"),
            "type": _required_string(row, "type"),
            "timestamp": _required_int(row, "timestamp"),
            "content": dict(_required_object(row, "content")),
        }
        for row in _required_object_rows(data.get("message_list"))
    ]
    return {
        "notifications": notifications,
        "notification_count": len(notifications),
    }


def _required_object_rows(data: JsonValue) -> tuple[JsonObject, ...]:
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
        raise ValueError("Failed to normalize notifications: message_list is not an array")
    if any(not isinstance(item, Mapping) for item in data):
        raise ValueError("Failed to normalize notifications: message_list contains a non-object")
    return tuple(item for item in data if isinstance(item, Mapping))


def _required_string(data: JsonObject, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Failed to normalize notification: {key} is not a string")
    return value


def _required_int(data: JsonObject, key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize notification: {key} is not an integer")
    return value


def _required_object(data: JsonObject, key: str) -> JsonObject:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"Failed to normalize notification: {key} is not an object")
    return value
