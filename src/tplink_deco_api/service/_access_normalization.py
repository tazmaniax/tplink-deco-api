"""Normalize positively evidenced access-control reads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_access_permissions(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical manager roles and component-access policies."""
    roles: list[dict[str, JsonValue]] = [
        {
            "role": _required_string(row, "role", "manager role"),
            "enabled": _required_bool(row, "enable", "manager role"),
        }
        for row in _required_object_rows(
            data.get("manager_role_list"),
            "access permissions manager_role_list",
        )
    ]
    permission_profiles = [
        _permission_profile(row)
        for row in _required_object_rows(
            data.get("permission_profile"),
            "access permissions permission_profile",
        )
    ]
    return {
        "roles": roles,
        "role_count": len(roles),
        "permission_profiles": permission_profiles,
        "permission_profile_count": len(permission_profiles),
    }


def _permission_profile(data: JsonObject) -> dict[str, JsonValue]:
    return {
        "role": _required_string(data, "role", "permission profile"),
        "forbidden_components": _required_string_array(
            data,
            "forbidden_component_list",
            "permission profile",
        ),
        "component_locks": [
            {
                "component": _required_string(row, "component", "component lock"),
                "lock": _required_int(row, "lock", "component lock"),
            }
            for row in _required_object_rows(
                data.get("lock_component_list"),
                "permission profile lock_component_list",
            )
        ],
    }


def _required_object_rows(data: JsonValue, dataset: str) -> tuple[JsonObject, ...]:
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: value is not an array")
    if any(not isinstance(item, Mapping) for item in data):
        raise ValueError(f"Failed to normalize {dataset}: array contains a non-object")
    return tuple(item for item in data if isinstance(item, Mapping))


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


def _required_string_array(data: JsonObject, key: str, dataset: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an array")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"Failed to normalize {dataset}: {key} contains a non-string")
    return [item for item in value if isinstance(item, str)]
