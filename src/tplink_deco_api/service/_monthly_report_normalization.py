"""Normalize positively evidenced monthly report reads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from ..models import ClientDevice

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_monthly_report_settings(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical monthly report generation state."""
    return {"enabled": _required_bool(data, "enable", "monthly report settings")}


def normalize_monthly_reports(data: JsonValue) -> dict[str, JsonValue]:
    """Return canonical monthly reports without dropping sensitive observations."""
    reports = _required_object_rows(data, "monthly reports")
    normalized = [_monthly_report(report) for report in reports]
    return {
        "reports": normalized,
        "report_count": len(normalized),
    }


def _monthly_report(data: JsonObject) -> dict[str, JsonValue]:
    daily = _required_object(data, "calculat_daily_clients", "monthly report")
    parental_control = _required_object(data, "parental_control", "monthly report")
    security = _required_object(data, "security", "monthly report")
    return {
        "year": _required_int(data, "year", "monthly report"),
        "month": _required_int(data, "month", "monthly report"),
        "daily_clients": {
            "client_counts": list(_required_int_array(daily, "client_count_list", "daily clients")),
            "new_clients": [
                _new_client(row)
                for row in _required_object_rows(
                    daily.get("new_client_list"),
                    "daily clients new_client_list",
                )
            ],
        },
        "parental_control": {
            "has_app_filter": _required_bool(
                parental_control,
                "has_app_filter",
                "monthly report parental control",
            ),
            "owners": [
                _parental_control_owner(row)
                for row in _required_object_rows(
                    parental_control.get("owners"),
                    "monthly report parental control owners",
                )
            ],
        },
        "security": {
            "issues": list(
                _required_string_array(
                    security,
                    "security_issue_list",
                    "monthly report security",
                )
            )
        },
    }


def _new_client(data: JsonObject) -> dict[str, JsonValue]:
    client = ClientDevice.from_api(data)
    return {
        "date": _required_string(data, "date", "monthly report new client"),
        "mac": client.mac,
        "name": client.name,
    }


def _parental_control_owner(data: JsonObject) -> dict[str, JsonValue]:
    forbidden = data.get("forbidden_app_web_list")
    if not isinstance(forbidden, Sequence) or isinstance(forbidden, (str, bytes)):
        raise ValueError(
            "Failed to normalize monthly report owner: forbidden_app_web_list is not an array"
        )
    return {
        "owner_id": _required_string(data, "owner_id", "monthly report owner"),
        "name": _required_string(data, "owner_name", "monthly report owner"),
        "app_web_activity": [
            {
                "url": _required_string(row, "url", "monthly report app/web activity"),
                "online_duration": _required_int(
                    row,
                    "online_duration",
                    "monthly report app/web activity",
                ),
            }
            for row in _required_object_rows(
                data.get("app_web_list"),
                "monthly report owner app_web_list",
            )
        ],
        "forbidden_app_web_list": list(forbidden),
    }


def _required_object(data: JsonObject, key: str, dataset: str) -> JsonObject:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an object")
    return value


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


def _required_int(data: JsonObject, key: str, dataset: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an integer")
    return value


def _required_bool(data: JsonObject, key: str, dataset: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not a boolean")
    return value


def _required_int_array(data: JsonObject, key: str, dataset: str) -> tuple[int, ...]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an array")
    if any(not isinstance(item, int) or isinstance(item, bool) for item in value):
        raise ValueError(f"Failed to normalize {dataset}: {key} contains a non-integer")
    return tuple(item for item in value if isinstance(item, int) and not isinstance(item, bool))


def _required_string_array(data: JsonObject, key: str, dataset: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an array")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"Failed to normalize {dataset}: {key} contains a non-string")
    return tuple(item for item in value if isinstance(item, str))
