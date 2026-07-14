"""Normalize positively evidenced parental-control reads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_parental_control_profiles(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical parental-control profile policies."""
    profiles = [
        _parental_control_profile(row)
        for row in _required_object_rows(
            data.get("owner_list"),
            "parental-control profiles owner_list",
        )
    ]
    return {
        "profiles": profiles,
        "profile_count": len(profiles),
    }


def normalize_parental_control_profile(data: JsonObject) -> dict[str, JsonValue]:
    """Return one canonical parental-control profile policy."""
    return {"profile": _parental_control_profile(data)}


def normalize_parental_control_filter_levels(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical default parental-control filtering levels."""
    filter_levels = [
        _filter_level(row)
        for row in _required_object_rows(
            data.get("filter_level_list"),
            "parental-control filter levels filter_level_list",
        )
    ]
    return {
        "filter_levels": filter_levels,
        "filter_level_count": len(filter_levels),
    }


def normalize_parental_control_catalog(data: JsonObject) -> dict[str, JsonValue]:
    """Return the canonical website and application filter catalogue."""
    entries = [
        {"name": _required_string(row, "name", "parental-control catalogue entry")}
        for row in _required_object_rows(
            data.get("website_app_list"),
            "parental-control catalogue website_app_list",
        )
    ]
    return {
        "has_app_filter": _required_bool(
            data,
            "has_app_filter",
            "parental-control catalogue",
        ),
        "needs_update": _required_bool(
            data,
            "need_up_to_date",
            "parental-control catalogue",
        ),
        "version": _required_int(data, "version", "parental-control catalogue"),
        "entries": entries,
        "entry_count": len(entries),
    }


def normalize_parental_control_insights(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical online-usage insights for one profile."""
    insights: list[dict[str, JsonValue]] = [
        {
            "spend_online": _required_int(
                row,
                "spend_online",
                "parental-control insight",
            ),
            "websites": _required_array(
                row,
                "website_list",
                "parental-control insight",
            ),
        }
        for row in _required_object_rows(
            data.get("insights"),
            "parental-control insights",
        )
    ]
    return {
        "owner_id": _required_string(data, "owner_id", "parental-control insights"),
        "insights": insights,
        "insight_count": len(insights),
    }


def normalize_parental_control_history(data: JsonObject) -> dict[str, JsonValue]:
    """Return canonical browsing history for one parental-control profile."""
    history = [
        {
            "access_timestamp": _required_string(
                row,
                "access_timestamp",
                "parental-control history entry",
            ),
            "website": _required_string(
                row,
                "website",
                "parental-control history entry",
            ),
        }
        for row in _required_object_rows(
            data.get("history"),
            "parental-control history",
        )
    ]
    return {
        "owner_id": _required_string(data, "owner_id", "parental-control history"),
        "history": history,
        "history_count": len(history),
    }


def _parental_control_profile(data: JsonObject) -> dict[str, JsonValue]:
    bed_time = _required_object(data, "bed_time", "parental-control profile")
    filter_detail = _required_object(
        data,
        "filter_level_detail",
        "parental-control profile",
    )
    time_limits = _required_object(data, "time_limits", "parental-control profile")
    return {
        "owner_id": _required_string(data, "owner_id", "parental-control profile"),
        "name": _required_string(data, "name", "parental-control profile"),
        "avatar_md5": _optional_string(data, "avatar_md5", "parental-control profile"),
        "internet_blocked": _required_bool(
            data,
            "internet_blocked",
            "parental-control profile",
        ),
        "filter": {
            "level": _required_string(data, "filter_level", "parental-control profile"),
            "categories": _required_string_array(
                filter_detail,
                "categories_list",
                "parental-control profile filter",
            ),
            "websites": _required_array(
                filter_detail,
                "website_list",
                "parental-control profile filter",
            ),
        },
        "bedtime": {
            "workdays": {
                "enabled": _required_bool(
                    bed_time,
                    "enable_workday_bed_time",
                    "parental-control profile bedtime",
                ),
                "begin": _required_int_or_string(
                    bed_time,
                    "workday_bed_time_begin",
                    "parental-control profile bedtime",
                ),
                "end": _required_int_or_string(
                    bed_time,
                    "workday_bed_time_end",
                    "parental-control profile bedtime",
                ),
            },
            "weekends": {
                "enabled": _required_bool(
                    bed_time,
                    "enable_weekend_bed_time",
                    "parental-control profile bedtime",
                ),
                "begin": _required_int_or_string(
                    bed_time,
                    "weekend_bed_time_begin",
                    "parental-control profile bedtime",
                ),
                "end": _required_int_or_string(
                    bed_time,
                    "weekend_bed_time_end",
                    "parental-control profile bedtime",
                ),
            },
        },
        "time_limits": {
            "workdays": {
                "enabled": _required_bool(
                    time_limits,
                    "enable_workday_time_limit",
                    "parental-control profile time limits",
                ),
                "daily_time": _required_int(
                    time_limits,
                    "workday_daily_time",
                    "parental-control profile time limits",
                ),
            },
            "weekends": {
                "enabled": _required_bool(
                    time_limits,
                    "enable_weekend_time_limit",
                    "parental-control profile time limits",
                ),
                "daily_time": _required_int(
                    time_limits,
                    "weekend_daily_time",
                    "parental-control profile time limits",
                ),
            },
        },
        "insights": _required_int_or_string(
            data,
            "insights",
            "parental-control profile",
        ),
        "workday": _required_int(data, "workday", "parental-control profile"),
        "weekend": _required_int(data, "weekend", "parental-control profile"),
    }


def _filter_level(data: JsonObject) -> dict[str, JsonValue]:
    detail = _required_object(data, "filter_level_detail", "parental-control filter level")
    return {
        "level": _required_string(data, "filter_level", "parental-control filter level"),
        "categories": [
            dict(row)
            for row in _required_object_rows(
                detail.get("categories_list"),
                "parental-control filter-level categories",
            )
        ],
        "websites": _required_array(
            detail,
            "website_list",
            "parental-control filter level",
        ),
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


def _required_array(data: JsonObject, key: str, dataset: str) -> list[JsonValue]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an array")
    return list(value)


def _required_string(data: JsonObject, key: str, dataset: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not a string")
    return value


def _optional_string(data: JsonObject, key: str, dataset: str) -> str | None:
    value = data.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not a string")
    return value


def _required_int(data: JsonObject, key: str, dataset: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an integer")
    return value


def _required_int_or_string(data: JsonObject, key: str, dataset: str) -> int | str:
    value = data.get(key)
    if not isinstance(value, (int, str)) or isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an integer or string")
    return value


def _required_bool(data: JsonObject, key: str, dataset: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not a boolean")
    return value


def _required_string_array(data: JsonObject, key: str, dataset: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {dataset}: {key} is not an array")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"Failed to normalize {dataset}: {key} contains a non-string")
    return [item for item in value if isinstance(item, str)]
