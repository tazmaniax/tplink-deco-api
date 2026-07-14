"""Normalize positively evidenced speed-test reads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue


def normalize_speed_test_servers(data: JsonObject) -> dict[str, JsonValue]:
    """Return automatic-selection state and model-specific server records."""
    automatic_selection = data.get("is_auto")
    if not isinstance(automatic_selection, bool):
        raise ValueError("Failed to normalize speed-test servers: is_auto is not a boolean")
    server_list = data.get("server_list")
    if not isinstance(server_list, Sequence) or isinstance(server_list, (str, bytes)):
        raise ValueError("Failed to normalize speed-test servers: server_list is not an array")
    if any(not isinstance(item, Mapping) for item in server_list):
        raise ValueError(
            "Failed to normalize speed-test servers: server_list contains a non-object"
        )
    servers: list[dict[str, JsonValue]] = [
        dict(item) for item in server_list if isinstance(item, Mapping)
    ]
    return {
        "automatic_selection": automatic_selection,
        "servers": servers,
        "server_count": len(servers),
    }
