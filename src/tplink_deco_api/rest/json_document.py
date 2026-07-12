"""Generic validated JSON document returned by semantic REST routes."""

from __future__ import annotations

from typing import TypeAlias

from pydantic import JsonValue

JsonDocument: TypeAlias = dict[str, JsonValue]
