"""One bounded read-only request variant proposed for compatibility probing."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue
    from ..endpoint_spec import EndpointSpec


@dataclass(frozen=True)
class FuzzyReadCandidate:
    """Describe one auditable read variant without exposing parameter values."""

    endpoint: EndpointSpec
    source_name: str
    variant: str
    params: JsonObject | None

    @property
    def parameter_schema(self) -> tuple[str, ...]:
        """Return parameter names and JSON scalar types without their values."""
        if self.params is None:
            return ()
        return tuple(
            sorted(f"{name}:{_json_scalar_type(value)}" for name, value in self.params.items())
        )


def _json_scalar_type(value: JsonValue) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, Sequence):
        return "array"
    raise TypeError("Failed to describe fuzzy read parameter: unsupported JSON value")
