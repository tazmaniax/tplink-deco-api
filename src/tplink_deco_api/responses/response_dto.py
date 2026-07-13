"""Mapping-compatible base for protocol-neutral response dataclasses."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import cast

from .._json import JsonValue


class ResponseDto(Mapping[str, JsonValue]):
    """Expose a response dataclass as a JSON-compatible immutable mapping."""

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the complete JSON representation of this response."""
        values = cast("dict[str, JsonValue]", vars(self))
        return {key: _response_value(value) for key, value in values.items()}

    def __getitem__(self, key: str) -> JsonValue:
        """Return one serialized response field."""
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        """Iterate over serialized response field names."""
        return iter(self.to_dict())

    def __len__(self) -> int:
        """Return the serialized response field count."""
        return len(self.to_dict())


def _response_value(value: JsonValue) -> JsonValue:
    if isinstance(value, ResponseDto):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {key: _response_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str):
        return [_response_value(item) for item in value]
    return value
