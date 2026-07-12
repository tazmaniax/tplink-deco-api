"""Mapping-compatible base for protocol-neutral response dataclasses."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import cast

from .json_types import JsonData, ResponseDocument


class ResponseDto(Mapping[str, JsonData]):
    """Expose a response dataclass as a JSON-compatible immutable mapping."""

    def to_dict(self) -> ResponseDocument:
        """Return the complete JSON representation of this response."""
        values = cast(
            "dict[str, JsonData | ResponseDto | list[ResponseDto]]",
            vars(self),
        )
        return {key: _response_value(value) for key, value in values.items()}

    def __getitem__(self, key: str) -> JsonData:
        """Return one serialized response field."""
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        """Iterate over serialized response field names."""
        return iter(self.to_dict())

    def __len__(self) -> int:
        """Return the serialized response field count."""
        return len(self.to_dict())


def _response_value(value: JsonData | ResponseDto | list[ResponseDto]) -> JsonData:
    if isinstance(value, ResponseDto):
        return cast("JsonData", value.to_dict())
    if isinstance(value, list):
        return cast(
            "JsonData",
            [item.to_dict() if isinstance(item, ResponseDto) else item for item in value],
        )
    return value
