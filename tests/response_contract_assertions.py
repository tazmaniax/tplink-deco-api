"""Assertions for DTO drift against service-produced response payloads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import TypeAdapter

if TYPE_CHECKING:
    from collections.abc import Mapping

    from tplink_deco_api._json import JsonValue
    from tplink_deco_api.responses import ResponseDto


def assert_response_contract(
    response_type: type[ResponseDto],
    payload: Mapping[str, JsonValue],
) -> None:
    """Require exact dataclass fields and runtime-valid nested response values."""
    constructed = response_type(**dict(payload))
    validated = TypeAdapter(response_type).validate_python(payload)

    assert constructed.to_dict() == validated.to_dict()
