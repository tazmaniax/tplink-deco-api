"""Complete response envelope returned by a Deco API operation."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, JsonValue, get_int, get_str


@dataclass(frozen=True)
class ApiResponse:
    """Preserve all fields returned by the firmware response envelope."""

    error_code: int
    result: JsonValue
    data: JsonValue
    message: str
    config_version: JsonValue
    payload: JsonObject

    @classmethod
    def from_api(cls, payload: JsonObject) -> ApiResponse:
        """Build an ``ApiResponse`` without discarding firmware-specific fields."""
        return cls(
            error_code=get_int(payload, "error_code") or get_int(payload, "errorcode"),
            result=payload.get("result"),
            data=payload.get("data"),
            message=get_str(payload, "msg") or get_str(payload, "message"),
            config_version=payload.get("config_version"),
            payload=payload,
        )

    def result_object(self) -> JsonObject:
        """Return the result as an object, or an empty object for another shape."""
        return self.result if isinstance(self.result, dict) else {}

    def result_list(self) -> list[JsonObject]:
        """Return object entries from a list result, dropping other item types."""
        if not isinstance(self.result, list):
            return []
        return [item for item in self.result if isinstance(item, dict)]
