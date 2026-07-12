"""Observed result of safely probing one Deco endpoint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from .._json import JsonValue
    from ..endpoint_spec import EndpointSpec
    from .api_response import ApiResponse

ProbeStatus: TypeAlias = Literal[
    "supported",
    "rejected",
    "not_found",
    "transport_error",
    "invalid_response",
]


@dataclass(frozen=True)
class EndpointProbeResult:
    """Record endpoint availability without conflating rejection with absence."""

    endpoint: EndpointSpec
    status: ProbeStatus
    elapsed_seconds: float
    response: ApiResponse | None = None
    error_code: int | None = None
    http_status: int | None = None
    error: str = ""

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a JSON-compatible, token-free probe record."""
        return {
            "endpoint": self.endpoint.to_dict(),
            "status": self.status,
            "elapsed_seconds": self.elapsed_seconds,
            "error_code": self.error_code,
            "http_status": self.http_status,
            "error": self.error,
            "result": self.response.result if self.response is not None else None,
        }
