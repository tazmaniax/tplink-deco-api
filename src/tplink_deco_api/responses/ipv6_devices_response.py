"""Response contract for semantic IPv6 client inventory."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class Ipv6DevicesResponse(ResponseDto):
    """Describe client identities observed in the IPv6 neighbor table."""

    schema_version: int
    status: str
    devices: list[JsonObject]
    device_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
