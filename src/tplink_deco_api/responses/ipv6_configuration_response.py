"""Response contract for semantic IPv6 configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class Ipv6ConfigurationResponse(ResponseDto):
    """Describe the current IPv6 WAN and LAN configuration."""

    schema_version: int
    status: str
    enabled: bool
    wan: JsonObject
    lan: JsonObject
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
