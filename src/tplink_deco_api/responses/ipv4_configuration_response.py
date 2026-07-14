"""Response contract for semantic IPv4 configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class Ipv4ConfigurationResponse(ResponseDto):
    """Describe the current IPv4 WAN and LAN configuration."""

    schema_version: int
    status: str
    wan: JsonObject
    lan: JsonObject
    unavailable_fields: list[str]
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
