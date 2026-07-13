"""Response contract for semantic LAN configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class LanConfigurationResponse(ResponseDto):
    """Describe current LAN addressing and upstream address inventory."""

    schema_version: int
    status: str
    ip: str
    subnet_mask: str
    dns_servers: list[str]
    wan_addresses: list[str]
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
