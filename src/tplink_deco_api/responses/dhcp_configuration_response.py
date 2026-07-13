"""Response contract for semantic DHCP configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class DhcpConfigurationResponse(ResponseDto):
    """Describe the current DHCP pool and resolver configuration."""

    schema_version: int
    status: str
    start_ip: str
    end_ip: str
    gateway: str
    dns_servers: list[str]
    addresses_in_use: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
