"""Response contract for semantic port-forwarding configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class PortForwardingResponse(ResponseDto):
    """Describe current port-forwarding rules and capacity."""

    schema_version: int
    status: str
    rules: list[JsonObject]
    rule_count: int
    rule_limit: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
