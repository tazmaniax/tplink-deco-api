"""Response contract for sanitized live configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import (  # noqa: TC001 - FastAPI resolves these annotations at runtime.
    JsonObject,
    JsonValue,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ConfigurationResponse(ResponseDto):
    """Describe available configuration sections without secret datasets."""

    schema_version: int
    controller: JsonObject
    related_sections: list[str]
    nickname: JsonValue
    nickname_status: str
    unavailable_sections: list[JsonObject]
    passwords_included: bool
    client_identities_included: bool
    address_reservations_included: bool
    router_contacted: bool
    mutation_invoked: bool
    operating_mode: JsonValue = None
    internet: JsonValue = None
    wan: JsonValue = None
    lan: JsonValue = None
    dhcp: JsonValue = None
    network_features: JsonValue = None
    time_settings: JsonValue = None
    wireless_features: JsonValue = None
