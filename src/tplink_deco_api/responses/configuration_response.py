"""Response contract for sanitized live configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import (  # noqa: TC001 - FastAPI resolves these at runtime.
    JsonData,
    JsonRecord,
    JsonSection,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class ConfigurationResponse(ResponseDto):
    """Describe available configuration sections without secret datasets."""

    schema_version: int
    controller: JsonSection
    related_sections: list[str]
    nickname: JsonData
    nickname_status: str
    unavailable_sections: list[JsonRecord]
    passwords_included: bool
    client_identities_included: bool
    address_reservations_included: bool
    router_contacted: bool
    mutation_invoked: bool
    operating_mode: JsonData = None
    internet: JsonData = None
    wan: JsonData = None
    lan: JsonData = None
    dhcp: JsonData = None
    network_features: JsonData = None
    time_settings: JsonData = None
    wireless_features: JsonData = None
