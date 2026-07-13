"""Response contract for available system-log levels."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class LogTypesResponse(ResponseDto):
    """Describe log levels and snapshot preparation without log contents."""

    schema_version: int
    categories: list[JsonObject]
    category_count: int
    selector_field: str
    web_ui_default_level: int
    all_level: int | None
    preparation_mutation: str
    status: str
    unavailable_sections: list[JsonObject]
    log_contents_included: bool
    router_contacted: bool
    mutation_invoked: bool
