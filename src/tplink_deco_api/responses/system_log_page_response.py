"""Response contract for one gated page of Deco system logs."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class SystemLogPageResponse(ResponseDto):
    """Describe one page of secret log content with pagination metadata."""

    schema_version: int
    current_index: int
    total_pages: int
    page_size: int
    entries: list[JsonObject]
    entry_count: int
    log_contents_included: bool
    prepared_level: None
    level_reported_by_firmware: bool
    preparation_mutation: str
    source_interface: str
    router_contacted: bool
    mutation_invoked: bool
