"""Response contract for available log categories."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import JsonRecord  # noqa: TC001 - FastAPI resolves this at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class LogTypesResponse(ResponseDto):
    """Describe log categories without including log contents."""

    schema_version: int
    categories: list[JsonRecord]
    category_count: int
    status: str
    unavailable_sections: list[JsonRecord]
    log_contents_included: bool
    router_contacted: bool
    mutation_invoked: bool
