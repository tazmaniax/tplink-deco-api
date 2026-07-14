"""Response contract for normalized monthly reports."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class MonthlyReportsResponse(ResponseDto):
    """Describe monthly client, parental-control, and security reports."""

    schema_version: int
    status: str
    reports: list[JsonObject]
    report_count: int
    provenance: JsonObject
    observed_at_epoch_seconds: float
    router_contacted: bool
    mutation_invoked: bool
