"""One process-local completed REST execution result."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class _IdempotencyRecord:
    """Bind an idempotency key to one request fingerprint and result."""

    fingerprint: str
    result: dict[str, JsonValue] | None
    expires_at: float
