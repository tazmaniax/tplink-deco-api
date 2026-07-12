"""Errors raised when an idempotency key is reused for another request."""

from __future__ import annotations

from .base import DecoError


class IdempotencyConflictError(DecoError):
    """Raised when one idempotency key identifies different requests."""
