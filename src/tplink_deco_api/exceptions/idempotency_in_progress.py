"""Errors raised when an idempotent request is already executing."""

from __future__ import annotations

from .base import DecoError


class IdempotencyInProgressError(DecoError):
    """Raised when a matching idempotent execution has not completed yet."""
