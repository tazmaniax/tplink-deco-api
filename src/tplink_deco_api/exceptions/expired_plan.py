"""Errors raised when a one-shot mutation plan has expired."""

from __future__ import annotations

from .base import DecoError


class ExpiredPlanError(DecoError):
    """Raised when a mutation plan is used after its expiry deadline."""
