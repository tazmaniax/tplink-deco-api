"""Errors raised when a mutation plan cannot be found."""

from __future__ import annotations

from .base import DecoError


class UnknownPlanError(DecoError):
    """Raised when a requested mutation plan does not exist."""
