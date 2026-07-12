"""Errors raised when an exact mutation confirmation is missing or incorrect."""

from __future__ import annotations

from .base import DecoError


class ConfirmationError(DecoError):
    """Raised when a mutation request lacks its exact required confirmation."""
