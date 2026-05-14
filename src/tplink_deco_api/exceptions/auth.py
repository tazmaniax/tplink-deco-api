"""Errors raised when authentication fails or is missing."""

from __future__ import annotations

from .base import DecoError


class AuthenticationError(DecoError):
    """Raised when login fails or a request runs without a session."""
