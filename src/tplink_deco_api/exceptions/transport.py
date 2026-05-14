"""Errors raised at the HTTP transport boundary."""

from __future__ import annotations

from .base import DecoError


class TransportError(DecoError):
    """Raised when an HTTP request to the router fails."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
