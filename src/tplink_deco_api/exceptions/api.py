"""Errors raised when the router returns a non-zero ``error_code``."""

from __future__ import annotations

from .base import DecoError


class ApiError(DecoError):
    """Raised when the router replies with a non-zero ``error_code``."""

    def __init__(self, error_code: int) -> None:
        super().__init__(f"Failed to call API: error_code={error_code}")
        self.error_code = error_code
