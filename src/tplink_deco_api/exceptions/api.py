"""Errors raised when the router returns a non-zero ``error_code``."""

from __future__ import annotations

from .base import DecoError


class ApiError(DecoError):
    """Raised when the router replies with a non-zero ``error_code``."""

    def __init__(self, error_code: int, message: str = "") -> None:
        detail = f"error_code={error_code}"
        if message:
            detail = f"{detail}, message={message}"
        super().__init__(f"Failed to call API: {detail}")
        self.error_code = error_code
        self.api_message = message
