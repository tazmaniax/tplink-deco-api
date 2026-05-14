"""Errors raised by the AES / RSA primitives."""

from __future__ import annotations

from .base import DecoError


class CryptoError(DecoError):
    """Raised when AES / RSA / handshake primitives fail."""
