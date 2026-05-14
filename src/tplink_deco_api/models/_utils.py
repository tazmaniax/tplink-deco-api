"""Small shared helpers for decoding router payload fields."""

from __future__ import annotations

from base64 import b64decode


def decode_b64(value: str) -> str:
    """Return the base64-decoded UTF-8 string, or ``value`` if empty."""
    if not value:
        return value
    return b64decode(value).decode()


def normalize_mac(value: str) -> str:
    """Return ``value`` with hyphens converted to colons and uppercased."""
    return value.replace("-", ":").upper()
