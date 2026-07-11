"""Errors raised while encoding or exchanging TMP/AppV2 messages."""

from __future__ import annotations

from .base import DecoError


class TmpProtocolError(DecoError):
    """Raised when a TMP/AppV2 peer violates the expected wire protocol."""
