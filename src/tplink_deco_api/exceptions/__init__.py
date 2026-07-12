"""Public exception hierarchy for the SDK."""

from __future__ import annotations

from .api import ApiError
from .auth import AuthenticationError
from .base import DecoError
from .crypto import CryptoError
from .tmp import TmpProtocolError
from .transport import TransportError

__all__ = [
    "ApiError",
    "AuthenticationError",
    "CryptoError",
    "DecoError",
    "TmpProtocolError",
    "TransportError",
]
