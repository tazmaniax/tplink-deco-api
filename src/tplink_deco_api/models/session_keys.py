"""Mutable AES key bundle that travels with each authenticated request."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SessionKeys:
    """AES key + IV, session hash and rolling sequence counter."""

    aes_key: str
    aes_iv: str
    session_hash: str
    seq: int
