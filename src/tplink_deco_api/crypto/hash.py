"""MD5 session hash used in the request signature."""

from __future__ import annotations

import hashlib


def md5_session_hash(username: str, password: str) -> str:
    """Return ``md5(username + password)`` as a lowercase hex digest."""
    return hashlib.md5((username + password).encode()).hexdigest()
