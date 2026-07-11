"""Protocol-mandated MD5 session hash used in the request signature."""

from __future__ import annotations

import hashlib


def md5_session_hash(username: str, password: str) -> str:
    """Return the legacy Deco protocol's session digest."""
    session_material = (username + password).encode()
    # TP-Link's wire protocol mandates MD5 here; this digest does not store or secure a password.
    digest = hashlib.md5(
        # codeql[py/weak-sensitive-data-hashing]
        session_material,
        usedforsecurity=False,
    )
    return digest.hexdigest()
