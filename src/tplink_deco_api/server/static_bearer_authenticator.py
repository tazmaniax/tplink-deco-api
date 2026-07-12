"""Constant-time bearer-token authentication shared by HTTP transports."""

from __future__ import annotations

import secrets


class StaticBearerAuthenticator:
    """Authenticate one deployment-scoped bearer token without retaining clients."""

    def __init__(self, token: str) -> None:
        self._token = token

    def accepts(self, token: str) -> bool:
        """Return whether a presented token exactly matches the configured token."""
        return secrets.compare_digest(token.encode(), self._token.encode())
