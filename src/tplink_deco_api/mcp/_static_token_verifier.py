"""Fixed bearer-token verification for a private self-hosted MCP endpoint."""

from __future__ import annotations

import secrets

from mcp.server.auth.provider import AccessToken


class _StaticTokenVerifier:
    """Verify one deployment-scoped bearer token without persisting client state."""

    def __init__(self, token: str, resource: str) -> None:
        self._token = token
        self._resource = resource

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return a fixed access identity only for the configured token."""
        if not secrets.compare_digest(token, self._token):
            return None
        return AccessToken(
            token=token,
            client_id="deco-mcp-private-client",
            scopes=[],
            resource=self._resource,
            subject="deco-mcp-private-client",
        )
