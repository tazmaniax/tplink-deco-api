"""Fixed bearer-token verification for a private self-hosted MCP endpoint."""

from __future__ import annotations

from mcp.server.auth.provider import AccessToken

from ..server import StaticBearerAuthenticator


class _StaticTokenVerifier:
    """Verify one deployment-scoped bearer token without persisting client state."""

    def __init__(self, token: str, resource: str) -> None:
        self._authenticator = StaticBearerAuthenticator(token)
        self._resource = resource

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return a fixed access identity only for the configured token."""
        if not self._authenticator.accepts(token):
            return None
        return AccessToken(
            token=token,
            client_id="deco-mcp-private-client",
            scopes=[],
            resource=self._resource,
            subject="deco-mcp-private-client",
        )
