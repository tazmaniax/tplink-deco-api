"""Host and Origin enforcement shared by the composite HTTP application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


class HttpTransportSecurityMiddleware:
    """Reject unexpected Host and browser Origin headers before route handling."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: tuple[str, ...],
        allowed_origins: tuple[str, ...],
        protected_prefixes: tuple[str, ...],
    ) -> None:
        self._app = app
        self._allowed_hosts = frozenset(allowed_hosts)
        self._allowed_origins = frozenset(allowed_origins)
        self._protected_prefixes = protected_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Forward only requests matching the configured transport boundary."""
        path = scope.get("path", "")
        protected = any(
            path == prefix or path.startswith(f"{prefix}/") for prefix in self._protected_prefixes
        )
        if scope["type"] not in {"http", "websocket"} or not protected:
            await self._app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if headers.get("host", "") not in self._allowed_hosts:
            await PlainTextResponse("Invalid host header", status_code=400)(scope, receive, send)
            return
        origin = headers.get("origin")
        if origin is not None and origin not in self._allowed_origins:
            await PlainTextResponse("Invalid origin header", status_code=403)(scope, receive, send)
            return
        await self._app(scope, receive, send)
