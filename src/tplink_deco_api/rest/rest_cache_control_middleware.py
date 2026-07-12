"""Private-response cache policy for the semantic REST surface."""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.datastructures import MutableHeaders

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RestCacheControlMiddleware:
    """Prevent intermediaries from retaining private REST responses."""

    def __init__(self, app: ASGIApp, *, protected_prefixes: tuple[str, ...]) -> None:
        self._app = app
        self._protected_prefixes = protected_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Attach a no-store policy to responses under the REST prefix."""
        path = scope.get("path", "")
        protected = any(
            path == prefix or path.startswith(f"{prefix}/") for prefix in self._protected_prefixes
        )
        if scope["type"] != "http" or not protected:
            await self._app(scope, receive, send)
            return

        async def send_without_caching(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-store"
            await send(message)

        await self._app(scope, receive, send_without_caching)
