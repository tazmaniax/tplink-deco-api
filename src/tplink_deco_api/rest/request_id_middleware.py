"""Request correlation for every composite HTTP response."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from starlette.datastructures import Headers, MutableHeaders

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestIdMiddleware:
    """Attach one bounded request identifier to state and response headers."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Propagate a safe caller ID or create a random correlation ID."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        supplied = Headers(scope=scope).get("x-request-id", "")
        request_id = supplied if 0 < len(supplied) <= 128 else uuid.uuid4().hex
        state = scope.setdefault("state", {})
        state["request_id"] = request_id

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).append("X-Request-ID", request_id)
            await send(message)

        await self._app(scope, receive, send_with_request_id)
