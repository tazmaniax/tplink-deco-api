"""Bounded in-flight request capacity for router-facing HTTP surfaces."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


class RequestCapacityMiddleware:
    """Reject excess REST and MCP requests before they occupy worker threads."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_in_flight: int,
        protected_prefixes: tuple[str, ...],
    ) -> None:
        self._app = app
        self._max_in_flight = max_in_flight
        self._protected_prefixes = protected_prefixes
        self._active = 0
        self._lock = asyncio.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Admit a bounded router-facing request or return a retryable error."""
        path = scope.get("path", "")
        protected = any(
            path == prefix or path.startswith(f"{prefix}/") for prefix in self._protected_prefixes
        )
        if scope["type"] != "http" or not protected:
            await self._app(scope, receive, send)
            return
        async with self._lock:
            if self._active >= self._max_in_flight:
                request_id = scope.get("state", {}).get("request_id", "")
                response = JSONResponse(
                    status_code=429,
                    content={
                        "type": "https://tplink-deco-api.invalid/problems/server-busy",
                        "title": "Server capacity exceeded",
                        "status": 429,
                        "detail": "Too many router-facing requests are already in progress.",
                        "instance": path,
                        "code": "server_busy",
                        "request_id": request_id,
                    },
                    headers={"Retry-After": "1"},
                    media_type="application/problem+json",
                )
                await response(scope, receive, send)
                return
            self._active += 1
        try:
            await self._app(scope, receive, send)
        finally:
            async with self._lock:
                self._active -= 1
