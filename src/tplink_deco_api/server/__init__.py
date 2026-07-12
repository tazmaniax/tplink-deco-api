"""Shared HTTP-server primitives for MCP and REST transports."""

from __future__ import annotations

from .config import ServerConfig
from .static_bearer_authenticator import StaticBearerAuthenticator

__all__ = ["ServerConfig", "StaticBearerAuthenticator"]
