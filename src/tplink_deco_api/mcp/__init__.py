"""MCP server integration for capability-aware Deco access."""

from __future__ import annotations

from .config import McpConfig
from .service import DecoMcpService

__all__ = ["DecoMcpService", "McpConfig"]
