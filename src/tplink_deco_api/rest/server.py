"""Command-line entry point for the composite MCP and REST HTTP service."""

from __future__ import annotations

import uvicorn

from ..server import ServerConfig
from .app import create_http_application


def main() -> None:
    """Run the composite HTTP service using environment-backed configuration."""
    config = ServerConfig.from_env()
    uvicorn.run(
        create_http_application(config),
        host=config.server_host,
        port=config.server_port,
        workers=1,
    )


if __name__ == "__main__":
    main()
