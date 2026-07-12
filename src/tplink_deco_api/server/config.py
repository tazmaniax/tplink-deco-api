"""Environment-backed configuration for the Deco service and transports."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from .._json import JsonValue

_TRUE_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_RESERVED_HTTP_PATHS: tuple[str, ...] = (
    "/healthz",
    "/readyz",
    "/openapi.json",
    "/docs",
    "/redoc",
)
McpTransport = Literal["stdio", "streamable-http"]


def _get_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE_VALUES


def _get_csv(name: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in os.environ.get(name, "").split(",") if value.strip())


def _get_port() -> int:
    value = os.environ.get("DECO_SERVER_PORT", "8000")
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError("Failed to configure server: DECO_SERVER_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Failed to configure server: DECO_SERVER_PORT must be between 1 and 65535")
    return port


def _get_max_in_flight() -> int:
    value = os.environ.get("DECO_SERVER_MAX_IN_FLIGHT_REQUESTS", "32")
    try:
        maximum = int(value)
    except ValueError as exc:
        raise ValueError(
            "Failed to configure server: DECO_SERVER_MAX_IN_FLIGHT_REQUESTS must be an integer"
        ) from exc
    if maximum <= 0:
        raise ValueError(
            "Failed to configure server: DECO_SERVER_MAX_IN_FLIGHT_REQUESTS must be positive"
        )
    return maximum


def _get_transport() -> McpTransport:
    value = os.environ.get("DECO_MCP_TRANSPORT", "stdio").strip().lower()
    if value not in {"stdio", "streamable-http"}:
        raise ValueError(
            "Failed to configure MCP: DECO_MCP_TRANSPORT must be stdio or streamable-http"
        )
    return cast("McpTransport", value)


def _paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(f"{right}/") or right.startswith(f"{left}/")


@dataclass(frozen=True)
class ServerConfig:
    """Configure router access, HTTP transports and independent risk gates."""

    host: str
    username: str
    password: str
    timeout: float
    allow_sensitive_reads: bool = False
    allow_bulk_secret_reads: bool = False
    allow_binary_content: bool = False
    allow_mutations: bool = False
    allow_destructive: bool = False
    allow_internal: bool = False
    tp_link_id: str = ""
    tmp_host_key_sha256: str = ""
    allow_tmp_reads: bool = False
    allow_unverified_tmp_reads: bool = False
    allow_tmp_noop_verification: bool = False
    allow_http_noop_verification: bool = False
    expose_diagnostic_tools: bool = False
    expose_raw_mutation_tools: bool = False
    transport: McpTransport = "stdio"
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    mcp_path: str = "/mcp"
    mcp_public_url: str = ""
    bearer_token: str = ""
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()
    rest_enabled: bool = False
    rest_prefix: str = "/api/v1"
    rest_expose_docs: bool = False
    max_in_flight_requests: int = 32

    @classmethod
    def from_env(cls) -> ServerConfig:
        """Load configuration without persisting credentials or session state."""
        timeout_text = os.environ.get("DECO_TIMEOUT", "60")
        try:
            timeout = float(timeout_text)
        except ValueError as exc:
            raise ValueError("Failed to configure server: DECO_TIMEOUT must be numeric") from exc
        if timeout <= 0:
            raise ValueError("Failed to configure server: DECO_TIMEOUT must be positive")
        config = cls(
            host=os.environ.get("DECO_HOST", "192.168.68.1"),
            username=os.environ.get("DECO_USERNAME", "admin"),
            password=os.environ.get("DECO_PASSWORD", ""),
            timeout=timeout,
            allow_sensitive_reads=_get_bool("DECO_ALLOW_SENSITIVE_READS"),
            allow_bulk_secret_reads=_get_bool("DECO_ALLOW_BULK_SECRET_READS"),
            allow_binary_content=_get_bool("DECO_ALLOW_BINARY_CONTENT"),
            allow_mutations=_get_bool("DECO_ALLOW_MUTATIONS"),
            allow_destructive=_get_bool("DECO_ALLOW_DESTRUCTIVE"),
            allow_internal=_get_bool("DECO_ALLOW_INTERNAL"),
            tp_link_id=os.environ.get("DECO_TP_LINK_ID", ""),
            tmp_host_key_sha256=os.environ.get("DECO_TMP_HOST_KEY_SHA256", ""),
            allow_tmp_reads=_get_bool("DECO_ALLOW_TMP_READS"),
            allow_unverified_tmp_reads=_get_bool("DECO_ALLOW_UNVERIFIED_TMP_READS"),
            allow_tmp_noop_verification=_get_bool("DECO_ALLOW_TMP_NOOP_VERIFICATION"),
            allow_http_noop_verification=_get_bool("DECO_ALLOW_HTTP_NOOP_VERIFICATION"),
            expose_diagnostic_tools=_get_bool("DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS"),
            expose_raw_mutation_tools=_get_bool("DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS"),
            transport=_get_transport(),
            server_host=os.environ.get("DECO_SERVER_HOST", "127.0.0.1").strip(),
            server_port=_get_port(),
            mcp_path=os.environ.get("DECO_MCP_PATH", "/mcp").strip(),
            mcp_public_url=os.environ.get("DECO_MCP_PUBLIC_URL", "").strip(),
            bearer_token=os.environ.get("DECO_SERVER_BEARER_TOKEN", "").strip(),
            allowed_hosts=_get_csv("DECO_SERVER_ALLOWED_HOSTS"),
            allowed_origins=_get_csv("DECO_SERVER_ALLOWED_ORIGINS"),
            rest_enabled=_get_bool("DECO_REST_ENABLED"),
            rest_prefix=os.environ.get("DECO_REST_PREFIX", "/api/v1").strip(),
            rest_expose_docs=_get_bool("DECO_REST_EXPOSE_DOCS"),
            max_in_flight_requests=_get_max_in_flight(),
        )
        config.validate_server()
        return config

    def validate_server(self) -> None:
        """Reject unsafe or incomplete transport configuration."""
        if not self.rest_prefix.startswith("/") or self.rest_prefix.endswith("/"):
            raise ValueError(
                "Failed to configure server: DECO_REST_PREFIX must start with / and not end with /"
            )
        if not self.mcp_path.startswith("/") or self.mcp_path.endswith("/"):
            raise ValueError(
                "Failed to configure server: DECO_MCP_PATH must start with / and not end with /"
            )
        if _paths_overlap(self.rest_prefix, self.mcp_path):
            raise ValueError(
                "Failed to configure server: DECO_REST_PREFIX and DECO_MCP_PATH must not overlap"
            )
        for configured_path in (self.rest_prefix, self.mcp_path):
            if any(
                _paths_overlap(configured_path, reserved_path)
                for reserved_path in _RESERVED_HTTP_PATHS
            ):
                raise ValueError(
                    "Failed to configure server: REST and MCP paths must not overlap "
                    "reserved HTTP routes"
                )
        if self.max_in_flight_requests <= 0:
            raise ValueError(
                "Failed to configure server: DECO_SERVER_MAX_IN_FLIGHT_REQUESTS must be positive"
            )
        if self.transport == "stdio":
            return
        if not self.server_host:
            raise ValueError("Failed to configure server: DECO_SERVER_HOST is required")
        if not 1 <= self.server_port <= 65535:
            raise ValueError(
                "Failed to configure server: DECO_SERVER_PORT must be between 1 and 65535"
            )
        if not self.mcp_public_url.startswith(("http://", "https://")):
            raise ValueError("Failed to configure MCP: DECO_MCP_PUBLIC_URL must be an HTTP(S) URL")
        if len(self.bearer_token) < 32:
            raise ValueError(
                "Failed to configure server: DECO_SERVER_BEARER_TOKEN must contain "
                "at least 32 characters"
            )
        if not self.allowed_hosts:
            raise ValueError(
                "Failed to configure server: DECO_SERVER_ALLOWED_HOSTS must contain "
                "at least one host"
            )

    def public_settings(self) -> dict[str, JsonValue]:
        """Return non-secret settings that callers may inspect safely."""
        return {
            "host": self.host,
            "username": self.username,
            "timeout": self.timeout,
            "password_configured": bool(self.password),
            "allow_sensitive_reads": self.allow_sensitive_reads,
            "allow_bulk_secret_reads": self.allow_bulk_secret_reads,
            "allow_binary_content": self.allow_binary_content,
            "allow_mutations": self.allow_mutations,
            "allow_destructive": self.allow_destructive,
            "allow_internal": self.allow_internal,
            "tp_link_id_configured": bool(self.tp_link_id),
            "tmp_host_key_sha256": self.tmp_host_key_sha256,
            "allow_tmp_reads": self.allow_tmp_reads,
            "allow_unverified_tmp_reads": self.allow_unverified_tmp_reads,
            "allow_tmp_noop_verification": self.allow_tmp_noop_verification,
            "allow_http_noop_verification": self.allow_http_noop_verification,
            "expose_diagnostic_tools": self.expose_diagnostic_tools,
            "expose_raw_mutation_tools": self.expose_raw_mutation_tools,
            "mcp_transport": self.transport,
            "server_host": self.server_host,
            "server_port": self.server_port,
            "mcp_path": self.mcp_path,
            "mcp_public_url": self.mcp_public_url,
            "server_bearer_token_configured": bool(self.bearer_token),
            "server_allowed_hosts": list(self.allowed_hosts),
            "server_allowed_origins": list(self.allowed_origins),
            "rest_enabled": self.rest_enabled,
            "rest_prefix": self.rest_prefix,
            "rest_docs_exposed": self.rest_expose_docs,
            "max_in_flight_requests": self.max_in_flight_requests,
        }
