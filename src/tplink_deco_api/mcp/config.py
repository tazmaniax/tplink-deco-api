"""Environment-backed configuration for the Deco MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue

_TRUE_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})


def _get_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE_VALUES


@dataclass(frozen=True)
class McpConfig:
    """Configure router access and independently gated MCP risk levels."""

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

    @classmethod
    def from_env(cls) -> McpConfig:
        """Load configuration without persisting credentials or session state."""
        timeout_text = os.environ.get("DECO_TIMEOUT", "60")
        try:
            timeout = float(timeout_text)
        except ValueError as exc:
            raise ValueError("Failed to configure MCP: DECO_TIMEOUT must be numeric") from exc
        if timeout <= 0:
            raise ValueError("Failed to configure MCP: DECO_TIMEOUT must be positive")
        return cls(
            host=os.environ.get("DECO_HOST", "192.168.68.1"),
            username=os.environ.get("DECO_USERNAME", "admin"),
            password=os.environ.get("DECO_PASSWORD", ""),
            timeout=timeout,
            allow_sensitive_reads=_get_bool("DECO_MCP_ALLOW_SENSITIVE_READS"),
            allow_bulk_secret_reads=_get_bool("DECO_MCP_ALLOW_BULK_SECRET_READS"),
            allow_binary_content=_get_bool("DECO_MCP_ALLOW_BINARY_CONTENT"),
            allow_mutations=_get_bool("DECO_MCP_ALLOW_MUTATIONS"),
            allow_destructive=_get_bool("DECO_MCP_ALLOW_DESTRUCTIVE"),
            allow_internal=_get_bool("DECO_MCP_ALLOW_INTERNAL"),
            tp_link_id=os.environ.get("DECO_TP_LINK_ID", ""),
            tmp_host_key_sha256=os.environ.get("DECO_TMP_HOST_KEY_SHA256", ""),
            allow_tmp_reads=_get_bool("DECO_MCP_ALLOW_TMP_READS"),
            allow_unverified_tmp_reads=_get_bool("DECO_MCP_ALLOW_UNVERIFIED_TMP_READS"),
            allow_tmp_noop_verification=_get_bool("DECO_MCP_ALLOW_TMP_NOOP_VERIFICATION"),
            allow_http_noop_verification=_get_bool("DECO_MCP_ALLOW_HTTP_NOOP_VERIFICATION"),
            expose_diagnostic_tools=_get_bool("DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS"),
            expose_raw_mutation_tools=_get_bool("DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS"),
        )

    def public_settings(self) -> dict[str, JsonValue]:
        """Return non-secret settings that agents may inspect safely."""
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
        }
