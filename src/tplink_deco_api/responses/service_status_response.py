"""Response contract for sanitized service status."""

from __future__ import annotations

from dataclasses import dataclass

from .response_dto import ResponseDto


@dataclass(frozen=True)
class ServiceStatusResponse(ResponseDto):
    """Describe server configuration, gates and connection state without secrets."""

    host: str
    username: str
    timeout: float
    password_configured: bool
    allow_sensitive_reads: bool
    allow_bulk_secret_reads: bool
    allow_binary_content: bool
    allow_mutations: bool
    allow_destructive: bool
    allow_internal: bool
    tp_link_id_configured: bool
    tmp_host_key_sha256: str
    allow_tmp_reads: bool
    allow_unverified_tmp_reads: bool
    allow_tmp_noop_verification: bool
    tmp_writes_hard_disabled: bool
    tmp_transport_status: str
    allow_http_noop_verification: bool
    expose_diagnostic_tools: bool
    expose_raw_mutation_tools: bool
    mcp_transport: str
    server_host: str
    server_port: int
    mcp_path: str
    mcp_public_url: str
    server_bearer_token_configured: bool
    server_allowed_hosts: list[str]
    server_allowed_origins: list[str]
    rest_enabled: bool
    rest_prefix: str
    rest_docs_exposed: bool
    max_in_flight_requests: int
    authenticated: bool
    tmp_connected: bool
    http_mutation_latched: bool
    tmp_mutation_latched: bool
    catalogued_operations: int
    schema_version: int
    identity_resolved: bool
    pending_mutation_plan_count: int
