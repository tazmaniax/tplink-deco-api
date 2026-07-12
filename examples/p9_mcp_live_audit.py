#!/usr/bin/env python3
"""Run authorized P9 MCP read audits while persisting only value-free evidence."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from tplink_deco_api.mcp.server import create_server
from tplink_deco_api.server import ServerConfig
from tplink_deco_api.service import DecoService

if TYPE_CHECKING:
    from tplink_deco_api._json import JsonObject, JsonValue


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.68.1")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--binary-digests", action="store_true")
    parser.add_argument("--complete-tmp-batch", action="store_true")
    parser.add_argument("--tp-link-id", default=os.environ.get("DECO_TP_LINK_ID", ""))
    parser.add_argument(
        "--host-key-sha256",
        default=os.environ.get("DECO_TMP_HOST_KEY_SHA256", ""),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _required(value: str, name: str) -> str:
    if value:
        return value
    raise ValueError(f"Failed to run P9 MCP live audit: {name} is required")


def _password() -> str:
    password = os.environ.pop("DECO_PASSWORD", "")
    return password or getpass.getpass("Deco owner password: ")


def _schema_paths(value: JsonValue, path: str = "$") -> set[str]:
    output: set[str] = set()
    if isinstance(value, Mapping):
        output.add(f"{path}:object")
        for key, child in value.items():
            output.update(_schema_paths(child, f"{path}.{key}"))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        output.add(f"{path}:array")
        for child in value:
            output.update(_schema_paths(child, f"{path}[]"))
    elif isinstance(value, bool):
        output.add(f"{path}:boolean")
    elif isinstance(value, int):
        output.add(f"{path}:integer")
    elif isinstance(value, float):
        output.add(f"{path}:number")
    elif isinstance(value, str):
        output.add(f"{path}:string")
    elif value is None:
        output.add(f"{path}:null")
    return output


def _tmp_evidence(payload: JsonObject) -> dict[str, JsonValue]:
    observations: list[dict[str, JsonValue]] = []
    raw_results = payload.get("results")
    if not isinstance(raw_results, Sequence) or isinstance(raw_results, (str, bytes)):
        raise ValueError("Failed to run P9 MCP live audit: TMP results are missing")
    for raw in raw_results:
        if not isinstance(raw, Mapping):
            continue
        observation: dict[str, JsonValue] = {
            key: raw[key]
            for key in (
                "code",
                "hex_code",
                "name",
                "category",
                "status",
                "error_type",
                "skip_reason",
                "parameter_keys",
                "parameter_source",
                "variant_index",
            )
            if key in raw
        }
        response = raw.get("response")
        paths = sorted(_schema_paths(response)) if response is not None else []
        observation["schema_paths"] = paths
        observation["schema_sha256"] = hashlib.sha256("\n".join(paths).encode()).hexdigest()
        if isinstance(response, Mapping):
            error_code = response.get("error_code")
            observation["firmware_error_code"] = (
                error_code
                if isinstance(error_code, int) and not isinstance(error_code, bool)
                else None
            )
        observations.append(observation)
    return {
        "available_count": payload.get("available_count"),
        "selected_count": payload.get("selected_count"),
        "parameterized_selected_count": payload.get("parameterized_selected_count"),
        "parameterized_resolved_count": payload.get("parameterized_resolved_count"),
        "request_count": payload.get("request_count"),
        "succeeded_count": payload.get("succeeded_count"),
        "failed_count": payload.get("failed_count"),
        "skipped_count": payload.get("skipped_count"),
        "all_available_operations_attempted": payload.get("all_available_operations_attempted"),
        "request_parameter_values_retained": False,
        "response_values_retained": False,
        "mutation_invoked": False,
        "observations": observations,
    }


def _write_owner_only(path: Path, value: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(f"{json.dumps(value, indent=2, sort_keys=True)}\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def main() -> int:
    """Run selected read audits and persist no router values."""
    args = _arguments()
    if args.timeout <= 0:
        raise ValueError("Failed to run P9 MCP live audit: --timeout must be positive")
    if not args.binary_digests and not args.complete_tmp_batch:
        raise ValueError("Failed to run P9 MCP live audit: select at least one audit")
    password = _password()
    config = ServerConfig(
        host=args.host,
        username=args.username,
        password=_required(password, "owner password"),
        timeout=args.timeout,
        allow_sensitive_reads=True,
        allow_bulk_secret_reads=args.binary_digests,
        tp_link_id=(_required(args.tp_link_id, "TP-Link ID") if args.complete_tmp_batch else ""),
        tmp_host_key_sha256=(
            _required(args.host_key_sha256, "pinned host key") if args.complete_tmp_batch else ""
        ),
        allow_tmp_reads=args.complete_tmp_batch,
        expose_diagnostic_tools=True,
    )
    password = ""
    server = create_server(config)
    registration: dict[str, JsonValue] = {
        "tool_count": len(server._tool_manager._tools),
        "resource_count": len(server._resource_manager._resources),
        "complete_tmp_batch_tool_registered": "deco_get_p9_tmp_data" in server._tool_manager._tools,
        "binary_digest_tool_registered": "deco_discover_p9_binary_reads"
        in server._tool_manager._tools,
        "http_noop_tool_registered": "deco_verify_p9_http_noop" in server._tool_manager._tools,
    }
    output: dict[str, JsonValue] = {
        "schema_version": 1,
        "model": "P9",
        "probe_kind": "mcp_live_read_audit",
        "registration": registration,
        "binary_digest_audit": None,
        "complete_tmp_batch_audit": None,
        "response_values_retained": False,
        "mutation_invoked": False,
    }
    service = DecoService(config)
    try:
        if args.binary_digests:
            print("[1/2] Running three-endpoint digest-only HTTP discovery...", flush=True)
            output["binary_digest_audit"] = service.discover_p9_binary_reads()
        if args.complete_tmp_batch:
            print("[2/2] Running complete 55-operation TMP JSON batch...", flush=True)
            output["complete_tmp_batch_audit"] = _tmp_evidence(
                service.p9_tmp_data(include_parameterized=True)
            )
    finally:
        service.close()
    _write_owner_only(args.output, output)
    print(f"Value-free result: {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
