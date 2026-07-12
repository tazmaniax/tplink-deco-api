#!/usr/bin/env python3
"""Collect a sanitized Deco snapshot through a strict read-only allowlist.

Usage::

    uv run examples/read_only_probe.py --host 192.168.68.1
    uv run examples/read_only_probe.py --host 192.168.68.1 --output snapshot.json

The password is accepted through ``DECO_PASSWORD`` or a hidden terminal prompt.
Sensitive reads require an explicit schema-only mode that discards values.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeAlias

from tplink_deco_api import (
    CATALOG_VERSION,
    DISCOVERABLE_READ_ENDPOINTS,
    ENDPOINT_CATALOG,
    P9_READ_ENDPOINTS,
    P9_SENSITIVE_SCHEMA_ENDPOINTS,
    SENSITIVE_SCHEMA_ENDPOINTS,
    ApiResponse,
    CapabilityReport,
    CompatibilityManifest,
    DecoClient,
    DecoError,
    EndpointObservation,
    EndpointProbeResult,
    EndpointSpec,
    FuzzyReadCandidate,
    FuzzyReadObservation,
    NodeClientList,
    build_fuzzy_read_candidates,
    get_endpoint,
    restore_fuzzy_read_candidate,
)
from tplink_deco_api._json import JsonObject, JsonValue

_AllowedParams: TypeAlias = Mapping[str, JsonValue] | None
_RequestSignature: TypeAlias = tuple[str, str, str]
_RecoveredProbe: TypeAlias = tuple[EndpointProbeResult, bool]
_RecoveredObservation: TypeAlias = tuple[EndpointObservation, bool]
_FUZZY_ATTEMPTS = 2
_MAX_FUZZY_CANDIDATES = 300
_FUZZY_READ_ALIASES: frozenset[str] = frozenset({"read", "get", "getlist", "list"})
_ALLOWED_REQUESTS: dict[tuple[str, str, str], _AllowedParams] = {
    ("admin/device", "device_list", "read"): None,
    ("admin/device", "mode", "read"): None,
    ("admin/network", "internet", "read"): None,
    ("admin/network", "wan_ipv4", "read"): {"device_mac": "default"},
    ("admin/network", "performance", "read"): None,
    ("admin/client", "client_list", "read"): {"device_mac": "default"},
    ("admin/wireless", "power", "read"): {"device_mac": "default"},
    ("admin/device", "timesetting", "read"): {"device_mac": "default"},
    ("admin/client", "addr_reservation", "getlist"): None,
}
_ALLOWED_REQUESTS.update(
    {
        (endpoint.path, endpoint.form, endpoint.operation): endpoint.default_params
        for endpoint in P9_READ_ENDPOINTS
    }
)
_ALLOWED_REQUESTS.update(
    {
        (endpoint.path, endpoint.form, endpoint.operation): endpoint.default_params
        for endpoint in DISCOVERABLE_READ_ENDPOINTS
    }
)
_STOK_RE = re.compile(r"(?P<prefix>;stok=)[^/;?\s]+", re.IGNORECASE)
_SYSAUTH_RE = re.compile(r"(?P<prefix>sysauth=)[^;\s]+", re.IGNORECASE)


class _ReadOnlyDecoClient(DecoClient):
    """Reject authenticated requests outside the probe's read-only allowlist."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        timeout: float = 10.0,
    ) -> None:
        super().__init__(host, username, password, timeout)
        self._allowed_fuzzy_requests: set[_RequestSignature] = set()
        self._allowed_sensitive_requests: set[_RequestSignature] = set()

    def _allow_sensitive_endpoint(self, endpoint: EndpointSpec) -> None:
        if endpoint not in SENSITIVE_SCHEMA_ENDPOINTS:
            raise PermissionError("Blocked sensitive request outside the schema allowlist")
        self._allowed_sensitive_requests.add(
            self._signature(endpoint.path, endpoint.form, endpoint.request_data())
        )

    def _allow_fuzzy_candidate(self, candidate: FuzzyReadCandidate) -> None:
        source = get_endpoint(candidate.source_name)
        if source not in DISCOVERABLE_READ_ENDPOINTS:
            raise PermissionError("Blocked fuzzy request without a discoverable read source")
        if (candidate.endpoint.path, candidate.endpoint.form) != (source.path, source.form):
            raise PermissionError("Blocked fuzzy request outside its source controller/form")
        if candidate.endpoint.safety != "read_only" or candidate.endpoint.sensitivity == "secret":
            raise PermissionError("Blocked unsafe fuzzy request")
        if (
            candidate.endpoint.authentication != source.authentication
            or candidate.endpoint.form_selector != source.form_selector
            or candidate.endpoint.response_kind != source.response_kind
        ):
            raise PermissionError("Blocked fuzzy request that changes source transport metadata")
        if (
            candidate.endpoint.operation != source.operation
            and candidate.endpoint.operation not in _FUZZY_READ_ALIASES
        ):
            raise PermissionError("Blocked fuzzy request with a non-read operation alias")
        if any(
            item.path == candidate.endpoint.path
            and item.form == candidate.endpoint.form
            and item.operation == candidate.endpoint.operation
            and item.safety != "read_only"
            for item in ENDPOINT_CATALOG
        ):
            raise PermissionError("Blocked fuzzy request matching a catalogued non-read operation")
        if candidate.params not in (None, {}, {"device_mac": "default"}):
            raise PermissionError("Blocked fuzzy request with unapproved parameters")
        self._allowed_fuzzy_requests.add(
            self._signature(
                candidate.endpoint.path,
                candidate.endpoint.form,
                candidate.endpoint.request_data(candidate.params),
            )
        )

    def _guard(self, path: str, form: str, data: Mapping[str, JsonValue]) -> None:
        operation = data.get("operation")
        if not isinstance(operation, str):
            raise PermissionError("Blocked request without a string operation")

        extra_fields = set(data) - {"operation", "params"}
        if extra_fields:
            raise PermissionError(f"Blocked request with extra fields: {sorted(extra_fields)}")
        if self._signature(path, form, data) in self._allowed_fuzzy_requests:
            return
        if self._signature(path, form, data) in self._allowed_sensitive_requests:
            return

        key = (path, form, operation)
        if key not in _ALLOWED_REQUESTS:
            raise PermissionError(f"Blocked non-allowlisted request: {path}/{form}/{operation}")

        expected_params = _ALLOWED_REQUESTS[key]
        actual_params = data.get("params")
        if (
            key == ("admin/client", "client_list", "read")
            and isinstance(actual_params, Mapping)
            and set(actual_params) == {"device_mac"}
            and isinstance(actual_params.get("device_mac"), str)
        ):
            return
        if expected_params is None:
            if actual_params not in (None, {}):
                raise PermissionError("Blocked unexpected request parameters")
        elif actual_params != expected_params:
            raise PermissionError("Blocked request with unexpected parameters")

    @staticmethod
    def _signature(
        path: str,
        form: str,
        data: Mapping[str, JsonValue],
    ) -> _RequestSignature:
        return path, form, json.dumps(data, sort_keys=True, separators=(",", ":"))

    def request(
        self,
        path: str,
        form: str,
        data: Mapping[str, JsonValue],
    ) -> JsonObject:
        """Send a request only when it exactly matches the read allowlist."""
        self._guard(path, form, data)
        return super().request(path, form, data)

    def request_list(
        self,
        path: str,
        form: str,
        data: Mapping[str, JsonValue],
    ) -> list[JsonObject]:
        """Send a list request only when it exactly matches the read allowlist."""
        self._guard(path, form, data)
        return super().request_list(path, form, data)

    def call(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
    ) -> ApiResponse:
        """Call only catalogued operations in the read-only allowlist."""
        self._guard(endpoint.path, endpoint.form, endpoint.request_data(params))
        return super().call(endpoint, params)

    def _probe_with_session_recovery(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
    ) -> _RecoveredProbe:
        probe = self.probe_endpoint(endpoint, params)
        if not self._needs_session_recovery(probe):
            return probe, False
        self.invalidate_session()
        self.login()
        return self.probe_endpoint(endpoint, params), True

    def _observe_sensitive_with_session_recovery(
        self,
        endpoint: EndpointSpec,
    ) -> _RecoveredObservation:
        observation = self.observe_endpoint_schema(endpoint, include_sensitive=True)
        if not self._needs_session_recovery(observation):
            return observation, False
        self.invalidate_session()
        self.login()
        return self.observe_endpoint_schema(endpoint, include_sensitive=True), True

    @staticmethod
    def _needs_session_recovery(
        probe: EndpointProbeResult | EndpointObservation,
    ) -> bool:
        return (
            probe.error_code == -1
            or probe.http_status in {401, 403}
            or (probe.status == "transport_error" and probe.http_status is None)
        )


def _scrub_error(message: str) -> str:
    message = _STOK_RE.sub(r"\g<prefix><redacted>", message)
    return _SYSAUTH_RE.sub(r"\g<prefix><redacted>", message)


def _capture(fn: Callable[[], JsonValue]) -> JsonObject:
    try:
        return {"status": "ok", "data": fn()}
    except (DecoError, OSError, TimeoutError, ValueError) as exc:
        return {
            "status": "error",
            "error_type": type(exc).__name__,
            "message": _scrub_error(str(exc)),
        }


def _probe_with_progress(
    client: _ReadOnlyDecoClient,
    endpoint_specs: tuple[EndpointSpec, ...],
    host: str,
) -> CapabilityReport:
    probes: list[EndpointProbeResult] = []
    total = len(endpoint_specs)
    for index, endpoint in enumerate(endpoint_specs, start=1):
        print(f"[endpoint {index}/{total}] {endpoint.name} ...", end="", flush=True)
        probe, recovered = client._probe_with_session_recovery(endpoint)
        probes.append(probe)
        details = []
        if recovered:
            details.append("session_refreshed")
        if probe.error_code is not None:
            details.append(f"error_code={probe.error_code}")
        if probe.http_status is not None:
            details.append(f"http_status={probe.http_status}")
        detail = f", {', '.join(details)}" if details else ""
        print(f" {probe.status} ({probe.elapsed_seconds:.1f}s{detail})", flush=True)
    return CapabilityReport(host, datetime.now(UTC).isoformat(), tuple(probes))


def _observe_sensitive_with_progress(
    client: _ReadOnlyDecoClient,
    endpoint_specs: tuple[EndpointSpec, ...],
    prior_observations: tuple[EndpointObservation, ...] = (),
    checkpoint: Callable[[tuple[EndpointObservation, ...]], None] | None = None,
) -> tuple[EndpointObservation, ...]:
    observations = list(prior_observations)
    for endpoint in endpoint_specs:
        client._allow_sensitive_endpoint(endpoint)
    for index, endpoint in enumerate(endpoint_specs, start=1):
        print(
            f"[sensitive schema {index}/{len(endpoint_specs)}] {endpoint.name} ...",
            end="",
            flush=True,
        )
        observation, recovered = client._observe_sensitive_with_session_recovery(endpoint)
        observations.append(observation)
        if checkpoint is not None:
            checkpoint(tuple(observations))
        details = []
        if recovered:
            details.append("session_refreshed")
        if observation.error_code is not None:
            details.append(f"error_code={observation.error_code}")
        if observation.http_status is not None:
            details.append(f"http_status={observation.http_status}")
        if observation.status == "supported":
            details.append(f"schema_paths={len(observation.schema_paths)}")
        suffix = f", {', '.join(details)}" if details else ""
        print(f" {observation.status} ({observation.elapsed_seconds:.1f}s{suffix})", flush=True)
    return tuple(observations)


def _reusable_sensitive_observations(
    manifest: CompatibilityManifest,
    endpoint_specs: tuple[EndpointSpec, ...],
) -> tuple[EndpointObservation, ...]:
    by_name = {observation.name: observation for observation in manifest.observations}
    reusable: list[EndpointObservation] = []
    for endpoint in endpoint_specs:
        observation = by_name.get(endpoint.name)
        if observation is None:
            continue
        if observation.status in {"supported", "rejected", "not_found"} or (
            observation.status == "transport_error" and observation.http_status is not None
        ):
            reusable.append(observation)
    return tuple(reusable)


def _probe_fuzzy_with_progress(
    client: _ReadOnlyDecoClient,
    candidates: tuple[FuzzyReadCandidate, ...],
    delay_seconds: float,
) -> tuple[FuzzyReadObservation, ...]:
    if len(candidates) > _MAX_FUZZY_CANDIDATES:
        raise ValueError(
            "Failed to run fuzzy read probe: "
            f"{len(candidates)} candidates exceeds the {_MAX_FUZZY_CANDIDATES} request budget"
        )
    for candidate in candidates:
        client._allow_fuzzy_candidate(candidate)

    attempts: list[list[EndpointProbeResult]] = [[] for _ in candidates]
    recoveries: list[list[bool]] = [[] for _ in candidates]
    last_request_at = 0.0
    for attempt_index in range(_FUZZY_ATTEMPTS):
        if attempt_index:
            print("Refreshing authentication before confirmation pass...", flush=True)
            client.invalidate_session()
            client.login()
            last_request_at = 0.0
        for candidate_index, candidate in enumerate(candidates):
            elapsed = time.monotonic() - last_request_at
            if last_request_at and elapsed < delay_seconds:
                time.sleep(delay_seconds - elapsed)
            print(
                f"[fuzzy {candidate_index + 1}/{len(candidates)} "
                f"attempt {attempt_index + 1}/{_FUZZY_ATTEMPTS}] "
                f"{candidate.endpoint.name} [{candidate.variant}] ...",
                end="",
                flush=True,
            )
            probe, recovered = client._probe_with_session_recovery(
                candidate.endpoint,
                candidate.params,
            )
            last_request_at = time.monotonic()
            attempts[candidate_index].append(probe)
            recoveries[candidate_index].append(recovered)
            details = []
            if recovered:
                details.append("session_refreshed")
            if probe.error_code is not None:
                details.append(f"error_code={probe.error_code}")
            if probe.http_status is not None:
                details.append(f"http_status={probe.http_status}")
            if probe.status == "supported" and probe.response is not None:
                details.append("null_result" if probe.response.result is None else "data")
            suffix = f", {', '.join(details)}" if details else ""
            print(f" {probe.status} ({probe.elapsed_seconds:.1f}s{suffix})", flush=True)
    return tuple(
        FuzzyReadObservation.from_attempts(
            candidate,
            tuple(candidate_attempts),
            tuple(candidate_recoveries),
        )
        for candidate, candidate_attempts, candidate_recoveries in zip(
            candidates,
            attempts,
            recoveries,
            strict=True,
        )
    )


def _fuzzy_result(
    observations: tuple[FuzzyReadObservation, ...],
    candidate_count: int,
    delay_seconds: float,
    scope: str,
) -> JsonObject:
    return {
        "status": "ok",
        "data": {
            "scope": scope,
            "candidate_count": candidate_count,
            "attempts_per_candidate": _FUZZY_ATTEMPTS,
            "minimum_delay_seconds": delay_seconds,
            "confirmed_supported": [
                {
                    "name": observation.name,
                    "source_name": observation.source_name,
                    "variant": observation.variant,
                    "parameter_schema": list(observation.parameter_schema),
                    "returned_data": observation.confirmed_data,
                }
                for observation in observations
                if observation.confirmed_supported
            ],
            "observations": [observation.to_dict() for observation in observations],
        },
    }


def _retry_candidates(
    manifest: CompatibilityManifest,
) -> tuple[FuzzyReadCandidate, ...]:
    first_unreliable = next(
        (
            index
            for index, observation in enumerate(manifest.fuzzy_observations)
            if not observation.consistent
            or len(observation.attempt_error_codes) != len(observation.attempt_statuses)
            or len(observation.attempt_http_statuses) != len(observation.attempt_statuses)
            or len(observation.attempt_session_recovered) != len(observation.attempt_statuses)
        ),
        None,
    )
    if first_unreliable is None:
        return ()
    return tuple(
        restore_fuzzy_read_candidate(observation)
        for observation in manifest.fuzzy_observations[first_unreliable:]
    )


def _merge_fuzzy_observations(
    existing: tuple[FuzzyReadObservation, ...],
    replacements: tuple[FuzzyReadObservation, ...],
) -> tuple[FuzzyReadObservation, ...]:
    replacements_by_identity = {observation.identity: observation for observation in replacements}
    return tuple(
        replacements_by_identity.get(observation.identity, observation) for observation in existing
    )


def _mesh_nodes(client: _ReadOnlyDecoClient) -> JsonValue:
    return [
        {
            "mac": node.mac,
            "device_id": node.device_id,
            "parent_device_id": node.parent_device_id,
            "device_ip": node.device_ip,
            "model": node.device_model,
            "role": node.role,
            "nickname": node.nickname,
            "custom_nickname": node.custom_nickname,
            "hardware_version": node.hardware_ver,
            "software_version": node.software_ver,
            "internet_status": node.inet_status,
            "group_status": node.group_status,
            "support_plc": node.support_plc,
            "connection_type": list(node.connection_type),
            "previous": node.previous,
            "speed_get_support": node.speed_get_support,
            "signal_level": {
                "band2_4": node.signal_level.band2_4,
                "band5": node.signal_level.band5,
                "band6": node.signal_level.band6,
            },
        }
        for node in client.get_device_list()
    ]


def _device_mode(client: _ReadOnlyDecoClient) -> JsonValue:
    mode = client.get_device_mode()
    return {"workmode": mode.workmode, "sysmode": mode.sysmode, "region": mode.region}


def _internet_status(client: _ReadOnlyDecoClient) -> JsonValue:
    status = client.get_internet_status()
    return {
        "link_status": status.link_status,
        "ipv4": {
            "internet_status": status.ipv4.inet_status,
            "dial_status": status.ipv4.dial_status,
            "connection_type": status.ipv4.connect_type,
            "auto_detect_type": status.ipv4.auto_detect_type,
            "error_code": status.ipv4.error_code,
        },
        "ipv6": {
            "internet_status": status.ipv6.inet_status,
            "dial_status": status.ipv6.dial_status,
            "connection_type": status.ipv6.connect_type,
            "auto_detect_type": status.ipv6.auto_detect_type,
            "error_code": status.ipv6.error_code,
        },
    }


def _wan_lan(client: _ReadOnlyDecoClient) -> JsonValue:
    info = client.get_wan_info()
    return {
        "wan": {
            "dial_type": info.wan.dial_type,
            "automatic_dns": info.wan.enable_auto_dns,
            "ip": info.wan.ip_info.ip,
            "mask": info.wan.ip_info.mask,
            "mac": info.wan.ip_info.mac,
            "gateway": info.wan.ip_info.gateway,
            "dns1": info.wan.ip_info.dns1,
            "dns2": info.wan.ip_info.dns2,
        },
        "lan": {
            "ip": info.lan.ip_info.ip,
            "mask": info.lan.ip_info.mask,
            "mac": info.lan.ip_info.mac,
        },
    }


def _performance(client: _ReadOnlyDecoClient) -> JsonValue:
    performance = client.get_performance()
    return {"cpu_usage": performance.cpu_usage, "memory_usage": performance.mem_usage}


def _clients(client: _ReadOnlyDecoClient) -> JsonValue:
    return [
        {
            "mac": device.mac,
            "ip": device.ip,
            "name": device.name,
            "connection_type": device.connection_type,
            "wire_type": device.wire_type,
            "interface": device.interface,
            "client_type": device.client_type,
            "access_host": device.access_host,
            "online": device.online,
        }
        for device in client.get_client_list()
    ]


def _clients_by_node(client: _ReadOnlyDecoClient) -> JsonValue:
    nodes = tuple(node for node in client.get_device_list() if node.mac)
    topology: list[NodeClientList] = []
    for index, node in enumerate(nodes, start=1):
        print(f"\n  [node {index}/{len(nodes)}] client_list ...", end="", flush=True)
        clients = tuple(client.get_client_list(node.mac))
        topology.append(NodeClientList(node.mac, clients))
        print(f" {len(clients)} clients", flush=True)
    return [node_client_list.to_dict() for node_client_list in topology]


def _wireless_power(client: _ReadOnlyDecoClient) -> JsonValue:
    power = client.get_wireless_power()
    return {"support_dfs": power.support_dfs}


def _time_settings(client: _ReadOnlyDecoClient) -> JsonValue:
    settings = client.get_time_settings()
    return {
        "time": settings.time,
        "date": settings.date,
        "timezone": settings.timezone,
        "timezone_region": settings.tz_region,
        "continent": settings.continent,
        "dst_status": settings.dst_status,
    }


def _address_reservations(client: _ReadOnlyDecoClient) -> JsonValue:
    table = client.get_address_reservations()
    return {
        "max_count": table.max_count,
        "is_full": table.is_full,
        "reservations": [
            {"mac": reservation.mac, "ip": reservation.ip} for reservation in table.reservations
        ],
    }


def _ordered_observations(
    observations: tuple[EndpointObservation, ...],
    endpoint_specs: tuple[EndpointSpec, ...],
) -> tuple[EndpointObservation, ...]:
    by_name = {observation.name: observation for observation in observations}
    return tuple(by_name[endpoint.name] for endpoint in endpoint_specs if endpoint.name in by_name)


def _sensitive_manifest(
    *,
    model: str,
    hardware_versions: tuple[str, ...],
    firmware_version: str,
    system_mode: str,
    observations: tuple[EndpointObservation, ...],
) -> CompatibilityManifest:
    return CompatibilityManifest(
        manifest_version=1,
        catalog_version=CATALOG_VERSION,
        model=model,
        hardware_versions=hardware_versions,
        firmware_version=firmware_version,
        system_mode=system_mode,
        observed_at=datetime.now(UTC).isoformat(),
        observations=observations,
    )


def _write_private_json(path: Path, payload: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    file_descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(file_descriptor, 0o600)
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="LAN IP address of the main Deco")
    parser.add_argument("--user", default="admin", help="Login username (default: admin)")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--manifest-output",
        type=Path,
        help=(
            "write a value-free manifest (requires --discover-all, --full-manifest, "
            "--fuzzy-read-variants, or --retry-fuzzy-manifest)"
        ),
    )
    parser.add_argument(
        "--discover-all",
        action="store_true",
        help="probe the curated non-secret P9 read catalogue and retain response values",
    )
    parser.add_argument(
        "--full-manifest",
        action="store_true",
        help="probe every non-secret owner-session read but retain only value-free schemas",
    )
    parser.add_argument(
        "--fuzzy-read-variants",
        action="store_true",
        help=(
            "after the full catalogue pass, repeat bounded read aliases and parameter variants "
            "twice without retaining values"
        ),
    )
    parser.add_argument(
        "--fuzzy-delay",
        type=float,
        default=0.25,
        help="minimum delay between fuzzy requests in seconds (minimum: 0.1)",
    )
    parser.add_argument(
        "--retry-fuzzy-manifest",
        type=Path,
        help=(
            "retry from the first inconsistent fuzzy observation in a version 2 manifest "
            "without repeating the exact catalogue pass; incomplete older evidence is retried"
        ),
    )
    parser.add_argument(
        "--per-node-clients",
        action="store_true",
        help="query client_list separately for every Deco MAC to map client topology",
    )
    parser.add_argument(
        "--p9-sensitive-schemas",
        action="store_true",
        help=(
            "probe only secret reads declared by P9 web assets and retain field paths/types, "
            "never values or binary content"
        ),
    )
    parser.add_argument(
        "--all-sensitive-schemas",
        action="store_true",
        help=(
            "probe all catalogued secret owner-session JSON reads, checkpointing value-free "
            "schemas after every endpoint"
        ),
    )
    parser.add_argument(
        "--resume-sensitive-manifest",
        type=Path,
        help=(
            "resume the complete sensitive-schema pass, preserving stable observations and "
            "retrying missing or transient results"
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.manifest_output is not None and not (
        args.discover_all
        or args.full_manifest
        or args.fuzzy_read_variants
        or args.retry_fuzzy_manifest is not None
        or args.p9_sensitive_schemas
        or args.all_sensitive_schemas
        or args.resume_sensitive_manifest is not None
    ):
        raise SystemExit(
            "--manifest-output requires --discover-all, --full-manifest, "
            "--fuzzy-read-variants, --retry-fuzzy-manifest, --p9-sensitive-schemas, "
            "--all-sensitive-schemas, or --resume-sensitive-manifest"
        )
    if args.retry_fuzzy_manifest is not None and (
        args.discover_all or args.full_manifest or args.fuzzy_read_variants
    ):
        raise SystemExit(
            "--retry-fuzzy-manifest cannot be combined with discovery or fuzzy-read flags"
        )
    sensitive_mode = (
        args.p9_sensitive_schemas
        or args.all_sensitive_schemas
        or args.resume_sensitive_manifest is not None
    )
    if sensitive_mode and (
        args.discover_all
        or args.full_manifest
        or args.fuzzy_read_variants
        or args.retry_fuzzy_manifest is not None
        or args.per_node_clients
    ):
        raise SystemExit("sensitive-schema modes cannot be combined with other probe modes")
    if args.p9_sensitive_schemas and (
        args.all_sensitive_schemas or args.resume_sensitive_manifest is not None
    ):
        raise SystemExit("select only one sensitive-schema scope")
    if (args.all_sensitive_schemas or args.resume_sensitive_manifest is not None) and (
        args.manifest_output is None
    ):
        raise SystemExit("complete sensitive-schema probing requires --manifest-output")
    if (
        args.fuzzy_read_variants or args.retry_fuzzy_manifest is not None
    ) and args.fuzzy_delay < 0.1:
        raise SystemExit("--fuzzy-delay must be at least 0.1 seconds")
    retry_manifest: CompatibilityManifest | None = None
    retry_candidates: tuple[FuzzyReadCandidate, ...] = ()
    sensitive_resume: CompatibilityManifest | None = None
    if args.retry_fuzzy_manifest is not None:
        try:
            retry_manifest = CompatibilityManifest.from_json(
                args.retry_fuzzy_manifest.read_text(encoding="utf-8")
            )
            retry_candidates = _retry_candidates(retry_manifest)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"Failed to load fuzzy retry manifest: {exc}") from exc
        if not retry_candidates:
            raise SystemExit("Fuzzy retry manifest contains no incomplete or inconsistent evidence")
    if args.resume_sensitive_manifest is not None:
        try:
            sensitive_resume = CompatibilityManifest.from_json(
                args.resume_sensitive_manifest.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise SystemExit(f"Failed to load sensitive-schema manifest: {exc}") from exc
    password = os.environ.pop("DECO_PASSWORD", "")
    if not password:
        password = getpass.getpass("Deco owner password: ")
    if not password:
        raise SystemExit("No password was supplied")

    logging.getLogger("tplink_deco_api").setLevel(logging.WARNING)
    client = _ReadOnlyDecoClient(args.host, args.user, password, timeout=args.timeout)
    password = ""

    results: dict[str, JsonValue] = {}
    manifest: CompatibilityManifest | None = None
    fuzzy_observations: tuple[FuzzyReadObservation, ...] = ()
    print("Password received; authenticating...", flush=True)
    with client:
        print("Authenticated.", flush=True)
        operations: tuple[tuple[str, Callable[[], JsonValue]], ...] = ()
        if not sensitive_mode:
            print("Collecting snapshot reads...", flush=True)
            operations = (
                ("mesh_nodes", lambda: _mesh_nodes(client)),
                ("device_mode", lambda: _device_mode(client)),
                ("internet_status", lambda: _internet_status(client)),
                ("wan_lan", lambda: _wan_lan(client)),
                ("performance", lambda: _performance(client)),
                ("clients", lambda: _clients(client)),
                ("wireless_power", lambda: _wireless_power(client)),
                ("time_settings", lambda: _time_settings(client)),
                ("address_reservations", lambda: _address_reservations(client)),
            )
        if args.per_node_clients:
            operations += (("clients_by_node", lambda: _clients_by_node(client)),)
        for index, (name, operation) in enumerate(operations, start=1):
            print(f"[snapshot {index}/{len(operations)}] {name} ...", end="", flush=True)
            results[name] = _capture(operation)
            print(f" {results[name]['status']}", flush=True)
        if sensitive_mode:
            endpoint_scope = (
                P9_SENSITIVE_SCHEMA_ENDPOINTS
                if args.p9_sensitive_schemas
                else SENSITIVE_SCHEMA_ENDPOINTS
            )
            prior_observations = (
                _reusable_sensitive_observations(sensitive_resume, endpoint_scope)
                if sensitive_resume is not None
                else ()
            )
            reusable_names = {observation.name for observation in prior_observations}
            pending_endpoints = tuple(
                endpoint for endpoint in endpoint_scope if endpoint.name not in reusable_names
            )
            nodes = client.get_device_list()
            mode = client.get_device_mode()
            model = ", ".join(sorted({node.device_model for node in nodes if node.device_model}))
            hardware_versions = tuple(
                sorted({node.hardware_ver for node in nodes if node.hardware_ver})
            )
            firmware_version = ", ".join(
                sorted({node.software_ver for node in nodes if node.software_ver})
            )

            def checkpoint(observations: tuple[EndpointObservation, ...]) -> None:
                nonlocal manifest
                manifest = _sensitive_manifest(
                    model=model,
                    hardware_versions=hardware_versions,
                    firmware_version=firmware_version,
                    system_mode=mode.sysmode,
                    observations=_ordered_observations(observations, endpoint_scope),
                )
                if args.manifest_output is not None:
                    _write_private_json(args.manifest_output, manifest.to_dict())

            print(
                f"Collecting value-free schemas from {len(endpoint_scope)} sensitive reads "
                f"({len(prior_observations)} reusable, {len(pending_endpoints)} pending)...",
                flush=True,
            )
            sensitive_observations = _observe_sensitive_with_progress(
                client,
                pending_endpoints,
                prior_observations,
                checkpoint,
            )
            sensitive_observations = _ordered_observations(
                sensitive_observations,
                endpoint_scope,
            )
            checkpoint(sensitive_observations)
            results["sensitive_schema_discovery"] = {
                "status": "ok",
                "data": {
                    "scope": (
                        "p9_web_asset_secret_json_reads"
                        if args.p9_sensitive_schemas
                        else "complete_catalogued_secret_owner_session_json_reads"
                    ),
                    "probed": len(sensitive_observations),
                    "reused": len(prior_observations),
                    "newly_probed": len(pending_endpoints),
                    "supported": [
                        observation.name
                        for observation in sensitive_observations
                        if observation.status == "supported"
                    ],
                    "values_retained": False,
                    "binary_reads_excluded": True,
                },
            }
        elif retry_manifest is not None:
            print(
                f"Retrying {len(retry_candidates)} fuzzy variants from the first "
                "incomplete or inconsistent observation...",
                flush=True,
            )
            fuzzy_observations = _probe_fuzzy_with_progress(
                client,
                retry_candidates,
                args.fuzzy_delay,
            )
            results["fuzzy_read_discovery"] = _fuzzy_result(
                fuzzy_observations,
                len(retry_candidates),
                args.fuzzy_delay,
                "retry_from_first_incomplete_or_inconsistent_observation",
            )
            manifest = replace(
                retry_manifest,
                fuzzy_observations=_merge_fuzzy_observations(
                    retry_manifest.fuzzy_observations,
                    fuzzy_observations,
                ),
                fuzzy_observed_at=datetime.now(UTC).isoformat(),
            )
        elif args.discover_all or args.full_manifest or args.fuzzy_read_variants:
            endpoint_specs = (
                DISCOVERABLE_READ_ENDPOINTS
                if args.full_manifest or args.fuzzy_read_variants
                else P9_READ_ENDPOINTS
            )
            print(f"Probing {len(endpoint_specs)} catalogued endpoints...", flush=True)
            report = _probe_with_progress(client, endpoint_specs, args.host)
            if args.full_manifest or args.fuzzy_read_variants:
                results["endpoint_discovery"] = {
                    "status": "ok",
                    "data": {
                        "scope": "complete_non_secret_owner_session_catalog",
                        "probed": len(report.probes),
                        "supported": list(report.supported_names),
                    },
                }
            else:
                results["endpoint_discovery"] = {"status": "ok", "data": report.to_dict()}
            if args.fuzzy_read_variants:
                candidates = build_fuzzy_read_candidates(report)
                print(
                    f"Probing {len(candidates)} bounded fuzzy read variants twice...",
                    flush=True,
                )
                fuzzy_observations = _probe_fuzzy_with_progress(
                    client,
                    candidates,
                    args.fuzzy_delay,
                )
                results["fuzzy_read_discovery"] = _fuzzy_result(
                    fuzzy_observations,
                    len(candidates),
                    args.fuzzy_delay,
                    "complete_bounded_fuzzy_read_variants",
                )
            nodes = client.get_device_list()
            mode = client.get_device_mode()
            manifest = CompatibilityManifest.from_report(
                report,
                catalog_version=CATALOG_VERSION,
                model=", ".join(sorted({node.device_model for node in nodes if node.device_model})),
                hardware_versions=tuple(node.hardware_ver for node in nodes),
                firmware_version=", ".join(
                    sorted({node.software_ver for node in nodes if node.software_ver})
                ),
                system_mode=mode.sysmode,
                fuzzy_observations=fuzzy_observations,
            )
        payload: JsonObject = {
            "target": args.host,
            "probe_mode": ("sensitive_schema_only" if sensitive_mode else "read_only_allowlisted"),
            "excluded": {
                "sensitive_values": (
                    "queried transiently but discarded before serialization"
                    if sensitive_mode
                    else "not queried by automatic endpoint discovery"
                ),
                "binary_secret_reads": "not queried or downloaded",
                "fuzzy_routes": (
                    "limited to read-like operations on documented non-secret owner-session forms"
                ),
                "mutations": "catalogued but never invoked by this probe",
            },
            "results": results,
        }
        if manifest is not None:
            payload["compatibility_manifest"] = manifest.to_dict()

        if args.output is None:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            _write_private_json(args.output, payload)
            print(f"Sanitized result: {args.output}")
        if args.manifest_output is not None and manifest is not None:
            _write_private_json(args.manifest_output, manifest.to_dict())
            print(f"Compatibility manifest: {args.manifest_output}")


if __name__ == "__main__":
    main()
