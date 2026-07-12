"""Privacy-preserving observation of one endpoint response schema."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .._json import JsonObject, JsonValue, get_float, get_int, get_str, get_str_tuple

if TYPE_CHECKING:
    from .endpoint_probe_result import EndpointProbeResult, ProbeStatus

_PROBE_STATUSES: frozenset[str] = frozenset(
    {"supported", "rejected", "not_found", "transport_error", "invalid_response"}
)


def _schema_entries(value: JsonValue, path: str = "$") -> set[str]:
    if value is None:
        return {f"{path}:null"}
    if isinstance(value, bool):
        return {f"{path}:boolean"}
    if isinstance(value, int):
        return {f"{path}:integer"}
    if isinstance(value, float):
        return {f"{path}:number"}
    if isinstance(value, str):
        return {f"{path}:string"}
    if isinstance(value, Mapping):
        entries = {f"{path}:object"}
        for key, child in value.items():
            entries.update(_schema_entries(child, f"{path}.{key}"))
        return entries
    entries = {f"{path}:array"}
    for child in value:
        entries.update(_schema_entries(child, f"{path}[]"))
    return entries


@dataclass(frozen=True)
class EndpointObservation:
    """Capture availability and response shape without retaining response values."""

    name: str
    status: ProbeStatus
    response_kind: str
    elapsed_seconds: float
    error_code: int | None
    schema_paths: tuple[str, ...]
    schema_sha256: str
    http_status: int | None = None

    @classmethod
    def from_probe(cls, probe: EndpointProbeResult) -> EndpointObservation:
        """Summarize a probe without copying private payload values."""
        schema_paths = (
            tuple(sorted(_schema_entries(probe.response.result)))
            if probe.response is not None
            else ()
        )
        signature = "\n".join(schema_paths).encode()
        return cls(
            name=probe.endpoint.name,
            status=probe.status,
            response_kind=probe.endpoint.response_kind,
            elapsed_seconds=probe.elapsed_seconds,
            error_code=probe.error_code,
            schema_paths=schema_paths,
            schema_sha256=hashlib.sha256(signature).hexdigest() if schema_paths else "",
            http_status=probe.http_status,
        )

    @classmethod
    def from_api(cls, data: JsonObject) -> EndpointObservation:
        """Restore an observation from a serialized compatibility manifest."""
        status = get_str(data, "status")
        if status not in _PROBE_STATUSES:
            raise ValueError(f"Failed to parse endpoint observation: invalid status {status!r}")
        error_code_value = data.get("error_code")
        http_status_value = data.get("http_status")
        return cls(
            name=get_str(data, "name"),
            status=cast("ProbeStatus", status),
            response_kind=get_str(data, "response_kind"),
            elapsed_seconds=get_float(data, "elapsed_seconds"),
            error_code=(get_int(data, "error_code") if isinstance(error_code_value, int) else None),
            schema_paths=get_str_tuple(data, "schema_paths"),
            schema_sha256=get_str(data, "schema_sha256"),
            http_status=(
                get_int(data, "http_status") if isinstance(http_status_value, int) else None
            ),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Return JSON-compatible observation metadata."""
        return {
            "name": self.name,
            "status": self.status,
            "response_kind": self.response_kind,
            "elapsed_seconds": self.elapsed_seconds,
            "error_code": self.error_code,
            "schema_paths": list(self.schema_paths),
            "schema_sha256": self.schema_sha256,
            "http_status": self.http_status,
        }
