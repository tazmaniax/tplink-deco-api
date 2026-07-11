"""Privacy-preserving evidence from repeated fuzzy read probes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .._json import JsonObject, JsonValue, get_bool, get_float, get_int, get_str, get_str_tuple
from .endpoint_observation import EndpointObservation

if TYPE_CHECKING:
    from .endpoint_probe_result import EndpointProbeResult, ProbeStatus
    from .fuzzy_read_candidate import FuzzyReadCandidate

_PROBE_STATUSES: frozenset[str] = frozenset(
    {"supported", "rejected", "not_found", "transport_error", "invalid_response"}
)


@dataclass(frozen=True)
class FuzzyReadObservation:
    """Record repeated variant outcomes and provenance without response values."""

    name: str
    source_name: str
    variant: str
    parameter_schema: tuple[str, ...]
    attempt_statuses: tuple[ProbeStatus, ...]
    attempt_error_codes: tuple[int | None, ...]
    attempt_http_statuses: tuple[int | None, ...]
    attempt_session_recovered: tuple[bool, ...]
    consistent: bool
    confirmed_supported: bool
    confirmed_data: bool
    response_kind: str
    elapsed_seconds: float
    error_code: int | None
    http_status: int | None
    schema_paths: tuple[str, ...]
    schema_sha256: str

    @property
    def identity(self) -> str:
        """Return a stable value-free identifier for manifest comparison."""
        parameter_schema = ",".join(self.parameter_schema)
        return f"{self.name}::{self.variant}[{parameter_schema}]"

    @classmethod
    def from_attempts(
        cls,
        candidate: FuzzyReadCandidate,
        attempts: tuple[EndpointProbeResult, ...],
        session_recovered: tuple[bool, ...] = (),
    ) -> FuzzyReadObservation:
        """Summarize repeated attempts, preferring the latest successful schema."""
        if not attempts:
            raise ValueError("Failed to summarize fuzzy read: no attempts were supplied")
        if session_recovered and len(session_recovered) != len(attempts):
            raise ValueError("Failed to summarize fuzzy read: recovery evidence is misaligned")
        statuses = tuple(attempt.status for attempt in attempts)
        attempt_observations = tuple(
            EndpointObservation.from_probe(attempt) for attempt in attempts
        )
        signatures = tuple(
            (
                attempt.status,
                attempt.error_code,
                attempt.http_status,
                observation.schema_sha256,
            )
            for attempt, observation in zip(attempts, attempt_observations, strict=True)
        )
        selected = next(
            (attempt for attempt in reversed(attempts) if attempt.response is not None),
            attempts[-1],
        )
        observation = EndpointObservation.from_probe(selected)
        return cls(
            name=candidate.endpoint.name,
            source_name=candidate.source_name,
            variant=candidate.variant,
            parameter_schema=candidate.parameter_schema,
            attempt_statuses=statuses,
            attempt_error_codes=tuple(attempt.error_code for attempt in attempts),
            attempt_http_statuses=tuple(attempt.http_status for attempt in attempts),
            attempt_session_recovered=(
                session_recovered if session_recovered else tuple(False for _ in attempts)
            ),
            consistent=len(set(signatures)) == 1,
            confirmed_supported=all(status == "supported" for status in statuses),
            confirmed_data=all(
                attempt.response is not None and attempt.response.result is not None
                for attempt in attempts
            ),
            response_kind=observation.response_kind,
            elapsed_seconds=sum(attempt.elapsed_seconds for attempt in attempts),
            error_code=attempts[-1].error_code,
            http_status=attempts[-1].http_status,
            schema_paths=observation.schema_paths,
            schema_sha256=observation.schema_sha256,
        )

    @classmethod
    def from_api(cls, data: JsonObject) -> FuzzyReadObservation:
        """Restore a fuzzy observation from a value-free manifest entry."""
        statuses = get_str_tuple(data, "attempt_statuses")
        if any(status not in _PROBE_STATUSES for status in statuses):
            raise ValueError("Failed to parse fuzzy read observation: invalid attempt status")
        error_code_value = data.get("error_code")
        http_status_value = data.get("http_status")
        return cls(
            name=get_str(data, "name"),
            source_name=get_str(data, "source_name"),
            variant=get_str(data, "variant"),
            parameter_schema=get_str_tuple(data, "parameter_schema"),
            attempt_statuses=cast("tuple[ProbeStatus, ...]", statuses),
            attempt_error_codes=_optional_int_tuple(data, "attempt_error_codes"),
            attempt_http_statuses=_optional_int_tuple(data, "attempt_http_statuses"),
            attempt_session_recovered=_bool_tuple(data, "attempt_session_recovered"),
            consistent=get_bool(data, "consistent"),
            confirmed_supported=get_bool(data, "confirmed_supported"),
            confirmed_data=get_bool(data, "confirmed_data"),
            response_kind=get_str(data, "response_kind"),
            elapsed_seconds=get_float(data, "elapsed_seconds"),
            error_code=(get_int(data, "error_code") if isinstance(error_code_value, int) else None),
            http_status=(
                get_int(data, "http_status") if isinstance(http_status_value, int) else None
            ),
            schema_paths=get_str_tuple(data, "schema_paths"),
            schema_sha256=get_str(data, "schema_sha256"),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Return auditable variant evidence without parameter or response values."""
        return {
            "name": self.name,
            "source_name": self.source_name,
            "variant": self.variant,
            "parameter_schema": list(self.parameter_schema),
            "attempt_statuses": list(self.attempt_statuses),
            "attempt_error_codes": list(self.attempt_error_codes),
            "attempt_http_statuses": list(self.attempt_http_statuses),
            "attempt_session_recovered": list(self.attempt_session_recovered),
            "consistent": self.consistent,
            "confirmed_supported": self.confirmed_supported,
            "confirmed_data": self.confirmed_data,
            "response_kind": self.response_kind,
            "elapsed_seconds": self.elapsed_seconds,
            "error_code": self.error_code,
            "http_status": self.http_status,
            "schema_paths": list(self.schema_paths),
            "schema_sha256": self.schema_sha256,
        }


def _optional_int_tuple(data: JsonObject, key: str) -> tuple[int | None, ...]:
    value = data.get(key)
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item if isinstance(item, int) and not isinstance(item, bool) else None for item in value
    )


def _bool_tuple(data: JsonObject, key: str) -> tuple[bool, ...]:
    value = data.get(key)
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, bool))
