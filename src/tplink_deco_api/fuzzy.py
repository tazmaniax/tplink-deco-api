"""Generate bounded read-only variants for ambiguous endpoint observations."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from .endpoint_catalog import ENDPOINT_CATALOG, get_endpoint
from .models import (
    CapabilityReport,
    EndpointProbeResult,
    FuzzyReadCandidate,
    FuzzyReadObservation,
)

if TYPE_CHECKING:
    from .endpoint_spec import EndpointSpec

_READ_ALIASES: tuple[str, ...] = ("read", "get", "getlist", "list")
_DEVICE_SCOPED_FORMS: frozenset[tuple[str, str]] = frozenset(
    {
        ("admin/network", "lan_block"),
        ("admin/network", "mac_clone_list"),
        ("admin/network", "dsl_status"),
        ("admin/wireless", "bridge"),
        ("admin/wireless", "power"),
        ("admin/device", "system"),
        ("admin/device", "gateway"),
        ("admin/device", "mini_device_list"),
        ("admin/device", "envar"),
        ("admin/device", "get_server"),
        ("admin/device", "led"),
        ("admin/device", "sysmode"),
        ("admin/device", "signal_level_list"),
        ("admin/device", "detect_mode"),
        ("admin/device", "fixed_wan_port"),
        ("admin/device", "systime"),
        ("admin/device", "eco_mode"),
    }
)


def build_fuzzy_read_candidates(report: CapabilityReport) -> tuple[FuzzyReadCandidate, ...]:
    """Build hard-bounded aliases and parameter shapes for ambiguous safe reads."""
    catalog_keys = {(item.path, item.form, item.operation) for item in ENDPOINT_CATALOG}
    unsafe_keys = {
        (item.path, item.form, item.operation)
        for item in ENDPOINT_CATALOG
        if item.safety != "read_only"
    }
    candidates: list[FuzzyReadCandidate] = []
    seen: set[tuple[str, str, str, str]] = set()
    for probe in report.probes:
        endpoint = probe.endpoint
        if not _is_ambiguous_read(probe) or not _is_safe_source(endpoint):
            continue
        for operation in _READ_ALIASES:
            key = (endpoint.path, endpoint.form, operation)
            if operation == endpoint.operation or key in catalog_keys or key in unsafe_keys:
                continue
            alias_endpoint = replace(
                endpoint,
                operation=operation,
                required_params=(),
                optional_params=(),
                contract_source="none",
            )
            _append_candidate(
                candidates,
                seen,
                FuzzyReadCandidate(
                    endpoint=alias_endpoint,
                    source_name=endpoint.name,
                    variant=f"operation_alias:{operation}",
                    params=endpoint.default_params,
                ),
            )

        parameter_endpoint = replace(endpoint, default_params=None)
        if endpoint.default_params is not None:
            _append_candidate(
                candidates,
                seen,
                FuzzyReadCandidate(
                    endpoint=parameter_endpoint,
                    source_name=endpoint.name,
                    variant="params:omitted",
                    params=None,
                ),
            )
        _append_candidate(
            candidates,
            seen,
            FuzzyReadCandidate(
                endpoint=parameter_endpoint,
                source_name=endpoint.name,
                variant="params:empty",
                params={},
            ),
        )
        if (endpoint.path, endpoint.form) in _DEVICE_SCOPED_FORMS and endpoint.default_params != {
            "device_mac": "default"
        }:
            _append_candidate(
                candidates,
                seen,
                FuzzyReadCandidate(
                    endpoint=parameter_endpoint,
                    source_name=endpoint.name,
                    variant="params:device_mac_default",
                    params={"device_mac": "default"},
                ),
            )
    return tuple(candidates)


def restore_fuzzy_read_candidate(observation: FuzzyReadObservation) -> FuzzyReadCandidate:
    """Restore one generated request from value-free, allowlisted provenance."""
    source = get_endpoint(observation.source_name)
    if not _is_safe_source(source):
        raise ValueError("Failed to restore fuzzy read: source is not a safe discoverable read")

    if observation.variant.startswith("operation_alias:"):
        operation = observation.variant.removeprefix("operation_alias:")
        if operation not in _READ_ALIASES:
            raise ValueError("Failed to restore fuzzy read: unsupported operation alias")
        endpoint = replace(
            source,
            operation=operation,
            required_params=(),
            optional_params=(),
            contract_source="none",
        )
        params = source.default_params
    elif observation.variant == "params:omitted":
        endpoint = replace(source, default_params=None)
        params = None
    elif observation.variant == "params:empty":
        endpoint = replace(source, default_params=None)
        params = {}
    elif observation.variant == "params:device_mac_default":
        if (source.path, source.form) not in _DEVICE_SCOPED_FORMS:
            raise ValueError("Failed to restore fuzzy read: form is not device-scoped")
        endpoint = replace(source, default_params=None)
        params = {"device_mac": "default"}
    else:
        raise ValueError("Failed to restore fuzzy read: unknown variant")

    candidate = FuzzyReadCandidate(endpoint, source.name, observation.variant, params)
    if candidate.endpoint.name != observation.name:
        raise ValueError("Failed to restore fuzzy read: endpoint provenance does not match")
    if candidate.parameter_schema != observation.parameter_schema:
        raise ValueError("Failed to restore fuzzy read: parameter provenance does not match")
    return candidate


def _is_ambiguous_read(probe: EndpointProbeResult) -> bool:
    return probe.status in {"rejected", "transport_error", "invalid_response"} or (
        probe.status == "supported" and probe.response is not None and probe.response.result is None
    )


def _is_safe_source(endpoint: EndpointSpec) -> bool:
    return (
        endpoint.safety == "read_only"
        and endpoint.sensitivity != "secret"
        and endpoint.generic_call_supported
    )


def _append_candidate(
    candidates: list[FuzzyReadCandidate],
    seen: set[tuple[str, str, str, str]],
    candidate: FuzzyReadCandidate,
) -> None:
    identity = (
        candidate.endpoint.path,
        candidate.endpoint.form,
        candidate.endpoint.operation,
        candidate.variant,
    )
    if identity not in seen:
        seen.add(identity)
        candidates.append(candidate)
