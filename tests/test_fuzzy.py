"""Tests for bounded read-only endpoint variant discovery."""

from __future__ import annotations

from dataclasses import replace
from unittest import mock

import pytest
from examples.read_only_probe import _ReadOnlyDecoClient, _retry_candidates

from tplink_deco_api import (
    ApiResponse,
    CapabilityReport,
    CompatibilityManifest,
    EndpointProbeResult,
    FuzzyReadCandidate,
    FuzzyReadObservation,
    build_fuzzy_read_candidates,
    get_endpoint,
    restore_fuzzy_read_candidate,
)


def _ambiguous_report() -> CapabilityReport:
    rejected = EndpointProbeResult(
        endpoint=get_endpoint("admin.wireless.power.read"),
        status="rejected",
        elapsed_seconds=0.1,
        error_code=1,
    )
    accepted_null = EndpointProbeResult(
        endpoint=get_endpoint("admin.component_control.switch_list.read"),
        status="supported",
        elapsed_seconds=0.1,
        response=ApiResponse.from_api({"error_code": 0, "result": None}),
    )
    not_found = EndpointProbeResult(
        endpoint=get_endpoint("admin.route.route.read"),
        status="not_found",
        elapsed_seconds=0.1,
        http_status=404,
    )
    return CapabilityReport(
        "192.0.2.1", "2026-07-10T00:00:00Z", (rejected, accepted_null, not_found)
    )


def test_fuzzy_candidates_are_bounded_to_ambiguous_safe_forms() -> None:
    candidates = build_fuzzy_read_candidates(_ambiguous_report())

    assert candidates
    assert all(candidate.endpoint.safety == "read_only" for candidate in candidates)
    assert all(candidate.endpoint.sensitivity != "secret" for candidate in candidates)
    assert all(
        candidate.endpoint.operation in {"read", "get", "getlist", "list"}
        for candidate in candidates
    )
    assert all(candidate.source_name != "admin.route.route.read" for candidate in candidates)
    assert any(candidate.variant == "params:omitted" for candidate in candidates)
    assert any(candidate.variant == "params:empty" for candidate in candidates)


def test_fuzzy_candidate_parameter_schema_omits_values() -> None:
    candidate = FuzzyReadCandidate(
        endpoint=get_endpoint("admin.client.client_list.read"),
        source_name="admin.client.client_list.read",
        variant="params:device_mac_default",
        params={"device_mac": "do-not-retain"},
    )

    assert candidate.parameter_schema == ("device_mac:string",)
    assert "do-not-retain" not in str(candidate.parameter_schema)


def test_fuzzy_observation_requires_repeatable_support_and_roundtrips() -> None:
    candidate = FuzzyReadCandidate(
        endpoint=get_endpoint("admin.wireless.power.read"),
        source_name="admin.wireless.power.read",
        variant="params:empty",
        params={},
    )
    supported = EndpointProbeResult(
        endpoint=candidate.endpoint,
        status="supported",
        elapsed_seconds=0.2,
        response=ApiResponse.from_api({"error_code": 0, "result": {"enable": True}}),
    )
    observation = FuzzyReadObservation.from_attempts(candidate, (supported, supported))

    assert observation.consistent
    assert observation.confirmed_supported
    assert observation.confirmed_data
    assert observation.attempt_statuses == ("supported", "supported")
    assert observation.attempt_error_codes == (None, None)
    assert observation.attempt_session_recovered == (False, False)
    assert FuzzyReadObservation.from_api(observation.to_dict()) == observation

    inconsistent = FuzzyReadObservation.from_attempts(
        candidate,
        (
            supported,
            EndpointProbeResult(candidate.endpoint, "rejected", 0.1, error_code=1),
        ),
    )
    assert not inconsistent.consistent
    assert not inconsistent.confirmed_supported
    assert not inconsistent.confirmed_data

    changed_error = FuzzyReadObservation.from_attempts(
        candidate,
        (
            EndpointProbeResult(candidate.endpoint, "rejected", 0.1, error_code=-1),
            EndpointProbeResult(candidate.endpoint, "rejected", 0.1, error_code=1),
        ),
    )
    assert changed_error.attempt_statuses == ("rejected", "rejected")
    assert changed_error.attempt_error_codes == (-1, 1)
    assert not changed_error.consistent

    recovered_observation = FuzzyReadObservation.from_attempts(
        candidate,
        (supported, supported),
        (True, False),
    )
    assert recovered_observation.attempt_session_recovered == (True, False)

    accepted_null = EndpointProbeResult(
        candidate.endpoint,
        "supported",
        0.1,
        response=ApiResponse.from_api({"error_code": 0, "result": None}),
    )
    null_observation = FuzzyReadObservation.from_attempts(
        candidate,
        (accepted_null, accepted_null),
    )
    assert null_observation.confirmed_supported
    assert not null_observation.confirmed_data


def test_fuzzy_manifest_uses_version_two_and_preserves_provenance() -> None:
    report = _ambiguous_report()
    candidate = build_fuzzy_read_candidates(report)[0]
    attempt = EndpointProbeResult(candidate.endpoint, "rejected", 0.1, error_code=1)
    fuzzy = FuzzyReadObservation.from_attempts(candidate, (attempt, attempt))

    manifest = CompatibilityManifest.from_report(
        report,
        catalog_version=3,
        model="P9",
        hardware_versions=("1.0",),
        firmware_version="1.3.0",
        fuzzy_observations=(fuzzy,),
    )
    restored = CompatibilityManifest.from_json(manifest.to_json())

    assert manifest.manifest_version == 2
    assert manifest.fuzzy_observed_at == report.observed_at
    assert restored == manifest
    assert restored.fuzzy_observations[0].source_name == candidate.source_name

    without_fuzzy = replace(manifest, fuzzy_observations=())
    delta = manifest.compare(without_fuzzy)
    assert delta.fuzzy_added == (fuzzy.identity,)
    assert delta.to_dict()["fuzzy_added"] == [fuzzy.identity]


def test_fuzzy_candidate_restores_from_value_free_provenance() -> None:
    candidate = next(
        item
        for item in build_fuzzy_read_candidates(_ambiguous_report())
        if item.variant == "params:omitted"
    )
    attempt = EndpointProbeResult(candidate.endpoint, "rejected", 0.1, error_code=1)
    observation = FuzzyReadObservation.from_attempts(candidate, (attempt, attempt))

    assert restore_fuzzy_read_candidate(observation) == candidate

    with pytest.raises(ValueError, match="unsupported operation alias"):
        restore_fuzzy_read_candidate(replace(observation, variant="operation_alias:write"))


def test_retry_candidates_conservatively_include_suffix() -> None:
    report = _ambiguous_report()
    candidates = build_fuzzy_read_candidates(report)[:3]
    rejected = tuple(
        EndpointProbeResult(candidate.endpoint, "rejected", 0.1, error_code=1)
        for candidate in candidates
    )
    observations = (
        FuzzyReadObservation.from_attempts(candidates[0], (rejected[0], rejected[0])),
        FuzzyReadObservation.from_attempts(
            candidates[1],
            (
                EndpointProbeResult(candidates[1].endpoint, "rejected", 0.1, error_code=-1),
                rejected[1],
            ),
        ),
        FuzzyReadObservation.from_attempts(candidates[2], (rejected[2], rejected[2])),
    )
    manifest = CompatibilityManifest.from_report(
        report,
        catalog_version=3,
        model="P9",
        hardware_versions=("1.0",),
        firmware_version="1.3.0",
        fuzzy_observations=observations,
    )

    assert _retry_candidates(manifest) == candidates[1:]


def test_probe_recovers_expired_session_once() -> None:
    client = _ReadOnlyDecoClient("192.0.2.1", "admin", "secret")
    endpoint = get_endpoint("admin.wireless.power.read")
    expired = EndpointProbeResult(endpoint, "rejected", 0.1, error_code=-1)
    supported = EndpointProbeResult(
        endpoint,
        "supported",
        0.1,
        response=ApiResponse.from_api({"error_code": 0, "result": {"enable": True}}),
    )

    with (
        mock.patch.object(client, "probe_endpoint", side_effect=(expired, supported)) as probe,
        mock.patch.object(client, "invalidate_session") as invalidate,
        mock.patch.object(client, "login") as login,
    ):
        result, recovered = client._probe_with_session_recovery(endpoint)

    assert result is supported
    assert recovered
    assert probe.call_count == 2
    invalidate.assert_called_once_with()
    login.assert_called_once_with()


def test_probe_does_not_refresh_for_endpoint_rejection() -> None:
    client = _ReadOnlyDecoClient("192.0.2.1", "admin", "secret")
    endpoint = get_endpoint("admin.wireless.power.read")
    rejected = EndpointProbeResult(endpoint, "rejected", 0.1, error_code=1)

    with (
        mock.patch.object(client, "probe_endpoint", return_value=rejected) as probe,
        mock.patch.object(client, "login") as login,
    ):
        result, recovered = client._probe_with_session_recovery(endpoint)

    assert result is rejected
    assert not recovered
    probe.assert_called_once_with(endpoint, None)
    login.assert_not_called()


def test_probe_recognizes_transport_and_http_session_failures() -> None:
    endpoint = get_endpoint("admin.wireless.power.read")

    assert _ReadOnlyDecoClient._needs_session_recovery(
        EndpointProbeResult(endpoint, "transport_error", 0.1)
    )
    assert _ReadOnlyDecoClient._needs_session_recovery(
        EndpointProbeResult(endpoint, "transport_error", 0.1, http_status=403)
    )
    assert not _ReadOnlyDecoClient._needs_session_recovery(
        EndpointProbeResult(endpoint, "transport_error", 0.1, http_status=500)
    )


def test_probe_guard_accepts_registered_candidate_and_rejects_expansion() -> None:
    client = _ReadOnlyDecoClient("192.0.2.1", "admin", "secret")
    candidate = next(
        item
        for item in build_fuzzy_read_candidates(_ambiguous_report())
        if item.variant == "params:empty" and item.source_name == "admin.wireless.power.read"
    )
    client._allow_fuzzy_candidate(candidate)
    client._guard(
        candidate.endpoint.path,
        candidate.endpoint.form,
        candidate.endpoint.request_data(candidate.params),
    )

    with pytest.raises(PermissionError, match="unapproved parameters"):
        client._allow_fuzzy_candidate(replace(candidate, params={"enable": True}))
    with pytest.raises(PermissionError, match="non-read operation alias"):
        client._allow_fuzzy_candidate(
            replace(candidate, endpoint=replace(candidate.endpoint, operation="write"))
        )
    with pytest.raises(PermissionError, match="transport metadata"):
        client._allow_fuzzy_candidate(
            replace(candidate, endpoint=replace(candidate.endpoint, authentication="plain"))
        )
