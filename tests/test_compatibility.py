"""Tests for privacy-preserving firmware compatibility manifests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from tplink_deco_api import (
    ApiResponse,
    CapabilityReport,
    CompatibilityManifest,
    EndpointObservation,
    EndpointProbeResult,
    get_endpoint,
)


def _manifest() -> CompatibilityManifest:
    supported = EndpointProbeResult(
        endpoint=get_endpoint("admin.client.client_list.read"),
        status="supported",
        elapsed_seconds=1.25,
        response=ApiResponse.from_api(
            {
                "error_code": 0,
                "result": {
                    "client_list": [
                        {
                            "mac": "AA:BB:CC:DD:EE:FF",
                            "ip": "192.168.68.10",
                            "online": True,
                        }
                    ]
                },
            }
        ),
    )
    rejected = EndpointProbeResult(
        endpoint=get_endpoint("admin.wireless.beamforming.read"),
        status="rejected",
        elapsed_seconds=0.5,
        error_code=1,
        error="Failed to call API: error_code=1",
    )
    report = CapabilityReport(
        host="192.168.68.1",
        observed_at="2026-07-10T12:00:00+00:00",
        probes=(supported, rejected),
    )
    return CompatibilityManifest.from_report(
        report,
        catalog_version=1,
        model="P9",
        hardware_versions=("2.0", "1.0", "1.0"),
        firmware_version="1.3.0 Build 20250804 Rel. 58832",
        system_mode="Router",
    )


def test_manifest_records_schema_without_private_values() -> None:
    manifest = _manifest()
    payload = manifest.to_json()
    observation = manifest.observations[0]

    assert manifest.hardware_versions == ("1.0", "2.0")
    assert observation.status == "supported"
    assert "$.client_list[]:object" in observation.schema_paths
    assert "$.client_list[].mac:string" in observation.schema_paths
    assert len(observation.schema_sha256) == 64
    assert "AA:BB:CC:DD:EE:FF" not in payload
    assert "192.168.68.10" not in payload
    assert "client_list" in payload


def test_manifest_json_roundtrip() -> None:
    manifest = _manifest()

    restored = CompatibilityManifest.from_json(manifest.to_json())

    assert restored == manifest
    assert restored.to_dict()["manifest_version"] == 1


def test_manifest_rejects_unknown_version_and_observation_status() -> None:
    manifest_data = _manifest().to_dict()
    manifest_data["manifest_version"] = 3
    with pytest.raises(ValueError, match="unsupported version"):
        CompatibilityManifest.from_dict(manifest_data)

    observation_data = _manifest().observations[0].to_dict()
    observation_data["status"] = "maybe"
    with pytest.raises(ValueError, match="invalid status"):
        EndpointObservation.from_api(observation_data)


def test_manifest_preserves_not_found_http_status() -> None:
    probe = EndpointProbeResult(
        endpoint=get_endpoint("admin.route.route.read"),
        status="not_found",
        elapsed_seconds=0.2,
        http_status=404,
    )

    observation = EndpointObservation.from_probe(probe)
    restored = EndpointObservation.from_api(observation.to_dict())

    assert restored.status == "not_found"
    assert restored.http_status == 404


def test_manifest_compare_reports_status_schema_and_catalog_changes() -> None:
    previous = _manifest()
    client_observation, beamforming_observation = previous.observations
    current = replace(
        previous,
        firmware_version="1.4.0",
        observations=(
            replace(
                client_observation,
                schema_paths=(*client_observation.schema_paths, "$.client_list[].hostname:string"),
                schema_sha256="changed",
            ),
            replace(
                beamforming_observation,
                status="supported",
                error_code=None,
                schema_paths=("$:object", "$.enable:boolean"),
                schema_sha256="new-schema",
            ),
            EndpointObservation(
                name="admin.device.led.read",
                status="supported",
                response_kind="object",
                elapsed_seconds=0.2,
                error_code=None,
                schema_paths=("$:object",),
                schema_sha256="led-schema",
            ),
        ),
    )

    delta = current.compare(previous)

    assert delta.has_changes
    assert delta.current_firmware == "1.4.0"
    assert delta.added_operations == ("admin.device.led.read",)
    assert delta.removed_operations == ()
    assert delta.newly_supported == ("admin.wireless.beamforming.read",)
    assert delta.no_longer_supported == ()
    assert delta.status_changed == ("admin.wireless.beamforming.read",)
    assert delta.schema_changed == ("admin.client.client_list.read",)
    assert delta.to_dict()["has_changes"] is True


def test_manifest_compare_can_report_removed_and_lost_support() -> None:
    previous = _manifest()
    current = replace(
        previous,
        observations=(replace(previous.observations[0], status="rejected"),),
    )

    delta = current.compare(previous)

    assert delta.removed_operations == ("admin.wireless.beamforming.read",)
    assert delta.no_longer_supported == ("admin.client.client_list.read",)


def test_identical_manifest_has_no_changes() -> None:
    manifest = _manifest()

    delta = manifest.compare(manifest)

    assert not delta.has_changes
