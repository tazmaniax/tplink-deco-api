"""Versioned compatibility manifest for one observed Deco mesh."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .._json import JsonObject, JsonValue, get_int, get_str, get_str_tuple, loads
from .compatibility_delta import CompatibilityDelta
from .endpoint_observation import EndpointObservation
from .fuzzy_read_observation import FuzzyReadObservation

if TYPE_CHECKING:
    from .capability_report import CapabilityReport


@dataclass(frozen=True)
class CompatibilityManifest:
    """Persist firmware-specific endpoint evidence without response values."""

    manifest_version: int
    catalog_version: int
    model: str
    hardware_versions: tuple[str, ...]
    firmware_version: str
    system_mode: str
    observed_at: str
    observations: tuple[EndpointObservation, ...]
    fuzzy_observations: tuple[FuzzyReadObservation, ...] = ()
    fuzzy_observed_at: str = ""

    @classmethod
    def from_report(
        cls,
        report: CapabilityReport,
        *,
        catalog_version: int,
        model: str,
        hardware_versions: tuple[str, ...],
        firmware_version: str,
        system_mode: str = "",
        fuzzy_observations: tuple[FuzzyReadObservation, ...] = (),
    ) -> CompatibilityManifest:
        """Build a privacy-preserving manifest from live probe results."""
        return cls(
            manifest_version=2 if fuzzy_observations else 1,
            catalog_version=catalog_version,
            model=model,
            hardware_versions=tuple(sorted(set(hardware_versions))),
            firmware_version=firmware_version,
            system_mode=system_mode,
            observed_at=report.observed_at,
            observations=tuple(EndpointObservation.from_probe(probe) for probe in report.probes),
            fuzzy_observations=fuzzy_observations,
            fuzzy_observed_at=report.observed_at if fuzzy_observations else "",
        )

    @classmethod
    def from_dict(cls, data: JsonObject) -> CompatibilityManifest:
        """Restore and validate a serialized compatibility manifest."""
        observations_value = data.get("observations")
        observations = (
            tuple(
                EndpointObservation.from_api(item)
                for item in observations_value
                if isinstance(item, dict)
            )
            if isinstance(observations_value, list)
            else ()
        )
        fuzzy_value = data.get("fuzzy_observations")
        fuzzy_observations = (
            tuple(
                FuzzyReadObservation.from_api(item)
                for item in fuzzy_value
                if isinstance(item, dict)
            )
            if isinstance(fuzzy_value, list)
            else ()
        )
        manifest_version = get_int(data, "manifest_version")
        if manifest_version not in {1, 2}:
            raise ValueError(
                f"Failed to parse compatibility manifest: unsupported version {manifest_version}"
            )
        return cls(
            manifest_version=manifest_version,
            catalog_version=get_int(data, "catalog_version"),
            model=get_str(data, "model"),
            hardware_versions=get_str_tuple(data, "hardware_versions"),
            firmware_version=get_str(data, "firmware_version"),
            system_mode=get_str(data, "system_mode"),
            observed_at=get_str(data, "observed_at"),
            observations=observations,
            fuzzy_observations=fuzzy_observations,
            fuzzy_observed_at=get_str(data, "fuzzy_observed_at"),
        )

    @classmethod
    def from_json(cls, payload: str) -> CompatibilityManifest:
        """Restore a manifest from JSON text."""
        return cls.from_dict(loads(payload))

    def to_dict(self) -> dict[str, JsonValue]:
        """Return JSON-compatible manifest data without endpoint values."""
        return {
            "manifest_version": self.manifest_version,
            "catalog_version": self.catalog_version,
            "model": self.model,
            "hardware_versions": list(self.hardware_versions),
            "firmware_version": self.firmware_version,
            "system_mode": self.system_mode,
            "observed_at": self.observed_at,
            "observations": [observation.to_dict() for observation in self.observations],
            "fuzzy_observations": [
                observation.to_dict() for observation in self.fuzzy_observations
            ],
            "fuzzy_observed_at": self.fuzzy_observed_at,
        }

    def to_json(self) -> str:
        """Serialize the manifest deterministically for storage or comparison."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def compare(self, previous: CompatibilityManifest) -> CompatibilityDelta:
        """Compare this observation with an earlier firmware observation."""
        current_by_name = {item.name: item for item in self.observations}
        previous_by_name = {item.name: item for item in previous.observations}
        current_names = set(current_by_name)
        previous_names = set(previous_by_name)
        shared_names = current_names & previous_names
        current_fuzzy = {item.identity: item for item in self.fuzzy_observations}
        previous_fuzzy = {item.identity: item for item in previous.fuzzy_observations}
        current_fuzzy_names = set(current_fuzzy)
        previous_fuzzy_names = set(previous_fuzzy)
        shared_fuzzy_names = current_fuzzy_names & previous_fuzzy_names
        return CompatibilityDelta(
            previous_firmware=previous.firmware_version,
            current_firmware=self.firmware_version,
            added_operations=tuple(sorted(current_names - previous_names)),
            removed_operations=tuple(sorted(previous_names - current_names)),
            newly_supported=tuple(
                sorted(
                    name
                    for name in shared_names
                    if current_by_name[name].status == "supported"
                    and previous_by_name[name].status != "supported"
                )
            ),
            no_longer_supported=tuple(
                sorted(
                    name
                    for name in shared_names
                    if previous_by_name[name].status == "supported"
                    and current_by_name[name].status != "supported"
                )
            ),
            status_changed=tuple(
                sorted(
                    name
                    for name in shared_names
                    if current_by_name[name].status != previous_by_name[name].status
                )
            ),
            schema_changed=tuple(
                sorted(
                    name
                    for name in shared_names
                    if current_by_name[name].schema_sha256
                    and previous_by_name[name].schema_sha256
                    and current_by_name[name].schema_sha256 != previous_by_name[name].schema_sha256
                )
            ),
            fuzzy_added=tuple(sorted(current_fuzzy_names - previous_fuzzy_names)),
            fuzzy_removed=tuple(sorted(previous_fuzzy_names - current_fuzzy_names)),
            fuzzy_changed=tuple(
                sorted(
                    name
                    for name in shared_fuzzy_names
                    if (
                        current_fuzzy[name].attempt_statuses
                        != previous_fuzzy[name].attempt_statuses
                        or current_fuzzy[name].attempt_error_codes
                        != previous_fuzzy[name].attempt_error_codes
                        or current_fuzzy[name].attempt_http_statuses
                        != previous_fuzzy[name].attempt_http_statuses
                        or current_fuzzy[name].attempt_session_recovered
                        != previous_fuzzy[name].attempt_session_recovered
                        or current_fuzzy[name].confirmed_data != previous_fuzzy[name].confirmed_data
                        or current_fuzzy[name].schema_sha256 != previous_fuzzy[name].schema_sha256
                    )
                )
            ),
        )
