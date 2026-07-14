"""Normalize HTTP and TMP firmware availability into one semantic shape."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue

_ReleaseKey = tuple[str, str, str, str, bool, bool, bool, str, int]


@dataclass
class _FirmwareRelease:
    """Accumulate transport-specific firmware rows for one semantic release."""

    device_model: str
    hardware_id: str
    oem_id: str
    latest_version: str
    need_to_download: bool
    need_to_upgrade: bool
    force_upgrade: bool
    release_date: str
    file_size_bytes: int
    release_note: str | None
    current_versions: set[str] = field(default_factory=set)
    device_ids: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the canonical release shape."""
        return {
            "device_model": self.device_model,
            "hardware_id": self.hardware_id,
            "oem_id": self.oem_id,
            "latest_version": self.latest_version,
            "current_versions": sorted(self.current_versions),
            "device_ids": sorted(self.device_ids),
            "need_to_download": self.need_to_download,
            "need_to_upgrade": self.need_to_upgrade,
            "force_upgrade": self.force_upgrade,
            "release_date": self.release_date,
            "release_note": self.release_note,
            "file_size_bytes": self.file_size_bytes,
        }


def normalize_http_firmware_status(data: JsonObject) -> dict[str, JsonValue]:
    """Normalize node-oriented HTTP firmware records into grouped releases."""
    releases: dict[_ReleaseKey, _FirmwareRelease] = {}
    for row in _required_rows(data, "HTTP"):
        release = _http_release(row)
        key = _release_key(release)
        accumulated = releases.setdefault(key, release)
        accumulated.current_versions.add(_required_string(row, "software_ver", "HTTP"))
        accumulated.device_ids.add(_required_string(row, "device_id", "HTTP"))
    return _firmware_view(releases, ("releases[].release_note",))


def normalize_tmp_firmware_status(data: JsonObject) -> dict[str, JsonValue]:
    """Normalize release-oriented TMP firmware records into grouped releases."""
    releases: dict[_ReleaseKey, _FirmwareRelease] = {}
    for row in _required_rows(data, "TMP"):
        release = _tmp_release(row)
        key = _release_key(release)
        accumulated = releases.setdefault(key, release)
        accumulated.device_ids.update(_required_string_array(row, "device_id_list", "TMP"))
    return _firmware_view(releases, ("releases[].current_versions",))


def _http_release(data: JsonObject) -> _FirmwareRelease:
    return _FirmwareRelease(
        device_model=_required_string(data, "device_model", "HTTP"),
        hardware_id=_required_string(data, "hw_id", "HTTP"),
        oem_id=_required_string(data, "oem_id", "HTTP"),
        latest_version=_required_string(data, "new_version", "HTTP"),
        need_to_download=_required_bool(data, "need_to_download", "HTTP"),
        need_to_upgrade=_required_bool(data, "need_to_upgrade", "HTTP"),
        force_upgrade=_required_bool(data, "need_force_upgrade", "HTTP"),
        release_date=_required_string(data, "release_date", "HTTP"),
        file_size_bytes=_required_int(data, "file_size", "HTTP"),
        release_note=None,
    )


def _tmp_release(data: JsonObject) -> _FirmwareRelease:
    return _FirmwareRelease(
        device_model=_required_string(data, "device_model", "TMP"),
        hardware_id=_required_string(data, "hw_id", "TMP"),
        oem_id=_required_string(data, "oem_id", "TMP"),
        latest_version=_required_string(data, "version", "TMP"),
        need_to_download=_required_bool(data, "need_to_download", "TMP"),
        need_to_upgrade=_required_bool(data, "need_to_upgrade", "TMP"),
        force_upgrade=_required_bool(data, "need_force_upgrade", "TMP"),
        release_date=_required_string(data, "release_date", "TMP"),
        file_size_bytes=_required_int(data, "file_size", "TMP"),
        release_note=_required_string(data, "release_note", "TMP"),
    )


def _release_key(release: _FirmwareRelease) -> _ReleaseKey:
    return (
        release.device_model,
        release.hardware_id,
        release.oem_id,
        release.latest_version,
        release.need_to_download,
        release.need_to_upgrade,
        release.force_upgrade,
        release.release_date,
        release.file_size_bytes,
    )


def _firmware_view(
    releases: Mapping[_ReleaseKey, _FirmwareRelease],
    unavailable_fields: tuple[str, ...],
) -> dict[str, JsonValue]:
    ordered = sorted(releases.values(), key=_release_key)
    return {
        "update_available": any(
            release.need_to_download or release.need_to_upgrade for release in ordered
        ),
        "release_count": len(ordered),
        "releases": [release.to_dict() for release in ordered],
        "unavailable_fields": list(unavailable_fields),
    }


def _required_rows(data: JsonObject, interface: str) -> tuple[JsonObject, ...]:
    value = data.get("fw_list")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(
            f"Failed to normalize {interface} firmware status: fw_list is not an array"
        )
    if any(not isinstance(item, Mapping) for item in value):
        raise ValueError(
            f"Failed to normalize {interface} firmware status: fw_list contains a non-object"
        )
    return tuple(item for item in value if isinstance(item, Mapping))


def _required_string(data: JsonObject, key: str, interface: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Failed to normalize {interface} firmware status: {key} is not a string")
    return value


def _required_string_array(data: JsonObject, key: str, interface: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"Failed to normalize {interface} firmware status: {key} is not an array")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(
            f"Failed to normalize {interface} firmware status: {key} contains a non-string"
        )
    return tuple(item for item in value if isinstance(item, str))


def _required_bool(data: JsonObject, key: str, interface: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to normalize {interface} firmware status: {key} is not a boolean")
    return value


def _required_int(data: JsonObject, key: str, interface: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(
            f"Failed to normalize {interface} firmware status: {key} is not an integer"
        )
    return value
