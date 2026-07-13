"""Explicit authorization boundary for source-checkout TMP write research."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._json import JsonValue
    from .tmp_client import DecoTmpClient

TMP_LAB_WRITE_ENV = "DECO_TMP_LAB_ALLOW_WRITES"
_TRUE_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_MAC_PATTERN = re.compile(r"^[0-9A-F]{12}$")


@dataclass(frozen=True)
class TmpLabTarget:
    """Bind one lab authorization to an exact live Deco controller identity."""

    model: str
    firmware_version: str
    controller_mac: str

    def __post_init__(self) -> None:
        if not self.model.strip():
            raise ValueError("Failed to configure TMP lab target: model is required")
        if not self.firmware_version.strip():
            raise ValueError("Failed to configure TMP lab target: firmware version is required")
        if not _MAC_PATTERN.fullmatch(_normalized_mac(self.controller_mac)):
            raise ValueError("Failed to configure TMP lab target: controller MAC is invalid")

    @classmethod
    def from_env(cls) -> TmpLabTarget:
        """Load an exact lab target without providing server integration."""
        return cls(
            model=os.environ.get("DECO_TMP_LAB_TARGET_MODEL", ""),
            firmware_version=os.environ.get("DECO_TMP_LAB_TARGET_FIRMWARE", ""),
            controller_mac=os.environ.get("DECO_TMP_LAB_TARGET_MAC", ""),
        )


def require_tmp_lab_write_enabled() -> None:
    """Reject lab writes unless the source-checkout-only gate is explicitly enabled."""
    enabled = os.environ.get(TMP_LAB_WRITE_ENV, "").strip().lower() in _TRUE_VALUES
    if not enabled:
        raise PermissionError(
            "Failed to authorize TMP lab write: DECO_TMP_LAB_ALLOW_WRITES is disabled"
        )


def verify_tmp_lab_target(client: DecoTmpClient, expected: TmpLabTarget | None = None) -> None:
    """Verify the live controller identity before a lab write is permitted."""
    require_tmp_lab_write_enabled()
    expected = expected or TmpLabTarget.from_env()
    response = client.request_read_json(0x400F)
    if response.get("error_code") != 0:
        raise PermissionError(
            "Failed to authorize TMP lab write: controller identity read was rejected"
        )
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise PermissionError(
            "Failed to authorize TMP lab write: controller identity result is missing"
        )
    devices = result.get("device_list")
    if not isinstance(devices, (list, tuple)):
        raise PermissionError(
            "Failed to authorize TMP lab write: controller device list is missing"
        )
    controller = next(
        (
            device
            for device in devices
            if isinstance(device, Mapping) and device.get("role") == "master"
        ),
        None,
    )
    if controller is None:
        raise PermissionError(
            "Failed to authorize TMP lab write: main controller identity is missing"
        )
    observed = (
        controller.get("device_model"),
        controller.get("software_ver"),
        _normalized_mac(controller.get("mac")),
    )
    required = (
        expected.model.strip(),
        expected.firmware_version.strip(),
        _normalized_mac(expected.controller_mac),
    )
    if observed != required:
        raise PermissionError(
            "Failed to authorize TMP lab write: live controller identity does not match target"
        )


def _normalized_mac(value: JsonValue) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace(":", "").replace("-", "").strip().upper()
