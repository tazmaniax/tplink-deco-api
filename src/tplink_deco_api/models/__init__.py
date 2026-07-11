"""Public dataclasses returned by the SDK."""

from __future__ import annotations

from .address_reservation import AddressReservation
from .address_reservation_table import AddressReservationTable
from .api_response import ApiResponse
from .binary_response import BinaryResponse
from .capability_report import CapabilityReport
from .client_device import ClientDevice
from .compatibility_delta import CompatibilityDelta
from .compatibility_manifest import CompatibilityManifest
from .device import Device
from .device_mode import DeviceMode
from .dsl_status import DslStatus
from .endpoint_observation import EndpointObservation
from .endpoint_probe_result import EndpointProbeResult
from .fuzzy_read_candidate import FuzzyReadCandidate
from .fuzzy_read_observation import FuzzyReadObservation
from .http_mutation_verification_candidate import HttpMutationVerificationCandidate
from .http_noop_verification_result import HttpNoopVerificationResult
from .internet_status import InternetStatus, IpStatus
from .log_type import LogType
from .login_result import LoginResult
from .model_compatibility_profile import ModelCompatibilityProfile
from .mutation_plan import MutationPlan
from .network_totals import NetworkTotals
from .node_client_list import NodeClientList
from .operation_compatibility import OperationCompatibility
from .performance import Performance
from .signal_level import SignalLevel
from .speed_test import SpeedTest
from .time_settings import TimeSettings
from .tmp_mutation_plan import TmpMutationPlan
from .tmp_mutation_verification_candidate import TmpMutationVerificationCandidate
from .tmp_noop_verification_result import TmpNoopVerificationResult
from .tmp_opcode_spec import TmpOpcodeSpec
from .wan_info import IpInfo, LanDetails, WanDetails, WanInfo
from .wireless_power import WirelessPower
from .wlan_config import (
    IotHost,
    MloHost,
    WlanBackhaul,
    WlanBand,
    WlanConfig,
    WlanGuest,
    WlanHost,
)

__all__ = [
    "AddressReservation",
    "AddressReservationTable",
    "ApiResponse",
    "BinaryResponse",
    "CapabilityReport",
    "ClientDevice",
    "CompatibilityDelta",
    "CompatibilityManifest",
    "Device",
    "DeviceMode",
    "DslStatus",
    "EndpointObservation",
    "EndpointProbeResult",
    "FuzzyReadCandidate",
    "FuzzyReadObservation",
    "HttpMutationVerificationCandidate",
    "HttpNoopVerificationResult",
    "InternetStatus",
    "IotHost",
    "IpInfo",
    "IpStatus",
    "LanDetails",
    "LogType",
    "LoginResult",
    "MloHost",
    "ModelCompatibilityProfile",
    "MutationPlan",
    "NetworkTotals",
    "NodeClientList",
    "OperationCompatibility",
    "Performance",
    "SignalLevel",
    "SpeedTest",
    "TimeSettings",
    "TmpMutationPlan",
    "TmpMutationVerificationCandidate",
    "TmpNoopVerificationResult",
    "TmpOpcodeSpec",
    "WanDetails",
    "WanInfo",
    "WirelessPower",
    "WlanBackhaul",
    "WlanBand",
    "WlanConfig",
    "WlanGuest",
    "WlanHost",
]
