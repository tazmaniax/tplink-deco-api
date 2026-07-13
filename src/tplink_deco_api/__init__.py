"""Public API surface for the TP-Link Deco SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .capability_routing import (
    CAPABILITY_ROUTES,
    MUTATION_CAPABILITY_ROUTES,
    get_capability_route,
    get_mutation_capability_route,
)
from .client import DecoClient
from .endpoint_catalog import (
    CAPABILITY_ENDPOINTS,
    CATALOG_VERSION,
    DISCOVERABLE_READ_ENDPOINTS,
    ENDPOINT_CATALOG,
    MUTATION_ENDPOINTS,
    P9_MUTATION_CANDIDATES,
    P9_PROFILE_FIRMWARE,
    P9_PROFILE_HARDWARE_VERSIONS,
    P9_PROFILE_OBSERVED_AT,
    P9_READ_ENDPOINTS,
    READ_ONLY_ENDPOINTS,
    get_endpoint,
)
from .endpoint_spec import EndpointSpec
from .exceptions import (
    ApiError,
    AuthenticationError,
    ConfirmationError,
    ControllerChangedError,
    CryptoError,
    DecoError,
    ExpiredPlanError,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    MutationIneligibleError,
    TmpProtocolError,
    TransportError,
    UnknownPlanError,
)
from .fuzzy import build_fuzzy_read_candidates, restore_fuzzy_read_candidate
from .http_mutation_verification import build_http_mutation_verification_queue
from .http_noop_verification import (
    HTTP_NOOP_CONFIRMATIONS,
    HTTP_NOOP_PREFLIGHT_OPERATIONS,
    verify_http_setting_noop,
)
from .model_compatibility import (
    P9_COMPATIBILITY_PROFILE,
    P9_SENSITIVE_SCHEMA_ENDPOINTS,
    SENSITIVE_SCHEMA_ENDPOINTS,
    get_compatibility_profile,
)
from .models import (
    AddressReservation,
    AddressReservationTable,
    ApiResponse,
    BinaryResponse,
    CapabilityReport,
    CapabilityRoute,
    ClientDevice,
    CompatibilityDelta,
    CompatibilityManifest,
    Device,
    DeviceMode,
    DslStatus,
    EndpointObservation,
    EndpointProbeResult,
    FuzzyReadCandidate,
    FuzzyReadObservation,
    HttpMutationVerificationCandidate,
    HttpNoopVerificationResult,
    InternetStatus,
    IotHost,
    IpInfo,
    IpStatus,
    LanDetails,
    LoginResult,
    LogType,
    MloHost,
    ModelCompatibilityProfile,
    MutationCapabilityRoute,
    MutationPlan,
    NetworkTotals,
    NodeClientList,
    OperationCompatibility,
    Performance,
    SignalLevel,
    SpeedTest,
    SystemLogEntry,
    SystemLogPage,
    TimeSettings,
    TmpMutationPlan,
    TmpMutationVerificationCandidate,
    TmpNoopVerificationResult,
    TmpOpcodeSpec,
    WanDetails,
    WanInfo,
    WirelessPower,
    WlanBackhaul,
    WlanBand,
    WlanConfig,
    WlanGuest,
    WlanHost,
)
from .mutation_planner import build_mutation_plan
from .server import ServerConfig
from .service import DecoService
from .tmp_beamforming_noop_verification import TMP_BEAMFORMING_NOOP_CONFIRMATION
from .tmp_client import DecoTmpClient
from .tmp_monthly_report_noop_verification import TMP_MONTHLY_REPORT_NOOP_CONFIRMATION
from .tmp_mutation_planner import build_tmp_mutation_plan
from .tmp_mutation_verification import build_tmp_mutation_verification_queue
from .tmp_noop_verification import TMP_IEEE80211R_NOOP_CONFIRMATION
from .tmp_opcode_catalog import TMP_OPCODE_CATALOG, get_tmp_opcode
from .tmp_protocol import TmpAppV2Session
from .tmp_read_contract_probe import probe_tmp_read_contracts
from .tmp_ssh_config import TmpSshConfig
from .tmp_stream import TmpStream
from .tmp_unverified_read_probe import probe_tmp_unverified_reads

if TYPE_CHECKING:
    from .tmp_ssh_stream import TmpSshStream

__all__ = [
    "CAPABILITY_ENDPOINTS",
    "CAPABILITY_ROUTES",
    "CATALOG_VERSION",
    "DISCOVERABLE_READ_ENDPOINTS",
    "ENDPOINT_CATALOG",
    "HTTP_NOOP_CONFIRMATIONS",
    "HTTP_NOOP_PREFLIGHT_OPERATIONS",
    "MUTATION_CAPABILITY_ROUTES",
    "MUTATION_ENDPOINTS",
    "P9_COMPATIBILITY_PROFILE",
    "P9_MUTATION_CANDIDATES",
    "P9_PROFILE_FIRMWARE",
    "P9_PROFILE_HARDWARE_VERSIONS",
    "P9_PROFILE_OBSERVED_AT",
    "P9_READ_ENDPOINTS",
    "P9_SENSITIVE_SCHEMA_ENDPOINTS",
    "READ_ONLY_ENDPOINTS",
    "SENSITIVE_SCHEMA_ENDPOINTS",
    "TMP_BEAMFORMING_NOOP_CONFIRMATION",
    "TMP_IEEE80211R_NOOP_CONFIRMATION",
    "TMP_MONTHLY_REPORT_NOOP_CONFIRMATION",
    "TMP_OPCODE_CATALOG",
    "AddressReservation",
    "AddressReservationTable",
    "ApiError",
    "ApiResponse",
    "AuthenticationError",
    "BinaryResponse",
    "CapabilityReport",
    "CapabilityRoute",
    "ClientDevice",
    "CompatibilityDelta",
    "CompatibilityManifest",
    "ConfirmationError",
    "ControllerChangedError",
    "CryptoError",
    "DecoClient",
    "DecoError",
    "DecoService",
    "DecoTmpClient",
    "Device",
    "DeviceMode",
    "DslStatus",
    "EndpointObservation",
    "EndpointProbeResult",
    "EndpointSpec",
    "ExpiredPlanError",
    "FuzzyReadCandidate",
    "FuzzyReadObservation",
    "HttpMutationVerificationCandidate",
    "HttpNoopVerificationResult",
    "IdempotencyConflictError",
    "IdempotencyInProgressError",
    "InternetStatus",
    "IotHost",
    "IpInfo",
    "IpStatus",
    "LanDetails",
    "LogType",
    "LoginResult",
    "MloHost",
    "ModelCompatibilityProfile",
    "MutationCapabilityRoute",
    "MutationIneligibleError",
    "MutationPlan",
    "NetworkTotals",
    "NodeClientList",
    "OperationCompatibility",
    "Performance",
    "ServerConfig",
    "SignalLevel",
    "SpeedTest",
    "SystemLogEntry",
    "SystemLogPage",
    "TimeSettings",
    "TmpAppV2Session",
    "TmpMutationPlan",
    "TmpMutationVerificationCandidate",
    "TmpNoopVerificationResult",
    "TmpOpcodeSpec",
    "TmpProtocolError",
    "TmpSshConfig",
    "TmpSshStream",
    "TmpStream",
    "TransportError",
    "UnknownPlanError",
    "WanDetails",
    "WanInfo",
    "WirelessPower",
    "WlanBackhaul",
    "WlanBand",
    "WlanConfig",
    "WlanGuest",
    "WlanHost",
    "build_fuzzy_read_candidates",
    "build_http_mutation_verification_queue",
    "build_mutation_plan",
    "build_tmp_mutation_plan",
    "build_tmp_mutation_verification_queue",
    "get_capability_route",
    "get_compatibility_profile",
    "get_endpoint",
    "get_mutation_capability_route",
    "get_tmp_opcode",
    "probe_tmp_read_contracts",
    "probe_tmp_unverified_reads",
    "restore_fuzzy_read_candidate",
    "verify_http_setting_noop",
]


def __getattr__(name: str) -> object:
    """Load optional TMP SSH support only when the public class is requested."""
    if name == "TmpSshStream":
        from .tmp_ssh_stream import TmpSshStream

        return TmpSshStream
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
