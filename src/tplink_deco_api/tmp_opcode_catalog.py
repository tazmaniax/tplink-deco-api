"""Reverse-engineered Deco TMP/AppV2 opcode discovery catalogue."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from importlib import resources
from typing import TYPE_CHECKING, cast

from ._json import JsonObject, get_bool, get_int, get_str, get_str_tuple, loads
from .models import TmpOpcodeSpec

if TYPE_CHECKING:
    from .endpoint_spec import SafetyLevel, SensitivityLevel
    from .models.tmp_opcode_spec import (
        TmpAppContractProvenance,
        TmpAppContractStatus,
        TmpP9MutationObservation,
        TmpP9MutationSafetyStatus,
        TmpP9Observation,
    )

_LEGACY_OPCODE_ROWS: tuple[tuple[int, str], ...] = (
    (0x0000, "TMP_APPV2_OP_UNKNOWN"),
    (0x0001, "TMP_APPV2_OP_TOKEN_ALLOC"),
    (0x0002, "TMP_APPV2_OP_TOKEN_VERIFY"),
    (0x0003, "TMP_APPV2_OP_TOKEN_FREE"),
    (0x4001, "TMP_APPV2_OP_COMP_NEGOTIATE"),
    (0x4002, "TMP_APPV2_OP_COMP_NEGOTIATE_BT"),
    (0x4003, "TMP_APPV2_OP_NICKNAME_SET"),
    (0x4004, "TMP_APPV2_OP_IPV4_GET"),
    (0x4005, "TMP_APPV2_OP_IPV4_SET"),
    (0x4006, "TMP_APPV2_OP_IPV6_GET"),
    (0x4007, "TMP_APPV2_OP_IPV6_SET"),
    (0x4008, "TMP_APPV2_OP_WIRELESS_SET"),
    (0x4009, "TMP_APPV2_OP_WIRELESS_GET"),
    (0x400A, "TMP_APPV2_OP_LOCATION_GET"),
    (0x400B, "TMP_APPV2_OP_QS_M5_SLAVE_TRY"),
    (0x400C, "TMP_APPV2_OP_INTERNET_GET"),
    (0x400D, "TMP_APPV2_OP_BRIDGE_STATUS_GET"),
    (0x400E, "TMP_APPV2_OP_TIME_SYNC"),
    (0x400F, "TMP_APPV2_OP_DEVICE_LIST_GET"),
    (0x4010, "TMP_APPV2_OP_SPEEDTEST_INFO_GET"),
    (0x4011, "TMP_APPV2_OP_SPEEDTEST_START"),
    (0x4012, "TMP_APPV2_OP_CLIENT_LIST_GET"),
    (0x4013, "TMP_APPV2_OP_CLIENT_LIST_SET"),
    (0x4014, "TMP_APPV2_OP_CLIENT_LIST_SPEED_GET"),
    (0x4015, "TMP_APPV2_OP_CLIENT_SPEED_GET"),
    (0x4016, "TMP_APPV2_OP_DEVICE_LIST_REBOOT"),
    (0x4017, "TMP_APPV2_OP_CLIENT_LIST_BLOCK"),
    (0x4018, "TMP_APPV2_OP_BLOCKED_LIST_GET"),
    (0x4019, "TMP_APPV2_OP_BLOCKED_LIST_UNBLOCK"),
    (0x401A, "TMP_APPV2_OP_AUTO_LED_GET"),
    (0x401B, "TMP_APPV2_OP_AUTO_LED_SET"),
    (0x401C, "TMP_APPV2_OP_FW_LATEST_GET"),
    (0x401D, "TMP_APPV2_OP_FW_UPDATE"),
    (0x401E, "TMP_APPV2_OP_FW_PROG_GET"),
    (0x401F, "TMP_APPV2_OP_QS_M5_MASTER_TRY"),
    (0x4020, "TMP_APPV2_OP_QS_M5_MASTER_SET"),
    (0x4021, "TMP_APPV2_OP_QS_M5_SLAVE_SET"),
    (0x4022, "TMP_APPV2_OP_DEVICE_LIST_REMOVE"),
    (0x4023, "TMP_APPV2_OP_NETWORK_UNBIND"),
    (0x4024, "TMP_APPV2_OP_SPEEDTEST_HISTORY_GET"),
    (0x4025, "TMP_APPV2_OP_SPEEDTEST_HISTORY_CLEAR"),
    (0x4026, "TMP_APPV2_OP_SPEEDTEST_LATEST_GET"),
    (0x4027, "TMP_APPV2_OP_SPEEDTEST_STOP"),
    (0x4028, "TMP_APPV2_OP_MESSAGE_LIST_GET"),
    (0x4029, "TMP_APPV2_OP_OWNER_LIST_GET"),
    (0x402A, "TMP_APPV2_OP_OWNER_LIST_ADD"),
    (0x402B, "TMP_APPV2_OP_OWNER_LIST_REMOVE"),
    (0x402C, "TMP_APPV2_OP_OWNER_MODIFY"),
    (0x402D, "TMP_APPV2_OP_OWNER_GET"),
    (0x402E, "TMP_APPV2_OP_PARENT_CTRL_INTERNET_BLOCK"),
    (0x402F, "TMP_APPV2_OP_PARENT_CTRL_INSIGHTS_GET"),
    (0x4030, "TMP_APPV2_OP_PARENT_CTRL_WEBSITE_BLOCK"),
    (0x4031, "TMP_APPV2_OP_PARENT_CTRL_HISTORY_GET"),
    (0x4032, "TMP_APPV2_OP_FILTER_CATEGORIES_GET"),
    (0x4033, "TMP_APPV2_OP_PARENT_CTRL_CLIENT_ADD"),
    (0x4034, "TMP_APPV2_OP_PARENT_CTRL_CLIENT_REMOVE"),
    (0x4035, "TMP_APPV2_OP_DEFAULT_FILTER_LEVEL_GET"),
    (0x4036, "TMP_APPV2_OP_QOS_MODE_GET"),
    (0x4037, "TMP_APPV2_OP_QOS_MODE_SET"),
    (0x4038, "TMP_APPV2_OP_ACCOUNT_MODIFY"),
    (0x4039, "TMP_APPV2_OP_PROFILE_GET"),
    (0x403A, "TMP_APPV2_OP_DEFAULT_WEBSITE_APP_GET"),
    (0x403B, "TMP_APPV2_OP_SECURITY_INFO_GET"),
    (0x403C, "TMP_APPV2_OP_SECURITY_INFO_SET"),
    (0x403D, "TMP_APPV2_OP_SECURITY_HISTORY_GET"),
    (0x403E, "TMP_APPV2_OP_SECURITY_HISTORY_CLEAR"),
    (0x403F, "TMP_APPV2_OP_SECURITY_HISTORY_REMOVE"),
    (0x4040, "TMP_APPV2_OP_IOT_CLIENT_LIST_GET"),
    (0x4041, "TMP_APPV2_OP_IOT_CLIENT_LIST_REMOVE"),
    (0x4042, "TMP_APPV2_OP_IOT_CLIENT_LIST_ADD"),
    (0x4043, "TMP_APPV2_OP_IOT_CLIENT_LIST_MODIFY"),
    (0x4044, "TMP_APPV2_OP_IOT_CLIENT_LIST_SCAN"),
    (0x4045, "TMP_APPV2_OP_IOT_PRODUCT_PROFILE_GET"),
    (0x4047, "TMP_APPV2_OP_IOT_NEST_ACCOUNT_DELETE"),
    (0x4048, "TMP_APPV2_OP_IOT_CLIENT_LIST_BEGIN_SCANNING"),
    (0x4049, "TMP_APPV2_OP_IOT_CLIENT_GET"),
    (0x404A, "TMP_APPV2_OP_IOT_CLIENT_IDENTIFY"),
    (0x404B, "TMP_APPV2_OP_IOT_CLIENT_LIST_GET_BY_MODULE"),
    (0x404C, "TMP_APPV2_OP_IOT_CLIENT_LIST_END_SCANNING"),
    (0x4050, "TMP_APPV2_OP_IOT_SPACE_LIST_GET"),
    (0x4051, "TMP_APPV2_OP_IOT_SPACE_LIST_ADD"),
    (0x4052, "TMP_APPV2_OP_IOT_SPACE_LIST_MODIFY"),
    (0x4053, "TMP_APPV2_OP_IOT_SPACE_LIST_REMOVE"),
    (0x4054, "TMP_APPV2_OP_IOT_SPACE_SET"),
    (0x4060, "TMP_APPV2_OP_IOT_OWNER_LIST_GET"),
    (0x4070, "TMP_APPV2_OP_ONE_CLICK_LIST_GET"),
    (0x4071, "TMP_APPV2_OP_ONE_CLICK_SET"),
    (0x4073, "TMP_APPV2_OP_ONE_CLICK_SCENE_ADD"),
    (0x4074, "TMP_APPV2_OP_ONE_CLICK_SCENE_MODIFY"),
    (0x4075, "TMP_APPV2_OP_ONE_CLICK_SCENE_LIST_REMOVE"),
    (0x4076, "TMP_APPV2_OP_ONE_CLICK_ACTION_ADD"),
    (0x4077, "TMP_APPV2_OP_ONE_CLICK_ACTION_MODIFY"),
    (0x4078, "TMP_APPV2_OP_ONE_CLICK_ACTION_LIST_REMOVE"),
    (0x4079, "TMP_APPV2_OP_ONE_CLICK_HISTORY_GET"),
    (0x407A, "TMP_APPV2_OP_ONE_CLICK_HISTORY_REMOVE"),
    (0x4080, "TMP_APPV2_OP_AUTOMATION_TASK_LIST_GET"),
    (0x4082, "TMP_APPV2_OP_AUTOMATION_TASK_ADD"),
    (0x4083, "TMP_APPV2_OP_AUTOMATION_TASK_MODIFY"),
    (0x4084, "TMP_APPV2_OP_AUTOMATION_TASK_LIST_REMOVE"),
    (0x4086, "TMP_APPV2_OP_AUTOMATION_TRIGGER_ADD"),
    (0x4087, "TMP_APPV2_OP_AUTOMATION_TRIGGER_MODIFY"),
    (0x4088, "TMP_APPV2_OP_AUTOMATION_TRIGGER_LIST_REMOVE"),
    (0x4089, "TMP_APPV2_OP_AUTOMATION_ACTION_ADD"),
    (0x408A, "TMP_APPV2_OP_AUTOMATION_ACTION_MODIFY"),
    (0x408B, "TMP_APPV2_OP_AUTOMATION_ACTION_LIST_REMOVE"),
    (0x408C, "TMP_APPV2_OP_AUTOMATION_HISTORY_GET"),
    (0x408D, "TMP_APPV2_OP_AUTOMATION_HISTORY_REMOVE"),
    (0x408E, "TMP_APPV2_OP_AUTOMATION_TASK_LIST_MODIFY"),
    (0x4090, "TMP_APPV2_OP_CLIENT_LIST_REMOVE"),
    (0x40A0, "TMP_APPV2_OP_OPERATION_MODE_GET"),
    (0x40A1, "TMP_APPV2_OP_OPERATION_MODE_SET"),
    (0x40B0, "TMP_APPV2_OP_PORT_FORWARDING_LIST_GET"),
    (0x40B1, "TMP_APPV2_OP_PORT_FORWARDING_ADD"),
    (0x40B2, "TMP_APPV2_OP_PORT_FORWARDING_MODIFY"),
    (0x40B3, "TMP_APPV2_OP_PORT_FORWARDING_DELETE"),
    (0x40C0, "TMP_APPV2_OP_IP_RESERVATION_LIST_GET"),
    (0x40C1, "TMP_APPV2_OP_IP_RESERVATION_LIST_ADD"),
    (0x40C2, "TMP_APPV2_OP_IP_RESERVATION_MODIFY"),
    (0x40C3, "TMP_APPV2_OP_IP_RESERVATION_LIST_REMOVE"),
    (0x40D0, "TMP_APPV2_OP_DDNS_GET"),
    (0x40D1, "TMP_APPV2_OP_DDNS_SET"),
    (0x40E0, "TMP_APPV2_OP_MONTHLY_REPORT_GET"),
    (0x4100, "TMP_APPV2_OP_ZIGBEE_COORDINATOR_ELECT"),
    (0x4201, "TMP_APPV2_OP_SECURITY_CATEGORY_LIST_GET"),
    (0x4202, "TMP_APPV2_OP_SECURITY_RULE_LIST_GET"),
    (0x4204, "TMP_APPV2_OP_ENV_VAR_SYNC"),
    (0x4205, "TMP_APPV2_OP_FW_DOWNLOAD"),
    (0x4206, "TMP_APPV2_OP_QS_HEART_BEAT"),
    (0x4207, "TMP_APPV2_OP_EPONYMOUS_NETWORK_DETECTION"),
    (0x4208, "TMP_APPV2_OP_11R_GET"),
    (0x4209, "TMP_APPV2_OP_11R_SET"),
    (0x420A, "TMP_APPV2_OP_QS_DISCOVERED_DEVICELIST_GET"),
    (0x420B, "TMP_APPV2_OP_QS_BATCHES_DEVICE_ALIAS_SET"),
    (0x420C, "TMP_APPV2_OP_WAN_SET"),
    (0x420D, "TMP_APPV2_OP_VLAN_GET"),
    (0x420E, "TMP_APPV2_OP_VLAN_SET"),
    (0x420F, "TMP_APPV2_OP_DEVICE_GATEWAY_SET"),
    (0x4211, "TMP_APPV2_OP_LAN_IP_GET"),
    (0x4212, "TMP_APPV2_OP_LAN_IP_SET"),
    (0x4213, "TMP_APPV2_OP_DHCP_GET"),
    (0x4214, "TMP_APPV2_OP_DHCP_SET"),
    (0x4215, "TMP_APPV2_OP_WPS_GET"),
    (0x4216, "TMP_APPV2_OP_WPS_SET"),
    (0x4217, "TMP_APPV2_OP_DEVICE_NETWORK_REMOVE"),
    (0x4218, "TMP_APPV2_OP_DEVICE_ACCOUNT_MODIFY"),
    (0x4219, "TMP_APPV2_OP_BANDWIDTH_GET"),
    (0x421A, "TMP_APPV2_OP_BANDWIDTH_SET"),
    (0x421B, "TMP_APPV2_OP_BEAMFORMING_GET"),
    (0x421C, "TMP_APPV2_OP_BEAMFORMING_SET"),
    (0x421D, "TMP_APPV2_OP_SIP_ALG_GET"),
    (0x421E, "TMP_APPV2_OP_SIP_ALG_SET"),
    (0x4220, "TMP_APPV2_OP_PARENT_CTRL_INSIGHTS_REMOVE"),
    (0x4221, "TMP_APPV2_OP_MONTHLY_REPORT_REMOVE"),
    (0x4222, "TMP_APPV2_OP_MONTHLY_REPORT_MGR_GET"),
    (0x4223, "TMP_APPV2_OP_MONTHLY_REPORT_MGR_SET"),
    (0x4224, "TMP_APPV2_OP_IPTV_GET"),
    (0x4225, "TMP_APPV2_OP_IPTV_SET"),
    (0x4226, "TMP_APPV2_OP_MAC_CLONE_GET"),
    (0x4227, "TMP_APPV2_OP_MAC_CLONE_SET"),
    (0x4228, "TMP_APPV2_OP_SPEEDTEST_SERVER_LIST_GET"),
    (0x4229, "TMP_APPV2_OP_MANAGER_PERMISSION_GET"),
    (0x422A, "TMP_APPV2_OP_MANAGER_PERMISSION_SET"),
    (0x422B, "TMP_APPV2_OP_SCAN_SSID_LIST_GET"),
    (0x422C, "TMP_APPV2_OP_HOST_NETWORK_SET"),
    (0x422D, "TMP_APPV2_OP_HOST_NETWORK_GET"),
    (0x422E, "TMP_APPV2_OP_FEEDBACK_LOG_BUILD"),
    (0x422F, "TMP_APPV2_OP_DEVICE_LIST_SPEED_GET"),
    (0x4230, "TMP_APPV2_OP_IPV6_FIREWALL_LIST_GET"),
    (0x4231, "TMP_APPV2_OP_IPV6_FIREWALL_LIST_ADD"),
    (0x4232, "TMP_APPV2_OP_IPV6_FIREWALL_LIST_REMOVE"),
    (0x4233, "TMP_APPV2_OP_IPV6_FIREWALL_LIST_MODIFY"),
    (0x4234, "TMP_APPV2_OP_IPV6_CLIENT_LIST_GET"),
    (0x4235, "TMP_APPV2_OP_FW_SYNC_GET"),
    (0x4236, "TMP_APPV2_OP_PARENT_CTRL_WEBSITE_UNBLOCK"),
    (0x4237, "TMP_APPV2_OP_SECURITY_DATABASE_UPDATE"),
    (0x4238, "TMP_APPV2_OP_IOT_CLIENT_LIST_MESH_SET"),
    (0x4239, "TMP_APPV2_OP_GA_INFO_LIST_GET"),
    (0x423A, "TMP_APPV2_OP_SECURITY_WHITELIST_GET"),
    (0x423B, "TMP_APPV2_OP_SECURITY_WHITELIST_ADD"),
    (0x423C, "TMP_APPV2_OP_SECURITY_WHITELIST_REMOVE"),
    (0x423D, "TMP_APPV2_OP_CLIENT_LEASE_GET"),
    (0x424A, "TMP_APPV2_OP_UPNP_GET"),
    (0x424B, "TMP_APPV2_OP_UPNP_SET"),
    (0x424C, "TMP_APPV2_OP_PLC_PAIR_GET"),
    (0x424D, "TMP_APPV2_OP_PLC_PAIR_SET"),
    (0x424E, "TMP_APPV2_HOMECARE_SERVICE_INFO_GET"),
    (0x424F, "TMP_APPV2_OP_NETWORK_OPTIMIZATION_SCAN"),
    (0x4250, "TMP_APPV2_OP_NETWORK_OPTIMIZATION_OPTIMIZE"),
    (0x4251, "TMP_APPV2_OP_WIRELESS_BANDWIDTH_ENHANCE_GET"),
    (0x4252, "TMP_APPV2_OP_WIRELESS_BANDWIDTH_ENHANCE_SET"),
    (0x4253, "TMP_APPV2_OP_DEVICE_LIST_TRANSFER_OWNERSHIP"),
    (0x4301, "TMP_APPV2_OP_FWLIST_LATEST_GET"),
)


def _load_opcode_registry() -> tuple[dict[int, JsonObject], str]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("tmp_opcode_registry.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 1:
        raise ValueError("Failed to load TMP opcode registry: unsupported schema version")
    records = data.get("operations")
    source = data.get("source")
    if not isinstance(records, (list, tuple)) or not isinstance(source, Mapping):
        raise ValueError("Failed to load TMP opcode registry: registry data is missing")
    operations: dict[int, JsonObject] = {}
    for item in records:
        if not isinstance(item, Mapping):
            continue
        code = get_int(item, "code", -1)
        name = get_str(item, "name")
        occurrences = get_int(item, "mapping_occurrences", 0)
        if code < 0 or not name.startswith("TMP_") or occurrences < 1:
            raise ValueError("Failed to load TMP opcode registry: invalid operation")
        operations[code] = cast("JsonObject", item)
    if len(operations) != get_int(data, "operation_count"):
        raise ValueError("Failed to load TMP opcode registry: operation count mismatch")
    if any(
        operations.get(code) is None
        or get_str(operations[code], "name")
        != ("TMP_APPV2_OP_SYSTEM_TIME" if code == 0x400E else name)
        for code, name in _LEGACY_OPCODE_ROWS
    ):
        raise ValueError("Failed to load TMP opcode registry: legacy coverage is incomplete")
    application = get_str(source, "application")
    if not application:
        raise ValueError("Failed to load TMP opcode registry: source is missing")
    return operations, application


_OPCODE_METADATA, _OPCODE_REGISTRY_SOURCE = _load_opcode_registry()
_OPCODE_ROWS: tuple[tuple[int, str], ...] = tuple(
    (code, get_str(operation, "name")) for code, operation in sorted(_OPCODE_METADATA.items())
)

_DESTRUCTIVE_MARKERS: tuple[str, ...] = (
    "_REBOOT",
    "_REMOVE",
    "_DELETE",
    "_CLEAR",
    "_EJECT",
    "_UNBIND",
    "_FW_UPDATE",
    "_FW_DOWNLOAD",
    "_TRANSFER_OWNERSHIP",
)

_SECRET_MARKERS: tuple[str, ...] = (
    "ACCOUNT",
    "CLIENT",
    "DDNS",
    "DHCP",
    "FEEDBACK_LOG",
    "HOST_NETWORK",
    "CONFIG_BACKUP",
    "ISP_PROFILE",
    "IPV4",
    "IPV6",
    "LAN_IP",
    "MANAGER_PERMISSION",
    "MESSAGE",
    "OWNER",
    "PARENT_CTRL",
    "RESERVATION",
    "SECURITY",
    "CALL_LOG",
    "PHONE_NUMBER",
    "PIN",
    "SIM_",
    "SMS",
    "TELEPHONE",
    "VOICE_MAIL",
    "VPN",
    "WIRELESS",
)

_CATEGORY_MARKERS: tuple[tuple[str, str], ...] = (
    ("PLC_", "plc"),
    ("MATTER", "iot"),
    ("IOT", "iot"),
    ("CLIENT", "clients"),
    ("DEVICE", "devices"),
    ("CAMERA_SECURITY", "security"),
    ("ANTIVIRUS", "security"),
    ("AVIRA", "security"),
    ("AD_FILTERING", "security"),
    ("HOMECARE", "security"),
    ("DPI_", "security"),
    ("WIRELESS", "wireless"),
    ("11R", "wireless"),
    ("BEAMFORMING", "wireless"),
    ("WAN", "network"),
    ("LAN_", "network"),
    ("IPV4", "network"),
    ("IPV6", "network"),
    ("VLAN", "network"),
    ("DHCP", "network"),
    ("IP_RESERVATION", "network"),
    ("IP_MAC_BINDING", "network"),
    ("WOL_", "network"),
    ("ISP_PROFILE", "network"),
    ("ROUTE_STATIC", "routing"),
    ("STATIC_ROUTE", "routing"),
    ("PORT_FORWARDING", "nat"),
    ("UPNP", "nat"),
    ("SIP_ALG", "nat"),
    ("SPEEDTEST", "diagnostics"),
    ("NETWORK_OPTIMIZATION", "diagnostics"),
    ("TRAFFIC_USAGE", "statistics"),
    ("FW", "firmware"),
    ("SECURITY", "security"),
    ("PARENT_CTRL", "parental_control"),
    ("QOS", "qos"),
    ("VPN", "vpn"),
    ("SMS", "telephony"),
    ("VOICE_MAIL", "telephony"),
    ("TELEPHONE", "telephony"),
    ("CALL_", "telephony"),
    ("DECT", "telephony"),
    ("VOIP", "telephony"),
    ("USB", "storage"),
    ("CONFIG_BACKUP", "backup"),
    ("REBOOT_SCHEDULE", "system"),
    ("AUTOMATION", "automation"),
    ("ONE_CLICK", "automation"),
    ("OWNER", "account"),
    ("ACCOUNT", "account"),
    ("DDNS", "cloud"),
    ("REPORT", "cloud"),
    ("TOKEN", "protocol"),
    ("COMP_NEGOTIATE", "protocol"),
)

_P9_PLC_VARIANTS: tuple[str, ...] = (
    "json_null",
    "json_empty_object",
    "json_default_device",
    "json_first_device_id",
    "raw_empty",
)

_SET_DISPATCHED_GET_REVIEWS: dict[int, str] = {
    0x4097: (
        "signed app repeatedly invokes quick-setup configuration synchronization through "
        "the set dispatcher with a mutable check_link request"
    ),
    0x40A5: (
        "signed app invokes TSS network-configuration synchronization through the set dispatcher"
    ),
    0x4369: (
        "signed app triggers OpenVPN certificate export through the set dispatcher and "
        "expects only Boolean completion"
    ),
}
_SECRET_OPCODE_CODES: frozenset[int] = frozenset(_SET_DISPATCHED_GET_REVIEWS)
_CATEGORY_OVERRIDES: dict[int, str] = {
    0x4097: "network",
    0x40A5: "network",
}


def _safety(code: int, name: str) -> SafetyLevel:
    if code in _SET_DISPATCHED_GET_REVIEWS:
        return "mutation"
    if name.endswith("_GET") or "_GET_BY_" in name:
        return "read_only"
    if name in {
        "TMP_APPV2_OP_UNKNOWN",
        "TMP_APPV2_OP_TOKEN_ALLOC",
        "TMP_APPV2_OP_TOKEN_VERIFY",
        "TMP_APPV2_OP_TOKEN_FREE",
        "TMP_APPV2_OP_COMP_NEGOTIATE",
        "TMP_APPV2_OP_COMP_NEGOTIATE_BT",
    }:
        return "internal"
    if any(marker in name for marker in _DESTRUCTIVE_MARKERS):
        return "destructive"
    return "mutation"


def _safety_evidence(code: int, name: str) -> str:
    if code in _SET_DISPATCHED_GET_REVIEWS:
        return "signed_app_set_dispatch_and_workflow_side_effect"
    if name.endswith("_GET") or "_GET_BY_" in name:
        return "opcode_name_read_semantics"
    if name in {
        "TMP_APPV2_OP_UNKNOWN",
        "TMP_APPV2_OP_TOKEN_ALLOC",
        "TMP_APPV2_OP_TOKEN_VERIFY",
        "TMP_APPV2_OP_TOKEN_FREE",
        "TMP_APPV2_OP_COMP_NEGOTIATE",
        "TMP_APPV2_OP_COMP_NEGOTIATE_BT",
    }:
        return "protocol_internal_opcode"
    if any(marker in name for marker in _DESTRUCTIVE_MARKERS):
        return "destructive_opcode_name_marker"
    return "opcode_name_mutation_semantics"


def _sensitivity(code: int, name: str) -> SensitivityLevel:
    return (
        "secret"
        if code in _SECRET_OPCODE_CODES or any(marker in name for marker in _SECRET_MARKERS)
        else "private"
    )


def _category(code: int, name: str) -> str:
    override = _CATEGORY_OVERRIDES.get(code)
    if override is not None:
        return override
    for marker, category in _CATEGORY_MARKERS:
        if marker in name:
            return category
    return "system"


def _optional_int(data: JsonObject, key: str) -> int | None:
    value = data.get(key)
    return get_int(data, key) if isinstance(value, int) and not isinstance(value, bool) else None


def _tested_variants(data: JsonObject, code: int) -> tuple[str, ...]:
    if code == 0x424C:
        return _P9_PLC_VARIANTS
    names = [get_str(data, "variant"), *get_str_tuple(data, "tested_variants")]
    fuzzy = data.get("fuzzy_variants")
    if isinstance(fuzzy, (list, tuple)):
        names.extend(get_str(item, "variant") for item in fuzzy if isinstance(item, Mapping))
    return tuple(dict.fromkeys(name for name in names if name))


def _confirmed_parameter_sets(data: JsonObject) -> tuple[tuple[str, ...], ...]:
    value = data.get("confirmed_parameter_sets")
    if not isinstance(value, (list, tuple)):
        return ()
    parameter_sets: list[tuple[str, ...]] = []
    for item in value:
        if not isinstance(item, (list, tuple)):
            continue
        keys = tuple(key for key in item if isinstance(key, str) and key)
        if keys and keys not in parameter_sets:
            parameter_sets.append(keys)
    return tuple(parameter_sets)


def _load_p9_read_observations() -> dict[int, JsonObject]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("p9_tmp_compatibility.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 1:
        raise ValueError("Failed to load TMP compatibility: unsupported schema version")
    records = data.get("observations")
    if not isinstance(records, (list, tuple)):
        raise ValueError("Failed to load TMP compatibility: observations are missing")
    observations: dict[int, JsonObject] = {}
    for item in records:
        if not isinstance(item, Mapping):
            continue
        code = get_int(item, "code", -1)
        status = get_str(item, "status")
        if code < 0 or status not in {
            "returned_data",
            "returned_binary",
            "rejected",
            "payload_rejected",
        }:
            raise ValueError("Failed to load TMP compatibility: invalid observation")
        observations[code] = cast("JsonObject", item)
    registry_names = dict(_OPCODE_ROWS)
    if len(observations) != get_int(data, "read_only_opcode_count") or any(
        code not in registry_names or _safety(code, registry_names[code]) != "read_only"
        for code in observations
    ):
        raise ValueError("Failed to load TMP compatibility: tested read coverage is invalid")
    return observations


def _load_p9_mutation_observations() -> dict[int, JsonObject]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("p9_tmp_mutation_compatibility.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 2:
        raise ValueError("Failed to load TMP mutation compatibility: unsupported schema version")
    records = data.get("observations")
    if not isinstance(records, (list, tuple)):
        raise ValueError("Failed to load TMP mutation compatibility: observations are missing")
    observations: dict[int, JsonObject] = {}
    valid_statuses = {
        "verified_noop",
        "same_value_immediate_verification_passed",
        "write_rejected",
        "rollback_confirmed",
        "rollback_unconfirmed",
    }
    registry_names = dict(_OPCODE_ROWS)
    for item in records:
        if not isinstance(item, Mapping):
            continue
        code = get_int(item, "code", -1)
        status = get_str(item, "status")
        safety_status = get_str(item, "safety_status")
        if (
            code not in registry_names
            or _safety(code, registry_names[code]) != "mutation"
            or status not in valid_statuses
            or safety_status != "safety_not_established"
        ):
            raise ValueError("Failed to load TMP mutation compatibility: invalid observation")
        observations[code] = cast("JsonObject", item)
    if len(observations) != get_int(data, "tested_mutation_count"):
        raise ValueError("Failed to load TMP mutation compatibility: tested count mismatch")
    return observations


def _load_app_contracts() -> tuple[dict[int, JsonObject], tuple[str, ...]]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("tmp_app_contracts.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 2:
        raise ValueError("Failed to load TMP app contracts: unsupported schema version")
    records = data.get("contracts")
    sources = data.get("sources")
    if not isinstance(records, (list, tuple)) or not isinstance(sources, (list, tuple)):
        raise ValueError("Failed to load TMP app contracts: contracts are missing")
    analysis_sources = tuple(
        application
        for item in sources
        if isinstance(item, Mapping) and (application := get_str(item, "application"))
    )
    if len(analysis_sources) != len(sources):
        raise ValueError("Failed to load TMP app contracts: sources are invalid")
    contracts: dict[int, JsonObject] = {}
    valid_statuses = {
        "no_app_call_site",
        "static_keys_recovered",
        "static_model_recovered",
        "static_null_payload",
    }
    for item in records:
        if not isinstance(item, Mapping):
            continue
        code = get_int(item, "code", -1)
        status = get_str(item, "static_contract_status")
        digest = get_str(item, "contract_sha256")
        if code < 0 or status not in valid_statuses or len(digest) != 64:
            raise ValueError("Failed to load TMP app contracts: invalid contract")
        contracts[code] = cast("JsonObject", item)
    expected_codes = {code for code, _name in _OPCODE_ROWS}
    if set(contracts) != expected_codes:
        raise ValueError("Failed to load TMP app contracts: opcode coverage is incomplete")
    return contracts, analysis_sources


def _load_indirect_app_contracts() -> dict[int, JsonObject]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("tmp_indirect_app_contracts.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 1:
        raise ValueError("Failed to load indirect TMP app contracts: unsupported schema version")
    records = data.get("contracts")
    if not isinstance(records, (list, tuple)):
        raise ValueError("Failed to load indirect TMP app contracts: contracts are missing")
    contracts: dict[int, JsonObject] = {}
    valid_statuses = {
        "static_keys_recovered",
        "static_model_recovered",
        "static_null_payload",
    }
    for item in records:
        if not isinstance(item, Mapping):
            continue
        code = get_int(item, "code", -1)
        status = get_str(item, "static_contract_status")
        if code < 0 or status not in valid_statuses or code in contracts:
            raise ValueError("Failed to load indirect TMP app contracts: invalid contract")
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
        contracts[code] = {
            **item,
            "contract_sha256": hashlib.sha256(canonical).hexdigest(),
        }
    return contracts


def _merge_indirect_app_contracts(
    contracts: dict[int, JsonObject],
    indirect_contracts: dict[int, JsonObject],
) -> dict[int, JsonObject]:
    for code, contract in indirect_contracts.items():
        existing = contracts.get(code)
        if existing is None or get_str(existing, "static_contract_status") != "no_app_call_site":
            raise ValueError("Failed to merge indirect TMP app contracts: unexpected base contract")
        contracts[code] = contract
    return contracts


def _app_contract_provenance(code: int) -> TmpAppContractProvenance:
    if code in _INDIRECT_APP_CONTRACTS:
        return "indirect_virtual_dispatch"
    if get_str(_APP_CONTRACTS[code], "static_contract_status") == "no_app_call_site":
        return "none"
    return "direct"


_P9_READ_OBSERVATIONS: dict[int, JsonObject] = _load_p9_read_observations()
_P9_MUTATION_OBSERVATIONS: dict[int, JsonObject] = _load_p9_mutation_observations()
_APP_CONTRACTS, _APP_ANALYSIS_SOURCES = _load_app_contracts()
_INDIRECT_APP_CONTRACTS = _load_indirect_app_contracts()
_APP_CONTRACTS = _merge_indirect_app_contracts(_APP_CONTRACTS, _INDIRECT_APP_CONTRACTS)


TMP_OPCODE_CATALOG: tuple[TmpOpcodeSpec, ...] = tuple(
    TmpOpcodeSpec(
        code=code,
        name=name,
        aliases=get_str_tuple(_OPCODE_METADATA[code], "aliases"),
        safety=_safety(code, name),
        safety_evidence=_safety_evidence(code, name),
        sensitivity=_sensitivity(code, name),
        category=_category(code, name),
        opcode_registry_source=_OPCODE_REGISTRY_SOURCE,
        opcode_registry_mapping_occurrences=get_int(_OPCODE_METADATA[code], "mapping_occurrences"),
        app_analysis_sources=_APP_ANALYSIS_SOURCES,
        app_contract_sources=get_str_tuple(_APP_CONTRACTS[code], "contract_sources"),
        app_dispatch_methods=get_str_tuple(_APP_CONTRACTS[code], "dispatch_methods"),
        app_contract_provenance=_app_contract_provenance(code),
        app_contract_status=cast(
            "TmpAppContractStatus",
            get_str(_APP_CONTRACTS[code], "static_contract_status"),
        ),
        app_request_models=get_str_tuple(_APP_CONTRACTS[code], "request_models"),
        app_candidate_parameter_keys=get_str_tuple(
            _APP_CONTRACTS[code], "candidate_parameter_keys"
        ),
        app_call_site_count=(
            len(call_sites)
            if isinstance((call_sites := _APP_CONTRACTS[code].get("call_sites")), (list, tuple))
            else 0
        ),
        app_contract_sha256=get_str(_APP_CONTRACTS[code], "contract_sha256"),
        app_set_dispatch_review=_SET_DISPATCHED_GET_REVIEWS.get(code, ""),
        p9_observation=(
            "accepted"
            if code in {0x0001, 0x4001}
            else cast("TmpP9Observation", get_str(_P9_READ_OBSERVATIONS[code], "status"))
            if code in _P9_READ_OBSERVATIONS
            else "untested"
        ),
        p9_appv2_error_code=(
            _optional_int(_P9_READ_OBSERVATIONS[code], "appv2_error_code")
            if code in _P9_READ_OBSERVATIONS
            else None
        ),
        p9_firmware_error_code=(
            _optional_int(_P9_READ_OBSERVATIONS[code], "firmware_error_code")
            if code in _P9_READ_OBSERVATIONS
            else None
        ),
        p9_tested_variants=(
            _tested_variants(_P9_READ_OBSERVATIONS[code], code)
            if code in _P9_READ_OBSERVATIONS
            else ()
        ),
        p9_confirmed_parameter_sets=(
            _confirmed_parameter_sets(_P9_READ_OBSERVATIONS[code])
            if code in _P9_READ_OBSERVATIONS
            else ()
        ),
        p9_parameter_value_source=(
            get_str(_P9_READ_OBSERVATIONS[code], "parameter_value_source")
            if code in _P9_READ_OBSERVATIONS
            else ""
        ),
        p9_schema_paths=(
            get_str_tuple(_P9_READ_OBSERVATIONS[code], "schema_paths")
            if code in _P9_READ_OBSERVATIONS
            else ()
        ),
        p9_response_size=(
            _optional_int(_P9_READ_OBSERVATIONS[code], "response_size")
            if code in _P9_READ_OBSERVATIONS
            else None
        ),
        p9_response_sha256=(
            get_str(_P9_READ_OBSERVATIONS[code], "response_sha256")
            if code in _P9_READ_OBSERVATIONS
            else ""
        ),
        p9_fuzzy_status=(
            get_str(_P9_READ_OBSERVATIONS[code], "fuzzy_status")
            if code in _P9_READ_OBSERVATIONS
            else ""
        ),
        p9_mutation_observation=(
            cast(
                "TmpP9MutationObservation",
                get_str(_P9_MUTATION_OBSERVATIONS[code], "status"),
            )
            if code in _P9_MUTATION_OBSERVATIONS
            else "untested"
        ),
        p9_mutation_safety_status=(
            cast(
                "TmpP9MutationSafetyStatus",
                get_str(_P9_MUTATION_OBSERVATIONS[code], "safety_status"),
            )
            if code in _P9_MUTATION_OBSERVATIONS
            else "untested"
        ),
        p9_mutation_firmware_error_code=(
            _optional_int(_P9_MUTATION_OBSERVATIONS[code], "firmware_error_code")
            if code in _P9_MUTATION_OBSERVATIONS
            else None
        ),
        p9_mutation_parameter_keys=(
            get_str_tuple(_P9_MUTATION_OBSERVATIONS[code], "parameter_keys")
            if code in _P9_MUTATION_OBSERVATIONS
            else ()
        ),
        p9_mutation_state_unchanged=(
            get_bool(_P9_MUTATION_OBSERVATIONS[code], "state_unchanged")
            if code in _P9_MUTATION_OBSERVATIONS
            else None
        ),
        p9_mutation_rollback_attempted=(
            get_bool(_P9_MUTATION_OBSERVATIONS[code], "rollback_attempted")
            if code in _P9_MUTATION_OBSERVATIONS
            else False
        ),
        p9_mutation_rollback_verified=(
            get_bool(_P9_MUTATION_OBSERVATIONS[code], "rollback_verified")
            if code in _P9_MUTATION_OBSERVATIONS
            and isinstance(_P9_MUTATION_OBSERVATIONS[code].get("rollback_verified"), bool)
            else None
        ),
        p9_mutation_request_count=(
            get_int(_P9_MUTATION_OBSERVATIONS[code], "mutation_request_count")
            if code in _P9_MUTATION_OBSERVATIONS
            else 0
        ),
        p9_mutation_evidence_artifact=(
            get_str(_P9_MUTATION_OBSERVATIONS[code], "evidence_artifact")
            if code in _P9_MUTATION_OBSERVATIONS
            else ""
        ),
    )
    for code, name in _OPCODE_ROWS
)


def get_tmp_opcode(code: int) -> TmpOpcodeSpec:
    """Return one reverse-engineered TMP opcode by numeric identifier."""
    for opcode in TMP_OPCODE_CATALOG:
        if opcode.code == code:
            return opcode
    raise KeyError(f"Unknown Deco TMP/AppV2 opcode: 0x{code:04X}")
