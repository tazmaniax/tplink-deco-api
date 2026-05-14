"""Deco mesh node (router unit)."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_bool, get_int, get_object, get_str
from ._utils import decode_b64, normalize_mac
from .signal_level import SignalLevel


@dataclass(frozen=True)
class Device:
    """One Deco mesh node (gateway, satellite, …)."""

    mac: str
    device_ip: str
    device_model: str
    device_type: str
    role: str
    nickname: str
    custom_nickname: str
    hardware_ver: str
    software_ver: str
    oem_id: str
    hw_id: str
    bssid_2g: str
    bssid_5g: str
    bssid_sta_2g: str
    bssid_sta_5g: str
    inet_status: str
    inet_error_msg: str
    group_status: str
    signal_level: SignalLevel
    product_level: int
    set_gateway_support: bool
    support_plc: bool
    oversized_firmware: bool
    nand_flash: bool

    @classmethod
    def from_api(cls, data: JsonObject) -> Device:
        """Build ``Device`` from a router payload."""
        return cls(
            mac=normalize_mac(get_str(data, "mac")),
            device_ip=get_str(data, "device_ip"),
            device_model=get_str(data, "device_model"),
            device_type=get_str(data, "device_type"),
            role=get_str(data, "role"),
            nickname=get_str(data, "nickname"),
            custom_nickname=decode_b64(get_str(data, "custom_nickname")),
            hardware_ver=get_str(data, "hardware_ver"),
            software_ver=get_str(data, "software_ver"),
            oem_id=get_str(data, "oem_id"),
            hw_id=get_str(data, "hw_id"),
            bssid_2g=normalize_mac(get_str(data, "bssid_2g")),
            bssid_5g=normalize_mac(get_str(data, "bssid_5g")),
            bssid_sta_2g=normalize_mac(get_str(data, "bssid_sta_2g")),
            bssid_sta_5g=normalize_mac(get_str(data, "bssid_sta_5g")),
            inet_status=get_str(data, "inet_status"),
            inet_error_msg=get_str(data, "inet_error_msg"),
            group_status=get_str(data, "group_status"),
            signal_level=SignalLevel.from_api(get_object(data, "signal_level")),
            product_level=get_int(data, "product_level"),
            set_gateway_support=get_bool(data, "set_gateway_support"),
            support_plc=get_bool(data, "support_plc"),
            oversized_firmware=get_bool(data, "oversized_firmware"),
            nand_flash=get_bool(data, "nand_flash"),
        )
