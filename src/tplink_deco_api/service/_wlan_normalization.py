"""Normalize HTTP and TMP WLAN configuration into one semantic shape."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .._json import get_str
from ..models import WlanConfig

if TYPE_CHECKING:
    from .._json import JsonObject, JsonValue
    from ..models import WlanBand

_BAND_KEYS: tuple[str, ...] = (
    "band2_4",
    "band5_1",
    "band5_2",
    "band6",
    "band6_2",
)


def normalize_http_wlan_configuration(
    config: WlanConfig,
    *,
    include_passwords: bool,
) -> dict[str, JsonValue]:
    """Normalize an HTTP WLAN model without exposing unrequested passwords."""
    return _wlan_view(config, include_passwords=include_passwords)


def normalize_tmp_wlan_configuration(
    data: JsonObject,
    *,
    include_passwords: bool,
) -> dict[str, JsonValue]:
    """Normalize validated TMP radio aliases into the HTTP semantic contract."""
    transformed: dict[str, JsonValue] = {}
    observed_band_count = 0
    for firmware_name in _BAND_KEYS:
        value = data.get(firmware_name)
        if value is None:
            continue
        if not isinstance(value, Mapping):
            raise ValueError(
                f"Failed to normalize TMP WLAN configuration: {firmware_name} is not an object"
            )
        transformed[firmware_name] = _tmp_band_shape(value, firmware_name)
        observed_band_count += 1
    if observed_band_count == 0:
        raise ValueError("Failed to normalize TMP WLAN configuration: no radio bands were returned")
    for key in ("iot", "mlo", "is_eg"):
        if key in data:
            transformed[key] = data[key]
    return _wlan_view(
        WlanConfig.from_api(transformed),
        include_passwords=include_passwords,
    )


def _tmp_band_shape(data: JsonObject, band_name: str) -> dict[str, JsonValue]:
    host = _required_object(data, "host", band_name)
    guest = _required_object(data, "guest", band_name)
    backhaul = _required_object(data, "backhaul", band_name)
    radio = _required_object(data, "radio", band_name)
    _validate_tmp_band(host, guest, backhaul, radio, band_name)
    normalized_host: dict[str, JsonValue] = dict(host)
    normalized_host["channel"] = _tmp_channel(radio, band_name)
    normalized_host["mode"] = get_str(radio, "hwmode")
    normalized_host["channel_width"] = get_str(radio, "htmode")
    return {
        "host": normalized_host,
        "guest": dict(guest),
        "backhaul": dict(backhaul),
    }


def _required_object(data: JsonObject, key: str, band_name: str) -> JsonObject:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(
            f"Failed to normalize TMP WLAN configuration: {band_name}.{key} is not an object"
        )
    return value


def _validate_tmp_band(
    host: JsonObject,
    guest: JsonObject,
    backhaul: JsonObject,
    radio: JsonObject,
    band_name: str,
) -> None:
    _require_types(
        host,
        band_name,
        "host",
        strings=("ssid", "password", "encryption_mode"),
        booleans=("enable", "enable_hide_ssid"),
    )
    _require_types(
        guest,
        band_name,
        "guest",
        strings=("ssid", "password", "encryption_mode"),
        booleans=("enable", "need_set_vlan"),
        integers=("vlan_id",),
    )
    _require_types(backhaul, band_name, "backhaul", integers=("channel",))
    _require_types(
        radio,
        band_name,
        "radio",
        strings=("channel", "htmode", "hwmode"),
        booleans=("enable",),
    )


def _require_types(
    data: JsonObject,
    band_name: str,
    section: str,
    *,
    strings: tuple[str, ...] = (),
    booleans: tuple[str, ...] = (),
    integers: tuple[str, ...] = (),
) -> None:
    expected: tuple[tuple[tuple[str, ...], type[str] | type[bool] | type[int], str], ...] = (
        (strings, str, "a string"),
        (booleans, bool, "a boolean"),
        (integers, int, "an integer"),
    )
    for keys, value_type, description in expected:
        for key in keys:
            value = data.get(key)
            if not isinstance(value, value_type) or (value_type is int and isinstance(value, bool)):
                raise ValueError(
                    "Failed to normalize TMP WLAN configuration: "
                    f"{band_name}.{section}.{key} is not {description}"
                )


def _tmp_channel(radio: JsonObject, band_name: str) -> int:
    channel = get_str(radio, "channel")
    if channel.casefold() == "auto":
        return 0
    try:
        return int(channel)
    except ValueError as exc:
        raise ValueError(
            "Failed to normalize TMP WLAN configuration: "
            f"{band_name}.radio.channel is not numeric or auto"
        ) from exc


def _wlan_band_view(
    band: WlanBand,
    *,
    include_passwords: bool,
) -> dict[str, JsonValue]:
    host: dict[str, JsonValue] = {
        "ssid": band.host.ssid,
        "channel": band.host.channel,
        "enabled": band.host.enable,
        "mode": band.host.mode,
        "channel_width": band.host.channel_width,
        "hidden": band.host.enable_hide_ssid,
    }
    guest: dict[str, JsonValue] = {
        "ssid": band.guest.ssid,
        "enabled": band.guest.enable,
        "vlan_id": band.guest.vlan_id,
        "need_set_vlan": band.guest.need_set_vlan,
    }
    if include_passwords:
        host["password"] = band.host.password
        guest["password"] = band.guest.password
    return {
        "host": host,
        "guest": guest,
        "backhaul": {"channel": band.backhaul.channel},
    }


def _wlan_view(config: WlanConfig, *, include_passwords: bool) -> dict[str, JsonValue]:
    iot: dict[str, JsonValue] = {
        "ssid": config.iot_host.ssid,
        "enabled": config.iot_host.enable,
        "enable_2g": config.iot_host.enable_2g,
        "enable_5g": config.iot_host.enable_5g,
        "encryption_mode": config.iot_host.encryption_mode,
    }
    mlo: dict[str, JsonValue] = {
        "ssid": config.mlo_host.ssid,
        "enabled": config.mlo_host.enable,
        "bands": list(config.mlo_host.band),
        "hidden": config.mlo_host.enable_hide_ssid,
    }
    if include_passwords:
        iot["password"] = config.iot_host.password
        mlo["password"] = config.mlo_host.password
    bands: dict[str, JsonValue] = {
        "2.4ghz": _wlan_band_view(config.band2_4, include_passwords=include_passwords),
        "5ghz": _wlan_band_view(config.band5_1, include_passwords=include_passwords),
        "6ghz": _wlan_band_view(config.band6, include_passwords=include_passwords),
    }
    if config.band5_2 is not None:
        bands["5ghz-2"] = _wlan_band_view(
            config.band5_2,
            include_passwords=include_passwords,
        )
    if config.band6_2 is not None:
        bands["6ghz-2"] = _wlan_band_view(
            config.band6_2,
            include_passwords=include_passwords,
        )
    return {
        "passwords_included": include_passwords,
        "is_eg": config.is_eg,
        "bands": bands,
        "iot": iot,
        "mlo": mlo,
    }
